package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/valyala/fasthttp"
	"golang.org/x/oauth2"
)

// OIDC cookies used to carry the CSRF state, the PKCE code verifier, and the
// post-login redirect target across the IdP round-trip. All are HttpOnly.
const (
	oidcStateCookie    = "oidc_state"
	oidcVerifierCookie = "oidc_verifier"
	oidcGotoCookie     = "oidc_goto"
	oidcDefaultScopes  = "openid email profile"
)

// oidcProviderCache caches a discovered OIDC provider per issuer so we don't
// re-fetch the discovery document and JWKS on every login.
var (
	oidcProviderCacheMu sync.Mutex
	oidcProviderCache   = map[string]*oidc.Provider{}
)

// oidcHTTPClient is the HTTP client used for IdP discovery and token exchange.
// TODO: route through the configured global proxy (proxy_config.enable_for_api)
// when the IdP is only reachable on a private network.
var oidcHTTPClient = &http.Client{Timeout: 30 * time.Second}

// getOIDCProvider returns a cached OIDC provider for the issuer, performing OIDC
// discovery (and JWKS fetch) on first use.
func getOIDCProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	oidcProviderCacheMu.Lock()
	defer oidcProviderCacheMu.Unlock()
	if p, ok := oidcProviderCache[issuer]; ok {
		return p, nil
	}
	// Route discovery/JWKS through oidcHTTPClient via a context-scoped client.
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, oidcHTTPClient), issuer)
	if err != nil {
		return nil, err
	}
	oidcProviderCache[issuer] = p
	return p, nil
}

// getOIDCConfig returns the configured, enabled OIDC login config or (nil, false).
func (h *SessionHandler) getOIDCConfig(ctx *fasthttp.RequestCtx) (*configstore.OIDCConfig, bool) {
	if h.configStore == nil {
		return nil, false
	}
	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil || authConfig == nil || authConfig.OIDC == nil || !authConfig.OIDC.Enabled {
		return nil, false
	}
	return authConfig.OIDC, true
}

// oidcScopes builds the OAuth2 scope list, always starting from the required
// openid/email/profile set and appending any operator-configured extra scopes.
func oidcScopes(cfg *configstore.OIDCConfig) []string {
	scopes := strings.Fields(oidcDefaultScopes)
	return append(scopes, cfg.Scopes...)
}

// oidcRedirectURI derives the callback URL the IdP must redirect back to. It uses
// the operator-configured RedirectURI when set, otherwise it is derived from the
// incoming request (respecting X-Forwarded-Proto / X-Forwarded-Host behind a proxy).
func (h *SessionHandler) oidcRedirectURI(ctx *fasthttp.RequestCtx, cfg *configstore.OIDCConfig) string {
	if cfg.RedirectURI != "" {
		return cfg.RedirectURI
	}
	scheme := "http"
	if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" {
		scheme = "https"
	}
	host := string(ctx.Request.Header.Peek("X-Forwarded-Host"))
	if host == "" {
		host = string(ctx.Host())
	}
	return scheme + "://" + host + "/api/session/oidc/callback"
}

// oidcLogin initiates the Authorization Code + PKCE flow: it validates the OIDC
// config, stores a CSRF state + PKCE verifier in HttpOnly cookies, and 302s the
// browser to the IdP's authorization endpoint.
func (h *SessionHandler) oidcLogin(ctx *fasthttp.RequestCtx) {
	cfg, ok := h.getOIDCConfig(ctx)
	if !ok {
		SendError(ctx, fasthttp.StatusForbidden, "OIDC login is not enabled")
		return
	}
	provider, err := getOIDCProvider(ctx, cfg.Issuer)
	if err != nil {
		logger.Error("oidc: discovery for issuer %s failed: %v", cfg.Issuer, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reach identity provider")
		return
	}

	state := randomOIDCString(24)
	verifier := randomOIDCString(43)
	challenge := base64.RawURLEncoding.EncodeToString(sha256Sum(verifier))

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret.GetValue(),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  h.oidcRedirectURI(ctx, cfg),
		Scopes:       oidcScopes(cfg),
	}
	authURL := oauth2Cfg.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	setOIDCCookie(ctx, oidcStateCookie, state)
	setOIDCCookie(ctx, oidcVerifierCookie, verifier)
	if gotoPath := normalizeOIDCGotoPath(string(ctx.QueryArgs().Peek("goto"))); gotoPath != "" {
		setOIDCCookie(ctx, oidcGotoCookie, gotoPath)
	}

	ctx.Response.Header.Set("Location", authURL)
	ctx.SetStatusCode(fasthttp.StatusFound)
}

// oidcCallback completes the flow: it verifies the CSRF state, exchanges the
// authorization code for tokens (PKCE), verifies the ID token against the IdP
// (audience/issuer/exp/nbf), enforces the claim allow-list, and on success
// issues a normal bifrost dashboard session.
func (h *SessionHandler) oidcCallback(ctx *fasthttp.RequestCtx) {
	cfg, ok := h.getOIDCConfig(ctx)
	if !ok {
		oidcRedirectToLogin(ctx, "oidc_not_configured")
		return
	}
	state := string(ctx.QueryArgs().Peek("state"))
	if state == "" || !secureEqual(state, string(ctx.Request.Header.Cookie(oidcStateCookie))) {
		oidcRedirectToLogin(ctx, "oidc_state_mismatch")
		return
	}
	code := string(ctx.QueryArgs().Peek("code"))
	if code == "" {
		oidcRedirectToLogin(ctx, "oidc_missing_code")
		return
	}
	verifier := string(ctx.Request.Header.Cookie(oidcVerifierCookie))
	if verifier == "" {
		oidcRedirectToLogin(ctx, "oidc_state_mismatch")
		return
	}

	provider, err := getOIDCProvider(ctx, cfg.Issuer)
	if err != nil {
		logger.Error("oidc: discovery for issuer %s failed: %v", cfg.Issuer, err)
		oidcRedirectToLogin(ctx, "oidc_discovery_failed")
		return
	}

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret.GetValue(),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  h.oidcRedirectURI(ctx, cfg),
		Scopes:       oidcScopes(cfg),
	}
	token, err := oauth2Cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		logger.Error("oidc: token exchange failed: %v", err)
		oidcRedirectToLogin(ctx, "oidc_token_exchange_failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		oidcRedirectToLogin(ctx, "oidc_missing_id_token")
		return
	}
	// Verify the ID token: audience (=client_id), issuer, exp/nbf are validated
	// by go-oidc using the provider's discovered metadata.
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		logger.Error("oidc: id token verification failed: %v", err)
		oidcRedirectToLogin(ctx, "oidc_invalid_id_token")
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		oidcRedirectToLogin(ctx, "oidc_claims_unavailable")
		return
	}
	if !oidcClaimsAllowed(claims, cfg.AllowedClaim, cfg.AllowedValues) {
		logger.Warn("oidc: user rejected by claim allow-list (claim=%q)", cfg.AllowedClaim)
		oidcRedirectToLogin(ctx, "oidc_not_authorized")
		return
	}

	if _, err := h.issueSession(ctx); err != nil {
		logger.Error("oidc: failed to create session: %v", err)
		oidcRedirectToLogin(ctx, "oidc_session_failed")
		return
	}

	gotoPath := normalizeOIDCGotoPath(string(ctx.Request.Header.Cookie(oidcGotoCookie)))
	clearOIDCCookies(ctx)
	if gotoPath == "" {
		gotoPath = "/login"
	}
	ctx.Response.Header.Set("Location", gotoPath)
	ctx.SetStatusCode(fasthttp.StatusFound)
}

// oidcClaimsAllowed enforces the optional claim allow-list. When no allow-list
// is configured every authenticated user is permitted (fail-open on an empty
// allow-list, by design — see security note in the plan).
func oidcClaimsAllowed(claims map[string]any, allowedClaim string, allowedValues []string) bool {
	if allowedClaim == "" || len(allowedValues) == 0 {
		return true
	}
	v, ok := claims[allowedClaim]
	if !ok {
		return false
	}
	switch val := v.(type) {
	case string:
		return slices.Contains(allowedValues, val)
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok && slices.Contains(allowedValues, s) {
				return true
			}
		}
	case []string:
		for _, s := range val {
			if slices.Contains(allowedValues, s) {
				return true
			}
		}
	}
	return false
}

// oidcRedirectToLogin 302s back to the dashboard login page with an error code.
func oidcRedirectToLogin(ctx *fasthttp.RequestCtx, errCode string) {
	clearOIDCCookies(ctx)
	ctx.Response.Header.Set("Location", "/login?error="+url.QueryEscape(errCode))
	ctx.SetStatusCode(fasthttp.StatusFound)
}

func setOIDCCookie(ctx *fasthttp.RequestCtx, name, value string) {
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey(name)
	cookie.SetValue(value)
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" {
		cookie.SetSecure(true)
	}
	ctx.Response.Header.SetCookie(cookie)
}

func clearOIDCCookies(ctx *fasthttp.RequestCtx) {
	for _, name := range []string{oidcStateCookie, oidcVerifierCookie, oidcGotoCookie} {
		cookie := fasthttp.AcquireCookie()
		cookie.SetKey(name)
		cookie.SetValue("")
		cookie.SetPath("/")
		cookie.SetHTTPOnly(true)
		cookie.SetExpire(time.Now().Add(-time.Hour * 24))
		ctx.Response.Header.SetCookie(cookie)
	}
}

// normalizeOIDCGotoPath restricts the post-login redirect to known-safe internal
// dashboard paths, preventing open-redirect via the goto cookie/query param.
func normalizeOIDCGotoPath(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	for _, prefix := range []string{"/workspace", "/login", "/oauth/consent"} {
		if strings.HasPrefix(raw, prefix) {
			return raw
		}
	}
	return ""
}

func randomOIDCString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Cryptographically-secure RNG failure is exceptional; fall back to a
		// time-derived value so the flow still produces a non-empty token.
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
