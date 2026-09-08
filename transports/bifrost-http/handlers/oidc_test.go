package handlers

import (
	"testing"
)

func TestNormalizeOIDCGotoPath(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"/workspace", "/workspace"},
		{"/login", "/login"},
		{"/oauth/consent", "/oauth/consent"},
		{"/workspace/keys", "/workspace/keys"},
		{"/etc/passwd", ""},         // not an allowed prefix
		{"https://evil.com/x", ""},  // no leading slash
		{"//evil.com/x", ""},        // protocol-relative, open-redirect guard
		{"/other", ""},              // unknown dashboard path
		{"/oauth/consent/x", "/oauth/consent/x"},
	}
	for _, c := range cases {
		if got := normalizeOIDCGotoPath(c.raw); got != c.want {
			t.Errorf("normalizeOIDCGotoPath(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestOIDCClaimsAllowed(t *testing.T) {
	claims := map[string]any{
		"email":  "alice@example.com",
		"roles":  []any{"admin", "viewer"},
		"groups": []string{"eng", "sales"},
		"single": "analyst",
	}

	// Empty allow-list => fail-open, admit everyone (by design).
	if !oidcClaimsAllowed(claims, "", nil) {
		t.Error("empty allow-list should admit")
	}
	if !oidcClaimsAllowed(claims, "roles", nil) {
		t.Error("empty values with a claim name should admit")
	}

	// String claim match.
	if !oidcClaimsAllowed(claims, "single", []string{"analyst"}) {
		t.Error("string claim should match")
	}
	if oidcClaimsAllowed(claims, "single", []string{"other"}) {
		t.Error("string claim mismatch should reject")
	}

	// []any claim match.
	if !oidcClaimsAllowed(claims, "roles", []string{"viewer"}) {
		t.Error("[]any claim should match one value")
	}
	if oidcClaimsAllowed(claims, "roles", []string{"nope"}) {
		t.Error("[]any claim no match should reject")
	}

	// []string claim match.
	if !oidcClaimsAllowed(claims, "groups", []string{"sales"}) {
		t.Error("[]string claim should match")
	}

	// Missing claim rejects.
	if oidcClaimsAllowed(claims, "missing", []string{"x"}) {
		t.Error("missing claim should reject")
	}
}

func TestSecureEqual(t *testing.T) {
	if !secureEqual("abc", "abc") {
		t.Error("equal strings should be equal")
	}
	if secureEqual("abc", "abd") {
		t.Error("differing strings should not be equal")
	}
	if secureEqual("ab", "abc") {
		t.Error("different lengths should not be equal")
	}
}

func TestRandomOIDCString(t *testing.T) {
	a := randomOIDCString(24)
	b := randomOIDCString(24)
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("random string should be non-empty")
	}
	if a == b {
		t.Error("two random strings should differ")
	}
	// 43 bytes -> base64 raw url (no padding) is 58 chars.
	if l := len(randomOIDCString(43)); l != 58 {
		t.Errorf("expected 58 chars for 43 bytes, got %d", l)
	}
}

func TestSha256Sum(t *testing.T) {
	sum := sha256Sum("hello")
	if len(sum) != 32 {
		t.Errorf("sha256 should be 32 bytes, got %d", len(sum))
	}
}
