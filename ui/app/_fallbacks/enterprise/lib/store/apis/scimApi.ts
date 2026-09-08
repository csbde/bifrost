import { baseApi } from "@/lib/store/apis/baseApi";

// Response shape of GET /api/auth/type — the dashboard authentication mode the
// OSS backend reports (and the enterprise backend already exposes). The OSS
// backend adds oidc_enabled so the login page / security view can show the SSO
// entry point even while password auth remains enabled.
export interface AuthTypeResponse {
	type: "password" | "sso" | "none";
	provider?: string;
	oidc_enabled?: boolean;
}

// OSS build has no SCIM backend, but /api/auth/type is served by the core
// (OSS) server, so this query is real: the login page and security view rely
// on it to decide whether to surface the OIDC SSO entry point.
const authTypeApi = baseApi.injectEndpoints({
	overrideExisting: false,
	endpoints: (builder) => ({
		getAuthType: builder.query<AuthTypeResponse, void>({
			query: () => ({
				url: "/auth/type",
				method: "GET",
			}),
			// Auth type can change when the admin edits OIDC/password config, so
			// re-fetch whenever config is invalidated (e.g. after a save).
			providesTags: ["Config"],
		}),
	}),
});

export const { useGetAuthTypeQuery } = authTypeApi;

// OSS stub for SCIM providers — returns an empty list so the onboarding
// widget's enterprise-only "configure SCIM" step is always considered
// incomplete (the step itself is hidden in OSS via IS_ENTERPRISE).
export const useGetSCIMProvidersQuery = (
	_args?: undefined,
	_opts?: { skip?: boolean },
): {
	data: { enabled: boolean }[] | undefined;
	isLoading: boolean;
	isError: boolean;
	error: null;
} => ({
	data: [],
	isLoading: false,
	isError: false,
	error: null,
});
