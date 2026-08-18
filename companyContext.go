package security

import (
	"net/http"
	"strings"
)

// Context keys for company-scoped values, following the same pattern as
// claimsCtxKey in authMiddleware.go.
const (
	companyIDCtxKey    ctxKey = "activeCompanyID"
	companyRoleCtxKey  ctxKey = "activeCompanyRole"
	companyEmailCtxKey ctxKey = "activeCompanyEmail"
)

// CompanyHeaderName is the HTTP header the frontend MAY use to tell the backend
// which company the current action targets. It is optional: the middleware also
// reads the company ID from the URL path (/companies/{companyId}/...), which is
// how the REST routes already carry it.
const CompanyHeaderName = "X-Company-ID"

// extractCompanyID pulls the target company ID from the request, checking, in
// order:
//  1. the X-Company-ID header,
//  2. the "companyId" query parameter,
//  3. the URL path segment right after "/companies/".
//
// Change this one function if you ever move the value somewhere else.
func extractCompanyID(r *http.Request) (string, bool) {
	if v := strings.TrimSpace(r.Header.Get(CompanyHeaderName)); v != "" {
		return v, true
	}

	if v := strings.TrimSpace(r.URL.Query().Get("companyId")); v != "" {
		return v, true
	}

	// Path fallback: .../companies/{companyId}/...
	if v := companyIDFromPath(r.URL.Path); v != "" {
		return v, true
	}

	return "", false
}

// companyIDFromPath returns the path segment immediately after "companies",
// or "" if there isn't one. Example:
//
//	/companies/fb47a31b-.../company-users/774d38fa-...  ->  "fb47a31b-..."
func companyIDFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if p == "companies" && i+1 < len(parts) {
			return strings.TrimSpace(parts[i+1])
		}
	}
	return ""
}

// GetActiveCompanyID returns the company ID attached by RequireCompanyAccess.
func GetActiveCompanyID(r *http.Request) (string, bool) {
	v, ok := r.Context().Value(companyIDCtxKey).(string)
	return v, ok
}

// GetActiveCompanyRole returns the company role (OWNER/MANAGER/...) attached
// by RequireCompanyAccess.
func GetActiveCompanyRole(r *http.Request) (string, bool) {
	v, ok := r.Context().Value(companyRoleCtxKey).(string)
	return v, ok
}

// GetActiveCompanyEmail returns the user's official e-mail (from
// public.usfirebasedata) attached by RequireCompanyAccess. This value is
// resolved server-side and must be trusted over anything sent by the frontend.
func GetActiveCompanyEmail(r *http.Request) (string, bool) {
	v, ok := r.Context().Value(companyEmailCtxKey).(string)
	return v, ok
}
