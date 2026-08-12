package security

import (
	"net/http"
	"strings"
)

// Context keys for company-scoped values, following the same pattern as
// claimsCtxKey in authMiddleware.go.
const (
	companyIDCtxKey   ctxKey = "activeCompanyID"
	companyRoleCtxKey ctxKey = "activeCompanyRole"
)

// CompanyHeaderName is the HTTP header the frontend uses to tell the backend
// which company the current action targets. The React app should read the
// selected company from localStorage and send it on every request, e.g.:
//
//	fetch(url, { headers: { "X-Company-ID": selectedCompanyId }, credentials: "include" })
const CompanyHeaderName = "X-Company-ID"

// extractCompanyID pulls the target company ID from the request. It prefers
// the X-Company-ID header and falls back to a "companyId" query parameter.
// Change this one function if you ever move the value somewhere else.
func extractCompanyID(r *http.Request) (string, bool) {
	if v := strings.TrimSpace(r.Header.Get(CompanyHeaderName)); v != "" {
		return v, true
	}

	if v := strings.TrimSpace(r.URL.Query().Get("companyId")); v != "" {
		return v, true
	}

	return "", false
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
