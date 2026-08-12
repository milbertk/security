package security

import (
	"context"
	"net/http"
)

// RequireCompanyAccess ensures the authenticated user is linked to the company
// the request targets AND holds a management role (OWNER / MANAGER).
//
// It must run AFTER authentication, because it reads the UID from the JWT
// claims placed in context by AuthMiddleware. The database check is performed
// directly by DValidateCompanyAccess (same style as DValidateStatus), so this
// package has no external database dependency.
//
// On success it stores the active company ID and the resolved company role in
// the request context, retrievable with GetActiveCompanyID(r) and
// GetActiveCompanyRole(r).
func RequireCompanyAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := GetClaims(r)
		if !ok || claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		companyID, ok := extractCompanyID(r)
		if !ok {
			http.Error(w, "Missing company identifier", http.StatusBadRequest)
			return
		}

		allowed, role, err := DValidateCompanyAccess(companyID, claims.UID)
		if err != nil {
			http.Error(w, "Failed to validate company access", http.StatusInternalServerError)
			return
		}

		if !allowed {
			// role may carry a non-management role (e.g. USER) for context,
			// but access is denied.
			http.Error(w, "User is not authorized for this company", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), companyIDCtxKey, companyID)
		ctx = context.WithValue(ctx, companyRoleCtxKey, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireActiveCompanyUser runs the full chain in one call:
//
//	AuthMiddleware -> RequireActiveUser (active check) -> RequireCompanyAccess
//
// Use this to protect any route that must be performed by an active user who
// is linked to the target company with a management role.
func RequireActiveCompanyUser(next http.Handler) http.Handler {
	return RequireActiveUser(RequireCompanyAccess(next))
}
