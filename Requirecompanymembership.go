package security

import (
	"context"
	"net/http"
)

// RequireCompanyMembership ensures the authenticated user simply BELONGS to the
// company the request targets — with ANY role. It does NOT require OWNER /
// MANAGER (that is RequireCompanyAccess).
//
// Use this for actions that any member of the company may perform, where you
// only need to confirm the caller previously belongs to the company.
//
// It must run AFTER authentication, because it reads the UID from the JWT
// claims placed in context by AuthMiddleware. On success it stores the same
// context values as RequireCompanyAccess, so the getters are shared:
//   - GetActiveCompanyID(r)
//   - GetActiveCompanyRole(r)
//   - GetActiveCompanyEmail(r)
func RequireCompanyMembership(next http.Handler) http.Handler {
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

		belongs, role, email, err := DValidateCompanyMembership(companyID, claims.UID)
		if err != nil {
			http.Error(w, "Failed to validate company membership", http.StatusInternalServerError)
			return
		}

		if !belongs {
			http.Error(w, "User does not belong to this company", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), companyIDCtxKey, companyID)
		ctx = context.WithValue(ctx, companyRoleCtxKey, role)
		ctx = context.WithValue(ctx, companyEmailCtxKey, email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireActiveCompanyMember runs the full chain in one call:
//
//	AuthMiddleware -> RequireActiveUser (exists + active) -> RequireCompanyMembership
//
// Use this to protect routes that any active user who belongs to the target
// company may perform, regardless of role.
func RequireActiveCompanyMember(next http.Handler) http.Handler {
	return RequireActiveUser(RequireCompanyMembership(next))
}
