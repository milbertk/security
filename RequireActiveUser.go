package security

import "net/http"

func RequireActiveUser(next http.Handler) http.Handler {
	return AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := GetClaims(r)
		if !ok || claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		valid, status, err := DValidateStatus(claims.UID)
		if err != nil || !valid {
			http.Error(w, status, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}))
}
