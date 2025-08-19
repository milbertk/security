package security

import (
	"context"
	"net/http"
	"strings"
)

// context key for claims
type ctxKey string

const claimsCtxKey ctxKey = "localJWTClaims"

// GetClaims extracts your typed claims from the request context in handlers.
func GetClaims(r *http.Request) (*LocalJWTClaims, bool) {
	claims, ok := r.Context().Value(claimsCtxKey).(*LocalJWTClaims)
	return claims, ok
}

// AuthMiddleware validates "Authorization: Bearer <token>" on every request.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow CORS preflight to pass through (optional)
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		ah := r.Header.Get("Authorization")
		if !strings.HasPrefix(ah, "Bearer ") {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		raw := strings.TrimPrefix(ah, "Bearer ")
		raw = strings.TrimSpace(raw)

		claims, err := ValidateLocalJWT(raw)
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Put claims in context for downstream handlers
		ctx := context.WithValue(r.Context(), claimsCtxKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
