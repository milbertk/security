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

// extractToken pulls the raw JWT from the request, preferring the
// access_token cookie (set by the login handler) and falling back to the
// "Authorization: Bearer <token>" header for non-browser clients
// (mobile apps, server-to-server, Postman, etc.).
//
// Returns the trimmed token string and a boolean indicating whether one
// was found.
func extractToken(r *http.Request) (string, bool) {
	// 1) Cookie (preferred for browser clients — HttpOnly + Secure).
	if token, err := ReadTokenFromCookie(r); err == nil && token != "" {
		return token, true
	}

	// 2) Authorization header fallback.
	ah := r.Header.Get("Authorization")
	if strings.HasPrefix(ah, "Bearer ") {
		raw := strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
		if raw != "" {
			return raw, true
		}
	}

	return "", false
}

// AuthMiddleware validates the local JWT on every request.
//
// Token source priority:
//  1. The "access_token" HttpOnly cookie (set by the login handler).
//  2. The "Authorization: Bearer <token>" header (fallback for clients
//     that don't use cookies).
//
// On success, the validated claims are attached to the request context so
// downstream handlers can retrieve them with GetClaims(r).
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow CORS preflight to pass through (optional)
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		raw, ok := extractToken(r)
		if !ok {
			http.Error(w, "Missing authentication token", http.StatusUnauthorized)
			return
		}

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
