package security

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// AccessTokenCookieName is the name of the cookie that holds the local JWT.
// Keep it in sync with the cookie set in HuserLogin (handler).
const AccessTokenCookieName = "access_token"

// ----------------------------------------------------------------------
// 1) Read the raw token string from the request cookie.
// ----------------------------------------------------------------------

// ReadTokenFromCookie returns the raw JWT string stored in the access_token
// cookie. It does NOT validate the token. Use ReadClaimsFromCookie or
// ValidateLocalJWT if you need verified claims.
//
// Returns an error if the cookie is missing or empty.
func ReadTokenFromCookie(r *http.Request) (string, error) {
	if r == nil {
		return "", errors.New("nil request")
	}

	cookie, err := r.Cookie(AccessTokenCookieName)
	if err != nil {
		return "", errors.New("access token cookie not found")
	}

	token := strings.TrimSpace(cookie.Value)
	if token == "" {
		return "", errors.New("access token cookie is empty")
	}

	return token, nil
}

// ----------------------------------------------------------------------
// 2) Read the cookie + validate + return typed claims.
// ----------------------------------------------------------------------

// ReadClaimsFromCookie reads the access_token cookie, validates the JWT, and
// returns the typed claims. Returns an error if the cookie is missing or the
// token is invalid/expired.
func ReadClaimsFromCookie(r *http.Request) (*LocalJWTClaims, error) {
	token, err := ReadTokenFromCookie(r)
	if err != nil {
		return nil, err
	}

	claims, err := ValidateLocalJWT(token)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// ----------------------------------------------------------------------
// 3) Same as above, but returns a generic JSON-friendly map.
//    Useful when a handler wants to echo the user info as JSON.
// ----------------------------------------------------------------------

// ReadClaimsAsJSONFromCookie reads the access_token cookie, validates the
// JWT, and returns the claims serialized as a map[string]any (JSON-friendly).
//
// This is handy for endpoints like /me that simply mirror the user's
// information back to the frontend.
func ReadClaimsAsJSONFromCookie(r *http.Request) (map[string]any, error) {
	claims, err := ReadClaimsFromCookie(r)
	if err != nil {
		return nil, err
	}

	// Round-trip through encoding/json so the result respects the json:""
	// tags on LocalJWTClaims (uid, email, name, picture, etc.).
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}

	return out, nil
}
