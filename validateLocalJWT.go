package security

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ValidateLocalJWT parses and verifies a locally issued JWT (HS256) and returns typed claims.
func ValidateLocalJWT(tokenString string) (*LocalJWTClaims, error) {
	// tokenString: raw JWT (not "Bearer ...")
	tkn, err := jwt.ParseWithClaims(
		tokenString,
		&LocalJWTClaims{},
		func(t *jwt.Token) (any, error) {
			// Enforce HMAC (matches GenerateLocalJWT's HS256)
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			// Reuse the package-level signingKey that was loaded by LoadJWTSecret()
			return signingKey, nil
		},
		// Hardening (jwt/v5)
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer("Aleph"),        // must match the Issuer in GenerateLocalJWT
		jwt.WithLeeway(30*time.Second), // small clock skew tolerance
	)
	if err != nil {
		return nil, fmt.Errorf("parse/verify jwt: %w", err)
	}

	claims, ok := tkn.Claims.(*LocalJWTClaims)
	if !ok || !tkn.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Optional extra checks (RegisteredClaims.Valid() has already run for exp/iat/iss)
	if claims.UID == "" || claims.Email == "" {
		return nil, errors.New("missing required custom claims (uid/email)")
	}

	return claims, nil
}
