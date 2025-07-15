package security

import (
	"context"
	"fmt"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/milbertk/class"
	"google.golang.org/api/option"
)

var signingKey = []byte(LoadJWTSecret())

// LocalJWTClaims defines the structure of your own JWT
type LocalJWTClaims struct {
	UID            string `json:"uid"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	Picture        string `json:"picture"`
	EmailVerified  bool   `json:"email_verified"`
	SignInProvider string `json:"sign_in_provider"`
	Role           string `json:"role"`
	jwt.RegisteredClaims
}

// ValidateFirebaseToken validates a Firebase token and returns the decoded user
func ValidateFirebaseToken(firebaseToken string) (*auth.Token, error) {
	// Load Firebase credentials
	println("start validate firebase Token")
	text, err := class.NewJSONReader("fileRoute.json")
	if err != nil {
		return nil, fmt.Errorf("error reading fileRoute.json: %w", err)
	}

	data := text.GetJSON()

	fileRoute, ok := data["fileRoute"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid or missing 'fileRoute' field in JSON")
	}

	opt := option.WithCredentialsFile(fileRoute)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, fmt.Errorf("firebase init error: %w", err)
	}

	client, err := app.Auth(context.Background())
	if err != nil {
		return nil, fmt.Errorf("auth client error: %w", err)
	}

	token, err := client.VerifyIDToken(context.Background(), firebaseToken)
	if err != nil {
		return nil, fmt.Errorf("invalid Firebase token: %w", err)
	}

	return token, nil
}

// GenerateLocalJWT issues your own JWT with extended user info
func GenerateLocalJWT(uid, email, name, picture, signInProvider, role string, emailVerified bool) (string, error) {
	claims := LocalJWTClaims{
		UID:            uid,
		Email:          email,
		Name:           name,
		Picture:        picture,
		EmailVerified:  emailVerified,
		SignInProvider: signInProvider,
		Role:           role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "your-backend", // <- Replace with your app name or URL
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("could not sign token: %w", err)
	}

	return signed, nil
}
