package security

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// LoadJWTSecret reads the JWT_SECRET from .env file
func LoadJWTSecret() []byte {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("❌ Error loading .env file")
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("❌ JWT_SECRET is not set in environment")
	}

	return []byte(secret)
}
