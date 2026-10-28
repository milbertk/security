package security

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// LoadJWTSecret reads JWT_SECRET from the environment (2026-10-27).
// A .env file is optional: it is loaded when present (local development).
// On a server, JWT_SECRET can come from the environment without any .env file.
// The program still stops if JWT_SECRET is empty.
func LoadJWTSecret() []byte {
	if err := godotenv.Load(); err != nil {
		if !os.IsNotExist(err) {
			log.Println("⚠ .env file could not be read:", err)
		}
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("❌ JWT_SECRET is not set (environment variable or .env file)")
	}

	return []byte(secret)
}
