package auth

import (
	"golang.org/x/crypto/bcrypt"
)

const (
	// BcryptCost is the bcrypt hashing cost factor.
	// 12 is a good balance between security and performance.
	BcryptCost = 12
)

// HashPassword creates a bcrypt hash of the given password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword compares a password with a bcrypt hash.
// Returns nil on success, or an error if the password doesn't match.
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
