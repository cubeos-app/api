// Package auth provides JWT-based authentication for CubeOS.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidToken is returned when token validation fails.
	ErrInvalidToken = errors.New("invalid or expired token")
	// ErrInvalidClaims is returned when token claims are invalid.
	ErrInvalidClaims = errors.New("invalid token claims")
)

// TokenType distinguishes between access and refresh tokens.
type TokenType string

const (
	// AccessToken is a short-lived token for API access.
	AccessToken TokenType = "access"
	// RefreshToken is a long-lived token for obtaining new access tokens.
	RefreshToken TokenType = "refresh"
)

// Claims represents the JWT claims for CubeOS tokens.
type Claims struct {
	jwt.RegisteredClaims
	UserID    int64     `json:"user_id"`
	Username  string    `json:"username"`
	TokenType TokenType `json:"token_type"`
}

// JWTService handles JWT token operations.
type JWTService struct {
	secretKey          []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
	issuer             string
}

// NewJWTService creates a new JWT service with the given configuration.
func NewJWTService(secretKey string, accessExpiry, refreshExpiry time.Duration) *JWTService {
	return &JWTService{
		secretKey:          []byte(secretKey),
		accessTokenExpiry:  accessExpiry,
		refreshTokenExpiry: refreshExpiry,
		issuer:             "cubeos",
	}
}

// GenerateAccessToken creates a new access token for the given user.
func (s *JWTService) GenerateAccessToken(userID int64, username string) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.accessTokenExpiry)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        generateTokenID(),
		},
		UserID:    userID,
		Username:  username,
		TokenType: AccessToken,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expiresAt, nil
}

// GenerateRefreshToken creates a new refresh token for the given user.
func (s *JWTService) GenerateRefreshToken(userID int64, username string) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.refreshTokenExpiry)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        generateTokenID(),
		},
		UserID:    userID,
		Username:  username,
		TokenType: RefreshToken,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expiresAt, nil
}

// ValidateToken parses and validates a JWT token string.
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.secretKey, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	return claims, nil
}

// ValidateAccessToken validates a token and ensures it's an access token.
func (s *JWTService) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != AccessToken {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ValidateRefreshToken validates a token and ensures it's a refresh token.
func (s *JWTService) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != RefreshToken {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// generateTokenID creates a random token ID for JWT jti claim.
func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateSecretKey creates a cryptographically secure random secret key.
// This is useful for initial setup if no key is configured.
func GenerateSecretKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
