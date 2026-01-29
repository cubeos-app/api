package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"cubeos-api/internal/config"
)

type contextKey string

const UserContextKey contextKey = "user"

// Claims represents JWT claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// JWTAuth middleware validates JWT tokens
func JWTAuth(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"Missing authorization header"}`, http.StatusUnauthorized)
				return
			}
			
			// Check Bearer prefix
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, `{"error":"Invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}
			
			tokenString := parts[1]
			
			// Parse and validate token
			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(cfg.JWTSecret), nil
			})
			
			if err != nil || !token.Valid {
				http.Error(w, `{"error":"Invalid or expired token"}`, http.StatusUnauthorized)
				return
			}
			
			// Add claims to context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GenerateToken creates a new JWT token
func GenerateToken(username, role string, cfg *config.Config) (string, error) {
	expirationTime := time.Now().Add(time.Duration(cfg.JWTExpirationHours) * time.Hour)
	
	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   username,
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecret))
}

// GetUserFromContext extracts user claims from request context
func GetUserFromContext(ctx context.Context) *Claims {
	if claims, ok := ctx.Value(UserContextKey).(*Claims); ok {
		return claims
	}
	return nil
}

// RequireRole middleware checks if user has required role
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			
			if claims.Role != role && claims.Role != "admin" {
				http.Error(w, `{"error":"Insufficient permissions"}`, http.StatusForbidden)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}
