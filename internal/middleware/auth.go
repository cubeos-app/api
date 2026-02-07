package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"cubeos-api/internal/config"
)

// writeJSONError writes a JSON-formatted error response with proper content-type.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": message,
		"code":  status,
	})
}

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
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSONError(w, http.StatusUnauthorized, "Missing authorization header")
				return
			}

			// Check Bearer prefix
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				writeJSONError(w, http.StatusUnauthorized, "Invalid authorization header format")
				return
			}

			tokenString := parts[1]

			// Parse and validate token
			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(cfg.JWTSecret), nil
			})

			if err != nil || !token.Valid {
				writeJSONError(w, http.StatusUnauthorized, "Invalid or expired token")
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

// maxRefreshWindow is the maximum age past expiration that a token can still be refreshed.
const maxRefreshWindow = 7 * 24 * time.Hour // 7 days

// ParseTokenAllowExpired parses a JWT token and allows recently-expired tokens
// (within maxRefreshWindow). Returns claims only if the token signature is valid
// and the token hasn't been expired for longer than the refresh window.
func ParseTokenAllowExpired(tokenString string, cfg *config.Config) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cfg.JWTSecret), nil
	}, jwt.WithoutClaimsValidation()) // Skip expiry check during parsing

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if token == nil {
		return nil, fmt.Errorf("invalid token")
	}

	// Verify the token was validly signed (claims are populated)
	if claims.Username == "" {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check if token is within the refresh window
	if claims.ExpiresAt != nil {
		expiry := claims.ExpiresAt.Time
		if time.Since(expiry) > maxRefreshWindow {
			return nil, fmt.Errorf("token expired beyond refresh window")
		}
	}

	return claims, nil
}

// JWTAuthAllowExpired is a middleware variant that allows recently-expired tokens.
// Used exclusively for the /auth/refresh endpoint.
func JWTAuthAllowExpired(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSONError(w, http.StatusUnauthorized, "Missing authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				writeJSONError(w, http.StatusUnauthorized, "Invalid authorization header format")
				return
			}

			claims, err := ParseTokenAllowExpired(parts[1], cfg)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole middleware checks if user has required role
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r.Context())
			if claims == nil {
				writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			if claims.Role != role && claims.Role != "admin" {
				writeJSONError(w, http.StatusForbidden, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// MaxBodySize middleware limits the size of incoming request bodies.
// Default limit is 10MB. Requests exceeding the limit receive 413 Payload Too Large.
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}
