package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// UserContextKey is the context key for the authenticated user.
	UserContextKey contextKey = "user"
	// ClaimsContextKey is the context key for JWT claims.
	ClaimsContextKey contextKey = "claims"
)

// Middleware provides authentication middleware for HTTP handlers.
type Middleware struct {
	jwtService  *JWTService
	userService *UserService
}

// NewMiddleware creates a new auth middleware.
func NewMiddleware(jwtService *JWTService, userService *UserService) *Middleware {
	return &Middleware{
		jwtService:  jwtService,
		userService: userService,
	}
}

// RequireAuth is middleware that requires a valid access token.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		token := extractBearerToken(r)
		if token == "" {
			unauthorized(w, "missing or invalid authorization header")
			return
		}

		// Validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			log.Debug().Err(err).Msg("Token validation failed")
			unauthorized(w, "invalid or expired token")
			return
		}

		// Load user from database
		user, err := m.userService.GetByID(r.Context(), claims.UserID)
		if err != nil {
			log.Debug().Err(err).Int64("user_id", claims.UserID).Msg("User not found")
			unauthorized(w, "user not found")
			return
		}

		// Add user and claims to context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin is middleware that requires admin privileges.
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r.Context())
		if user == nil {
			unauthorized(w, "authentication required")
			return
		}

		if !user.IsAdmin {
			forbidden(w, "admin privileges required")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// OptionalAuth is middleware that loads user info if a token is present, but doesn't require it.
func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			// Invalid token, but auth is optional - continue without user
			next.ServeHTTP(w, r)
			return
		}

		user, err := m.userService.GetByID(r.Context(), claims.UserID)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserFromContext retrieves the authenticated user from the request context.
func GetUserFromContext(ctx context.Context) *User {
	user, ok := ctx.Value(UserContextKey).(*User)
	if !ok {
		return nil
	}
	return user
}

// GetClaimsFromContext retrieves the JWT claims from the request context.
func GetClaimsFromContext(ctx context.Context) *Claims {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	if !ok {
		return nil
	}
	return claims
}

// extractBearerToken extracts the JWT token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Check for "Bearer " prefix (case-insensitive)
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
		return authHeader[7:]
	}

	return ""
}

// unauthorized sends a 401 Unauthorized response.
func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="cubeos"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error": "unauthorized", "message": "` + message + `"}`))
}

// forbidden sends a 403 Forbidden response.
func forbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error": "forbidden", "message": "` + message + `"}`))
}
