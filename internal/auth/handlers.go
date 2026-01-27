package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// Handler handles authentication HTTP requests.
type Handler struct {
	jwtService  *JWTService
	userService *UserService
}

// NewHandler creates a new auth handler.
func NewHandler(jwtService *JWTService, userService *UserService) *Handler {
	return &Handler{
		jwtService:  jwtService,
		userService: userService,
	}
}

// LoginRequest is the request body for the login endpoint.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenResponse is the response body containing JWT tokens.
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// UserResponse is the response body for user info.
type UserResponse struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email,omitempty"`
	IsAdmin     bool       `json:"is_admin"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// RefreshRequest is the request body for token refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// ChangePasswordRequest is the request body for changing password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// Login handles POST /api/v1/auth/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		badRequest(w, "username and password are required")
		return
	}

	// Authenticate user
	user, err := h.userService.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			log.Debug().Str("username", req.Username).Msg("Login failed: invalid credentials")
			unauthorized(w, "invalid username or password")
			return
		}
		log.Error().Err(err).Msg("Authentication error")
		internalError(w, "authentication failed")
		return
	}

	// Generate tokens
	accessToken, expiresAt, err := h.jwtService.GenerateAccessToken(user.ID, user.Username)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate access token")
		internalError(w, "failed to generate token")
		return
	}

	refreshToken, _, err := h.jwtService.GenerateRefreshToken(user.ID, user.Username)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate refresh token")
		internalError(w, "failed to generate token")
		return
	}

	log.Info().Str("username", user.Username).Msg("User logged in")

	// Calculate expires_in in seconds
	expiresIn := int(time.Until(expiresAt).Seconds())

	jsonResponse(w, http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
	})
}

// Refresh handles POST /api/v1/auth/refresh
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		badRequest(w, "refresh_token is required")
		return
	}

	// Validate refresh token
	claims, err := h.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		log.Debug().Err(err).Msg("Refresh token validation failed")
		unauthorized(w, "invalid or expired refresh token")
		return
	}

	// Verify user still exists
	user, err := h.userService.GetByID(r.Context(), claims.UserID)
	if err != nil {
		log.Debug().Err(err).Int64("user_id", claims.UserID).Msg("User not found for refresh")
		unauthorized(w, "user not found")
		return
	}

	// Generate new access token
	accessToken, expiresAt, err := h.jwtService.GenerateAccessToken(user.ID, user.Username)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate access token")
		internalError(w, "failed to generate token")
		return
	}

	// Optionally rotate refresh token (more secure but can cause issues with concurrent requests)
	// For now, keep the same refresh token until it expires

	expiresIn := int(time.Until(expiresAt).Seconds())

	jsonResponse(w, http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: req.RefreshToken, // Return same refresh token
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
	})
}

// Me handles GET /api/v1/auth/me
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		unauthorized(w, "authentication required")
		return
	}

	jsonResponse(w, http.StatusOK, UserResponse{
		ID:          user.ID,
		Username:    user.Username,
		Email:       user.Email,
		IsAdmin:     user.IsAdmin,
		CreatedAt:   user.CreatedAt,
		LastLoginAt: user.LastLoginAt,
	})
}

// ChangePassword handles POST /api/v1/auth/password
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		unauthorized(w, "authentication required")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		badRequest(w, "current_password and new_password are required")
		return
	}

	if len(req.NewPassword) < 8 {
		badRequest(w, "new password must be at least 8 characters")
		return
	}

	// Verify current password
	if err := CheckPassword(req.CurrentPassword, user.PasswordHash); err != nil {
		unauthorized(w, "current password is incorrect")
		return
	}

	// Update password
	if err := h.userService.UpdatePassword(r.Context(), user.ID, req.NewPassword); err != nil {
		log.Error().Err(err).Msg("Failed to update password")
		internalError(w, "failed to update password")
		return
	}

	log.Info().Str("username", user.Username).Msg("Password changed")

	jsonResponse(w, http.StatusOK, map[string]string{
		"message": "password updated successfully",
	})
}

// Logout handles POST /api/v1/auth/logout
// Note: With stateless JWTs, we can't really invalidate tokens server-side without a blacklist.
// This endpoint exists for clients to "logout" by discarding their tokens.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// For stateless JWT, logout is handled client-side by discarding tokens
	// Future: could add token to a blacklist in Redis/DB
	jsonResponse(w, http.StatusOK, map[string]string{
		"message": "logged out successfully",
	})
}

// Helper functions

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

func badRequest(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(`{"error": "bad_request", "message": "` + message + `"}`))
}

func internalError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(`{"error": "internal_error", "message": "` + message + `"}`))
}
