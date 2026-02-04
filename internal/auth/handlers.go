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
// @Description Login credentials
type LoginRequest struct {
	Username string `json:"username" example:"admin"`
	Password string `json:"password" example:"cubeos"`
}

// TokenResponse is the response body containing JWT tokens.
// @Description JWT token response
type TokenResponse struct {
	AccessToken  string    `json:"access_token" example:"eyJhbGciOiJIUzI1NiIs..."`
	RefreshToken string    `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIs..."`
	TokenType    string    `json:"token_type" example:"Bearer"`
	ExpiresIn    int       `json:"expires_in" example:"3600"`
	ExpiresAt    time.Time `json:"expires_at" example:"2025-02-04T12:00:00Z"`
}

// UserResponse is the response body for user info.
// @Description User information
type UserResponse struct {
	ID          int64      `json:"id" example:"1"`
	Username    string     `json:"username" example:"admin"`
	Email       string     `json:"email,omitempty" example:"admin@cubeos.cube"`
	IsAdmin     bool       `json:"is_admin" example:"true"`
	CreatedAt   time.Time  `json:"created_at" example:"2025-01-01T00:00:00Z"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty" example:"2025-02-04T10:30:00Z"`
}

// RefreshRequest is the request body for token refresh.
// @Description Token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIs..."`
}

// ChangePasswordRequest is the request body for changing password.
// @Description Password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" example:"oldpassword"`
	NewPassword     string `json:"new_password" example:"newpassword123"`
}

// MessageResponse is a simple message response.
// @Description Simple message response
type MessageResponse struct {
	Message string `json:"message" example:"operation successful"`
}

// ErrorResponse represents an authentication error.
// @Description Authentication error response
type ErrorResponse struct {
	Error   string `json:"error" example:"bad_request"`
	Message string `json:"message" example:"invalid request body"`
}

// Login godoc
// @Summary User login
// @Description Authenticates a user and returns JWT access and refresh tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} TokenResponse "Successfully authenticated"
// @Failure 400 {object} ErrorResponse "Invalid request body or missing credentials"
// @Failure 401 {object} ErrorResponse "Invalid username or password"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/auth/login [post]
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

// Refresh godoc
// @Summary Refresh access token
// @Description Refreshes an expired access token using a valid refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh token"
// @Success 200 {object} TokenResponse "New access token"
// @Failure 400 {object} ErrorResponse "Invalid request body or missing refresh token"
// @Failure 401 {object} ErrorResponse "Invalid or expired refresh token"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/auth/refresh [post]
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

// Me godoc
// @Summary Get current user
// @Description Returns information about the currently authenticated user
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} UserResponse "Current user information"
// @Failure 401 {object} ErrorResponse "Authentication required"
// @Router /api/v1/auth/me [get]
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

// ChangePassword godoc
// @Summary Change password
// @Description Changes the password for the currently authenticated user
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ChangePasswordRequest true "Password change request"
// @Success 200 {object} MessageResponse "Password updated successfully"
// @Failure 400 {object} ErrorResponse "Invalid request or password requirements not met"
// @Failure 401 {object} ErrorResponse "Authentication required or current password incorrect"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/auth/password [post]
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

// Logout godoc
// @Summary User logout
// @Description Logs out the current user. With stateless JWTs, this is primarily for client-side token cleanup.
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} MessageResponse "Logged out successfully"
// @Router /api/v1/auth/logout [post]
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
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   "bad_request",
		Message: message,
	})
}


func internalError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   "internal_error",
		Message: message,
	})
}
