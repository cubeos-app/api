package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"

	"cubeos-api/internal/config"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/middleware"
	"cubeos-api/internal/models"
)

// Handlers holds all handler dependencies
type Handlers struct {
	cfg       *config.Config
	db        *sqlx.DB
	system    *managers.SystemManager
	network   *managers.NetworkManager
	docker    *managers.DockerManager
	hal       *hal.Client
	startTime time.Time
}

// NewHandlers creates a new Handlers instance.
// systemMgr and networkMgr are passed in to avoid creating duplicate instances
// (they are shared with WSManager, MonitoringManager, etc.).
func NewHandlers(cfg *config.Config, db *sqlx.DB, docker *managers.DockerManager, halClient *hal.Client, systemMgr *managers.SystemManager, networkMgr *managers.NetworkManager) *Handlers {
	return &Handlers{
		cfg:       cfg,
		db:        db,
		system:    systemMgr,
		network:   networkMgr,
		docker:    docker,
		hal:       halClient,
		startTime: time.Now(),
	}
}

// Helper functions
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("ERROR: failed to encode JSON response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, models.ErrorResponse{Error: message, Code: status})
}

// =============================================================================
// Health
// =============================================================================

// Health godoc
// @Summary Health check
// @Description Returns API health status, version, and uptime
// @Tags Health
// @Produce json
// @Success 200 {object} models.HealthResponse "Health status"
// @Router /health [get]
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(h.startTime).Seconds()
	writeJSON(w, http.StatusOK, models.HealthResponse{
		Status:    "healthy",
		Version:   h.cfg.Version,
		Timestamp: time.Now(),
		Uptime:    uptime,
	})
}

// =============================================================================
// Authentication
// =============================================================================

// Login godoc
// @Summary User login
// @Description Authenticate user and return JWT access token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.LoginResponse "Login successful"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 401 {object} ErrorResponse "Invalid credentials"
// @Failure 500 {object} ErrorResponse "Server error"
// @Router /auth/login [post]
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get user from database
	var user models.User
	err := h.db.Get(&user, "SELECT * FROM users WHERE username = ?", req.Username)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Generate token
	token, err := middleware.GenerateToken(user.Username, user.Role, h.cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	writeJSON(w, http.StatusOK, models.LoginResponse{
		AccessToken: token,
		TokenType:   "bearer",
		ExpiresIn:   h.cfg.JWTExpirationHours * 3600,
		User: struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}{
			Username: user.Username,
			Role:     user.Role,
		},
	})
}

// Logout godoc
// @Summary User logout
// @Description Logout current user (client should discard token)
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse "Logout successful"
// @Router /auth/logout [post]
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, models.SuccessResponse{
		Status:  "success",
		Message: "Logged out successfully",
	})
}

// RefreshToken godoc
// @Summary Refresh JWT token
// @Description Generate a new JWT token using existing valid token
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "New token"
// @Failure 401 {object} ErrorResponse "Invalid token"
// @Failure 500 {object} ErrorResponse "Failed to generate token"
// @Router /auth/refresh [post]
func (h *Handlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetUserFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	token, err := middleware.GenerateToken(claims.Username, claims.Role, h.cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   h.cfg.JWTExpirationHours * 3600,
	})
}

// GetMe godoc
// @Summary Get current user
// @Description Returns current authenticated user information
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "User info with username and role"
// @Failure 401 {object} ErrorResponse "Invalid token"
// @Router /auth/me [get]
func (h *Handlers) GetMe(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetUserFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"username": claims.Username,
		"role":     claims.Role,
	})
}

// ChangePassword godoc
// @Summary Change password
// @Description Change password for current authenticated user
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.ChangePasswordRequest true "Current and new password"
// @Success 200 {object} models.SuccessResponse "Password changed successfully"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 401 {object} ErrorResponse "Invalid token or current password incorrect"
// @Failure 500 {object} ErrorResponse "Server error"
// @Router /auth/password [post]
func (h *Handlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetUserFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	var req models.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate new password length
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "New password must be at least 8 characters")
		return
	}

	var currentHash string
	err := h.db.Get(&currentHash, "SELECT password_hash FROM users WHERE username = ?", claims.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
		writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), config.BcryptCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	_, err = h.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(newHash), claims.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update password")
		return
	}

	writeJSON(w, http.StatusOK, models.SuccessResponse{
		Status:  "success",
		Message: "Password changed successfully",
	})
}

// =============================================================================
// System
// =============================================================================

// GetSystemInfo godoc
// @Summary Get system information
// @Description Returns detailed system information including hardware, OS, and memory
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SystemInfo "System information"
// @Router /system/info [get]
func (h *Handlers) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	info := h.system.GetSystemInfo()
	writeJSON(w, http.StatusOK, info)
}

// GetSystemStats godoc
// @Summary Get system statistics
// @Description Returns current system statistics including CPU, memory, and disk usage
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SystemStats "System statistics"
// @Router /system/stats [get]
func (h *Handlers) GetSystemStats(w http.ResponseWriter, r *http.Request) {
	stats := h.system.GetSystemStats()
	writeJSON(w, http.StatusOK, stats)
}

// GetTemperature godoc
// @Summary Get CPU temperature
// @Description Returns current CPU/SoC temperature
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.Temperature "Temperature information"
// @Router /system/temperature [get]
func (h *Handlers) GetTemperature(w http.ResponseWriter, r *http.Request) {
	temp := h.system.GetTemperature()
	writeJSON(w, http.StatusOK, temp)
}

// Reboot godoc
// @Summary Reboot system
// @Description Initiates system reboot with optional delay
// @Tags System
// @Produce json
// @Security BearerAuth
// @Param delay query int false "Delay in seconds before reboot" default(0)
// @Success 200 {object} models.SuccessResponse "Reboot scheduled"
// @Failure 500 {object} ErrorResponse "Failed to schedule reboot"
// @Router /system/reboot [post]
func (h *Handlers) Reboot(w http.ResponseWriter, r *http.Request) {
	delay, _ := strconv.Atoi(r.URL.Query().Get("delay"))
	result, err := h.system.Reboot(delay)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Shutdown godoc
// @Summary Shutdown system
// @Description Initiates system shutdown with optional delay
// @Tags System
// @Produce json
// @Security BearerAuth
// @Param delay query int false "Delay in seconds before shutdown" default(0)
// @Success 200 {object} models.SuccessResponse "Shutdown scheduled"
// @Failure 500 {object} ErrorResponse "Failed to schedule shutdown"
// @Router /system/shutdown [post]
func (h *Handlers) Shutdown(w http.ResponseWriter, r *http.Request) {
	delay, _ := strconv.Atoi(r.URL.Query().Get("delay"))
	result, err := h.system.Shutdown(delay)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// GetHostname godoc
// @Summary Get hostname
// @Description Returns the system hostname
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "Hostname"
// @Router /system/hostname [get]
func (h *Handlers) GetHostname(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"hostname": h.system.GetHostname(),
	})
}

// SetHostname godoc
// @Summary Set hostname
// @Description Sets the system hostname
// @Tags System
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "Hostname" example({"hostname": "cubeos"})
// @Success 200 {object} models.SuccessResponse "Hostname updated"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to set hostname"
// @Router /system/hostname [post]
func (h *Handlers) SetHostname(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "Hostname is required")
		return
	}
	if err := h.system.SetHostname(req.Hostname); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, models.SuccessResponse{
		Status:  "success",
		Message: "Hostname updated to " + req.Hostname,
	})
}

// GetTimezone godoc
// @Summary Get timezone
// @Description Returns the current system timezone
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "Timezone"
// @Router /system/timezone [get]
func (h *Handlers) GetTimezone(w http.ResponseWriter, r *http.Request) {
	tz := h.system.GetTimezone()
	writeJSON(w, http.StatusOK, map[string]string{
		"timezone": tz,
	})
}

// SetTimezone godoc
// @Summary Set timezone
// @Description Sets the system timezone
// @Tags System
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "Timezone" example({"timezone": "Europe/Amsterdam"})
// @Success 200 {object} models.SuccessResponse "Timezone updated"
// @Failure 400 {object} ErrorResponse "Invalid request body or timezone"
// @Failure 500 {object} ErrorResponse "Failed to set timezone"
// @Router /system/timezone [post]
func (h *Handlers) SetTimezone(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timezone string `json:"timezone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Timezone == "" {
		writeError(w, http.StatusBadRequest, "Timezone is required")
		return
	}
	if err := h.system.SetTimezone(req.Timezone); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, models.SuccessResponse{
		Status:  "success",
		Message: "Timezone updated to " + req.Timezone,
	})
}

// GetTimezones godoc
// @Summary List available timezones
// @Description Returns list of available system timezones
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Available timezones"
// @Router /system/timezones [get]
func (h *Handlers) GetTimezones(w http.ResponseWriter, r *http.Request) {
	timezones := h.system.GetTimezones()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"timezones": timezones,
		"count":     len(timezones),
	})
}

// =============================================================================
// Clients
// =============================================================================

// GetConnectedClients godoc
// @Summary List connected clients
// @Description Returns list of connected WiFi clients
// @Tags Clients
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Connected clients"
// @Failure 500 {object} ErrorResponse "Failed to get clients"
// @Router /clients [get]
func (h *Handlers) GetConnectedClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.network.GetConnectedClients()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_count": len(clients),
		"clients":     clients,
		"timestamp":   time.Now(),
	})
}

// GetClientCount godoc
// @Summary Get client count
// @Description Returns number of connected WiFi clients
// @Tags Clients
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Client count"
// @Router /clients/count [get]
func (h *Handlers) GetClientCount(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.network.GetConnectedClients()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":     len(clients),
		"timestamp": time.Now(),
	})
}

// BlockClient godoc
// @Summary Block a client
// @Description Blocks a client by MAC address
// @Tags Clients
// @Produce json
// @Security BearerAuth
// @Param mac path string true "MAC address"
// @Success 200 {object} models.SuccessResponse "Client blocked"
// @Failure 501 {object} ErrorResponse "Not implemented"
// @Router /clients/{mac}/block [post]
func (h *Handlers) BlockClient(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	writeError(w, http.StatusNotImplemented, "Client blocking not yet implemented for MAC: "+mac)
}

// UnblockClient godoc
// @Summary Unblock a client
// @Description Unblocks a previously blocked client by MAC address
// @Tags Clients
// @Produce json
// @Security BearerAuth
// @Param mac path string true "MAC address"
// @Success 200 {object} models.SuccessResponse "Client unblocked"
// @Failure 501 {object} ErrorResponse "Not implemented"
// @Router /clients/{mac}/unblock [post]
func (h *Handlers) UnblockClient(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	writeError(w, http.StatusNotImplemented, "Client unblocking not yet implemented for MAC: "+mac)
}

// =============================================================================
// Storage
// =============================================================================

// GetStorage godoc
// @Summary Get storage overview
// @Description Returns storage overview and mount information
// @Tags Storage
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Storage information"
// @Router /storage [get]
func (h *Handlers) GetStorage(w http.ResponseWriter, r *http.Request) {
	overview := h.system.GetStorageOverview()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"overview": overview,
	})
}

// GetMounts godoc
// @Summary List mounts
// @Description Returns list of mounted filesystems
// @Tags Storage
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Mount points"
// @Router /storage/mounts [get]
func (h *Handlers) GetMounts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mounts": []interface{}{},
		"count":  0,
	})
}

// AddMount godoc
// @Summary Add mount
// @Description Adds a new mount point
// @Tags Storage
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param mount body object true "Mount configuration"
// @Success 200 {object} models.SuccessResponse "Mount added"
// @Failure 501 {object} ErrorResponse "Not implemented"
// @Router /storage/mounts [post]
func (h *Handlers) AddMount(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "Mount management not yet implemented")
}

// RemoveMount godoc
// @Summary Remove mount
// @Description Removes a mount point
// @Tags Storage
// @Produce json
// @Security BearerAuth
// @Param id path string true "Mount ID"
// @Success 200 {object} models.SuccessResponse "Mount removed"
// @Failure 501 {object} ErrorResponse "Not implemented"
// @Router /storage/mounts/{id} [delete]
func (h *Handlers) RemoveMount(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "Mount management not yet implemented")
}

// =============================================================================
// Services
// =============================================================================

// ListServices godoc
// @Summary List Docker services
// @Description Returns list of all Docker services/containers
// @Tags Services
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Docker services"
// @Failure 500 {object} ErrorResponse "Failed to get services"
// @Router /services [get]
func (h *Handlers) ListServices(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	resp, err := h.docker.GetServicesResponse(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetService godoc
// @Summary Get Docker service
// @Description Returns details of a specific Docker service/container
// @Tags Services
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} map[string]interface{} "Service details"
// @Failure 404 {object} ErrorResponse "Service not found"
// @Router /services/{name} [get]
func (h *Handlers) GetService(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	name := chi.URLParam(r, "name")
	container, err := h.docker.GetContainer(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Service not found")
		return
	}
	writeJSON(w, http.StatusOK, container)
}

// StartService godoc
// @Summary Start Docker service
// @Description Starts a Docker service/container
// @Tags Services
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} models.ServiceAction "Service started"
// @Failure 403 {object} ErrorResponse "Cannot modify core service"
// @Failure 500 {object} ErrorResponse "Failed to start service"
// @Router /services/{name}/start [post]
func (h *Handlers) StartService(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	name := chi.URLParam(r, "name")
	if config.IsCoreService(name) {
		writeError(w, http.StatusForbidden, "Cannot modify core service")
		return
	}
	if err := h.docker.StartContainer(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, models.ServiceAction{
		Success: true,
		Service: name,
		Action:  "start",
		Message: "Service started",
	})
}

// StopService godoc
// @Summary Stop Docker service
// @Description Stops a Docker service/container
// @Tags Services
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} models.ServiceAction "Service stopped"
// @Failure 403 {object} ErrorResponse "Cannot modify core service"
// @Failure 500 {object} ErrorResponse "Failed to stop service"
// @Router /services/{name}/stop [post]
func (h *Handlers) StopService(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	name := chi.URLParam(r, "name")
	if config.IsCoreService(name) {
		writeError(w, http.StatusForbidden, "Cannot modify core service")
		return
	}
	if err := h.docker.StopContainer(r.Context(), name, h.cfg.ContainerStopTimeout); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, models.ServiceAction{
		Success: true,
		Service: name,
		Action:  "stop",
		Message: "Service stopped",
	})
}

// RestartService godoc
// @Summary Restart Docker service
// @Description Restarts a Docker service/container
// @Tags Services
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} models.ServiceAction "Service restarted"
// @Failure 500 {object} ErrorResponse "Failed to restart service"
// @Router /services/{name}/restart [post]
func (h *Handlers) RestartService(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	name := chi.URLParam(r, "name")
	if err := h.docker.RestartContainer(r.Context(), name, h.cfg.ContainerStopTimeout); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, models.ServiceAction{
		Success: true,
		Service: name,
		Action:  "restart",
		Message: "Service restarted",
	})
}

// EnableService godoc
// @Summary Enable Docker service
// @Description Enables a Docker service for auto-start
// @Tags Services
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} map[string]interface{} "Service enabled"
// @Failure 403 {object} ErrorResponse "Cannot modify core service"
// @Failure 500 {object} ErrorResponse "Failed to enable service"
// @Router /services/{name}/enable [post]
func (h *Handlers) EnableService(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	name := chi.URLParam(r, "name")
	if config.IsCoreService(name) {
		writeError(w, http.StatusForbidden, "Cannot modify core service")
		return
	}
	result, err := h.docker.EnableService(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// DisableService godoc
// @Summary Disable Docker service
// @Description Disables a Docker service from auto-start
// @Tags Services
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} map[string]interface{} "Service disabled"
// @Failure 403 {object} ErrorResponse "Cannot modify core service"
// @Failure 500 {object} ErrorResponse "Failed to disable service"
// @Router /services/{name}/disable [post]
func (h *Handlers) DisableService(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	name := chi.URLParam(r, "name")
	if config.IsCoreService(name) {
		writeError(w, http.StatusForbidden, "Cannot modify core service")
		return
	}
	result, err := h.docker.DisableService(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// =============================================================================
// Docker Management
// =============================================================================

// DockerPrune godoc
// @Summary Prune Docker resources
// @Description Removes unused Docker resources (containers, images, volumes, networks)
// @Tags Docker
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Prune results"
// @Failure 503 {object} ErrorResponse "Docker not available"
// @Router /docker/prune [post]
func (h *Handlers) DockerPrune(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	result, err := h.docker.PruneAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Docker cleanup completed",
		"result":  result,
	})
}

// DockerDiskUsage godoc
// @Summary Get Docker disk usage
// @Description Returns Docker disk usage statistics
// @Tags Docker
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Docker disk usage"
// @Failure 503 {object} ErrorResponse "Docker not available"
// @Router /docker/disk-usage [get]
func (h *Handlers) DockerDiskUsage(w http.ResponseWriter, r *http.Request) {
	if h.docker == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker not available")
		return
	}
	usage, err := h.docker.GetDiskUsage(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, usage)
}

// formatByteSize converts bytes to human readable format
func formatByteSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
