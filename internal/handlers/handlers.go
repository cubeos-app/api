package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"cubeos-api/internal/config"
	"cubeos-api/internal/database"
	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/middleware"
	"cubeos-api/internal/models"
)

// Handlers holds all handler dependencies
type Handlers struct {
	cfg         *config.Config
	db          *sqlx.DB
	system      *managers.SystemManager
	network     *managers.NetworkManager
	docker      *managers.DockerManager
	hal         *hal.Client
	filebrowser *managers.FileManagerClient
	piholePw    *managers.PiholePasswordClient
	npmMgr      *managers.NPMManager
	flowEngine  *flowengine.WorkflowEngine
	feStore     *flowengine.WorkflowStore
	startTime   time.Time
}

// SetFlowEngine wires the FlowEngine into the Handlers struct.
// Called from main.go after engine initialization.
func (h *Handlers) SetFlowEngine(engine *flowengine.WorkflowEngine, store *flowengine.WorkflowStore) {
	h.flowEngine = engine
	h.feStore = store
}

// NewHandlers creates a new Handlers instance.
// systemMgr and networkMgr are passed in to avoid creating duplicate instances
// (they are shared with WSManager, MonitoringManager, etc.).
func NewHandlers(cfg *config.Config, db *sqlx.DB, docker *managers.DockerManager, halClient *hal.Client, systemMgr *managers.SystemManager, networkMgr *managers.NetworkManager, fbClient *managers.FileManagerClient, piholePwClient *managers.PiholePasswordClient, npmMgr *managers.NPMManager) *Handlers {
	return &Handlers{
		cfg:         cfg,
		db:          db,
		system:      systemMgr,
		network:     networkMgr,
		docker:      docker,
		hal:         halClient,
		filebrowser: fbClient,
		piholePw:    piholePwClient,
		npmMgr:      npmMgr,
		startTime:   time.Now(),
	}
}

// Helper functions
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().Err(err).Msg("failed to encode JSON response")
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
// @Description Returns API health status, version, and uptime. NOTE: This endpoint is at root GET /health (outside /api/v1 BasePath), no auth required.
// @Tags Health
// @Produce json
// @Success 200 {object} models.HealthResponse "Health status"
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

	// Sync password to File Browser (non-fatal — best effort)
	if h.filebrowser != nil {
		go h.filebrowser.SyncAdminPassword(req.CurrentPassword, req.NewPassword)
	}
	// Sync password to Pi-hole (non-fatal — best effort)
	if h.piholePw != nil {
		go h.piholePw.SyncAdminPassword(req.CurrentPassword, req.NewPassword)
	}
	// Sync password to NPM human admin (non-fatal — best effort)
	if h.npmMgr != nil {
		go h.npmMgr.SyncAdminPassword(req.CurrentPassword, req.NewPassword)
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

	// Ensure CubeOS version is populated (prefer env var, fallback to config)
	if info.CubeOSVersion == "" {
		info.CubeOSVersion = h.cfg.Version
	}

	// Override hostname from HAL (host-level access) — same as GetHostname handler
	if halHostname, err := h.hal.GetHostname(r.Context()); err == nil {
		info.Hostname = halHostname.Hostname
	}

	// Override OS info from HAL (reads host /etc/os-release, not container's Alpine)
	if halOS, err := h.hal.GetOSInfo(r.Context()); err == nil {
		// Prefer PRETTY_NAME ("Ubuntu 24.04.3 LTS") over bare NAME ("Ubuntu")
		if halOS.Pretty != "" {
			info.OSName = halOS.Pretty
		} else if halOS.Name != "" {
			info.OSName = halOS.Name
		}
		if halOS.Version != "" {
			info.OSVersion = halOS.Version
		}
	}

	// Check if admin account still uses default credentials
	var passwordHash string
	err := h.db.Get(&passwordHash, "SELECT password_hash FROM users WHERE username = 'admin'")
	if err == nil {
		if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("cubeos")) == nil {
			info.DefaultCredentials = true
		}
	}

	writeJSON(w, http.StatusOK, info)
}

// ValidateConfig godoc
// @Summary Validate running configuration
// @Description Re-runs startup configuration validation checks and returns individual results. Useful for debugging config issues on-device.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Validation results with overall valid flag and per-field checks"
// @Router /system/config/validate [get]
func (h *Handlers) ValidateConfig(w http.ResponseWriter, r *http.Request) {
	results := h.cfg.ValidateAll()
	allValid := true
	for _, res := range results {
		if !res.Valid {
			allValid = false
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":  allValid,
		"checks": results,
	})
}

// GetAccessProfile godoc
// @Summary Get current access profile
// @Description Returns the current access profile and full configuration. Credentials (tokens, passwords) are masked in the response.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} database.AccessProfileConfig "Access profile configuration"
// @Router /system/access-profile [get]
func (h *Handlers) GetAccessProfile(w http.ResponseWriter, r *http.Request) {
	cfg, err := database.GetAccessProfileConfig(h.db.DB)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Mask credentials in response
	resp := map[string]interface{}{
		"profile":             cfg.Profile,
		"ext_npm_url":         cfg.ExtNPMURL,
		"ext_npm_token":       maskSecret(cfg.ExtNPMToken),
		"ext_pihole_url":      cfg.ExtPiholeURL,
		"ext_pihole_password": maskSecret(cfg.ExtPiholePass),
		"aio_dhcp_enabled":    cfg.AIODHCPEnabled,
		"aio_dns_enabled":     cfg.AIODNSEnabled,
		"aio_proxy_enabled":   cfg.AIOProxyEnabled,
	}
	writeJSON(w, http.StatusOK, resp)
}

// UpdateAccessProfile godoc
// @Summary Update access profile
// @Description Updates the access profile. If the profile changes, submits an access_profile_switch workflow (202 Accepted). If the same profile, just saves config (200 OK).
// @Tags System
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body database.AccessProfileConfig true "Access profile configuration"
// @Success 200 {object} map[string]string "Same profile, config saved"
// @Success 202 {object} map[string]string "Profile switch workflow started (job_id returned)"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /system/access-profile [put]
func (h *Handlers) UpdateAccessProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile       string `json:"profile"`
		ExtNPMURL     string `json:"ext_npm_url"`
		ExtNPMToken   string `json:"ext_npm_token"`
		ExtPiholeURL  string `json:"ext_pihole_url"`
		ExtPiholePass string `json:"ext_pihole_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if !database.ValidAccessProfiles[req.Profile] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "profile must be one of: standard, advanced, all_in_one"})
		return
	}
	if req.Profile == "advanced" {
		if req.ExtNPMURL == "" || req.ExtPiholeURL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "advanced profile requires ext_npm_url and ext_pihole_url"})
			return
		}
	}

	// Get current profile to determine if migration is needed
	currentProfile, err := database.GetAccessProfile(h.db.DB)
	if err != nil {
		log.Error().Err(err).Msg("failed to read current access profile")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read current profile"})
		return
	}

	// Same profile → just save config, no migration needed
	if currentProfile == req.Profile {
		cfg := &database.AccessProfileConfig{
			Profile:       req.Profile,
			ExtNPMURL:     req.ExtNPMURL,
			ExtNPMToken:   req.ExtNPMToken,
			ExtPiholeURL:  req.ExtPiholeURL,
			ExtPiholePass: req.ExtPiholePass,
		}
		if err := database.SetAccessProfileConfig(h.db.DB, cfg); err != nil {
			log.Error().Err(err).Msg("failed to save access profile config")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save profile"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"profile": req.Profile,
			"message": "Profile config updated (no migration needed)",
		})
		return
	}

	// Different profile → submit workflow
	if h.flowEngine == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "FlowEngine not available"})
		return
	}

	// Save credentials first (workflow reads them from fat envelope, but also persist in DB)
	cfg := &database.AccessProfileConfig{
		Profile:       currentProfile, // keep current profile until workflow succeeds
		ExtNPMURL:     req.ExtNPMURL,
		ExtNPMToken:   req.ExtNPMToken,
		ExtPiholeURL:  req.ExtPiholeURL,
		ExtPiholePass: req.ExtPiholePass,
	}
	if err := database.SetAccessProfileConfig(h.db.DB, cfg); err != nil {
		log.Error().Err(err).Msg("failed to save credentials before workflow")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save credentials"})
		return
	}

	// Get gateway IP for the workflow
	gatewayIP := h.cfg.GatewayIP
	if gatewayIP == "" {
		gatewayIP = models.DefaultGatewayIP
	}

	workflowInput := map[string]string{
		"from_profile":        currentProfile,
		"to_profile":          req.Profile,
		"ext_npm_url":         req.ExtNPMURL,
		"ext_npm_token":       req.ExtNPMToken,
		"ext_pihole_url":      req.ExtPiholeURL,
		"ext_pihole_password": req.ExtPiholePass,
		"gateway_ip":          gatewayIP,
	}
	inputJSON, err := json.Marshal(workflowInput)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to marshal workflow input"})
		return
	}

	wf, err := h.flowEngine.Submit(r.Context(), flowengine.SubmitParams{
		WorkflowType: "access_profile_switch",
		ExternalID:   "profile:" + currentProfile + "→" + req.Profile,
		Input:        inputJSON,
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to submit access_profile_switch workflow")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start profile switch: " + err.Error()})
		return
	}

	log.Info().Str("workflow_id", wf.ID).Str("from", currentProfile).Str("to", req.Profile).Msg("access_profile_switch workflow submitted")
	writeJSON(w, http.StatusAccepted, map[string]string{
		"job_id":  wf.ID,
		"message": "Profile switch started",
		"from":    currentProfile,
		"to":      req.Profile,
	})
}

// TestAccessProfile godoc
// @Summary Test external access profile credentials
// @Description Tests connectivity to external NPM and Pi-hole instances. Returns per-service results even if one fails.
// @Tags System
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body map[string]string true "External credentials to test"
// @Success 200 {object} map[string]interface{} "Test results with npm_ok, pihole_ok, versions, errors"
// @Router /system/access-profile/test [post]
func (h *Handlers) TestAccessProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExtNPMURL     string `json:"ext_npm_url"`
		ExtNPMToken   string `json:"ext_npm_token"`
		ExtPiholeURL  string `json:"ext_pihole_url"`
		ExtPiholePass string `json:"ext_pihole_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	result := map[string]interface{}{
		"npm_ok":         false,
		"npm_version":    "",
		"npm_error":      "",
		"pihole_ok":      false,
		"pihole_version": "",
		"pihole_error":   "",
	}

	// Test NPM connectivity
	if req.ExtNPMURL != "" {
		npmOK, npmVersion, npmErr := testExternalNPM(r.Context(), req.ExtNPMURL, req.ExtNPMToken)
		result["npm_ok"] = npmOK
		result["npm_version"] = npmVersion
		result["npm_error"] = npmErr
	} else {
		result["npm_error"] = "no URL provided"
	}

	// Test Pi-hole connectivity
	if req.ExtPiholeURL != "" {
		phOK, phVersion, phErr := testExternalPihole(r.Context(), req.ExtPiholeURL, req.ExtPiholePass)
		result["pihole_ok"] = phOK
		result["pihole_version"] = phVersion
		result["pihole_error"] = phErr
	} else {
		result["pihole_error"] = "no URL provided"
	}

	writeJSON(w, http.StatusOK, result)
}

// maskSecret returns a masked version of a secret string.
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
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
// @Description Initiates system reboot via HAL (privileged host access)
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse "Reboot initiated"
// @Failure 500 {object} ErrorResponse "Failed to initiate reboot"
// @Router /system/reboot [post]
func (h *Handlers) Reboot(w http.ResponseWriter, r *http.Request) {
	// Proxy to HAL which has privileged access (nsenter + pid:host)
	if err := h.hal.Reboot(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "reboot failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "initiated",
		"action":  "reboot",
		"message": "System rebooting now",
	})
}

// Shutdown godoc
// @Summary Shutdown system
// @Description Initiates system shutdown via HAL (privileged host access)
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse "Shutdown initiated"
// @Failure 500 {object} ErrorResponse "Failed to initiate shutdown"
// @Router /system/shutdown [post]
func (h *Handlers) Shutdown(w http.ResponseWriter, r *http.Request) {
	// Proxy to HAL which has privileged access (nsenter + pid:host)
	if err := h.hal.Shutdown(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "shutdown failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "initiated",
		"action":  "shutdown",
		"message": "System shutting down now",
	})
}

// GetHostname godoc
// @Summary Get hostname
// @Description Returns the system hostname via HAL (host-level access). Falls back to container hostname if HAL is unreachable.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "Hostname"
// @Router /system/hostname [get]
func (h *Handlers) GetHostname(w http.ResponseWriter, r *http.Request) {
	info, err := h.hal.GetHostname(r.Context())
	if err != nil {
		// Fallback: if HAL is unreachable, return container hostname
		log.Warn().Err(err).Msg("HAL hostname request failed, using fallback")
		writeJSON(w, http.StatusOK, map[string]string{
			"hostname": h.system.GetHostname(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"hostname": info.Hostname,
	})
}

// SetHostname godoc
// @Summary Set hostname
// @Description Sets the system hostname via HAL (host-level access)
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
	if err := h.hal.SetHostname(r.Context(), req.Hostname); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set hostname: "+err.Error())
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
	clients, err := h.network.GetConnectedClients(r.Context())
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
	clients, _ := h.network.GetConnectedClients(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":     len(clients),
		"timestamp": time.Now(),
	})
}

// BlockClient godoc
// @Summary Block a client
// @Description Blocks a client by MAC address from the access point
// @Tags Clients
// @Produce json
// @Security BearerAuth
// @Param mac path string true "MAC address"
// @Success 200 {object} models.SuccessResponse "Client blocked"
// @Failure 400 {object} ErrorResponse "Invalid MAC address"
// @Failure 500 {object} ErrorResponse "Failed to block client"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /clients/{mac}/block [post]
func (h *Handlers) BlockClient(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	if mac == "" {
		writeError(w, http.StatusBadRequest, "MAC address is required")
		return
	}
	if h.hal == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	if err := h.hal.BlockAPClient(r.Context(), mac); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to block client: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Client " + mac + " blocked",
	})
}

// UnblockClient godoc
// @Summary Unblock a client
// @Description Unblocks a previously blocked client by MAC address
// @Tags Clients
// @Produce json
// @Security BearerAuth
// @Param mac path string true "MAC address"
// @Success 200 {object} models.SuccessResponse "Client unblocked"
// @Failure 400 {object} ErrorResponse "Invalid MAC address"
// @Failure 500 {object} ErrorResponse "Failed to unblock client"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /clients/{mac}/unblock [post]
func (h *Handlers) UnblockClient(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	if mac == "" {
		writeError(w, http.StatusBadRequest, "MAC address is required")
		return
	}
	if h.hal == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	if err := h.hal.UnblockAPClient(r.Context(), mac); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to unblock client: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Client " + mac + " unblocked",
	})
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

// =============================================================================
// Services (DEPRECATED — use /apps/* via Orchestrator instead)
// =============================================================================

// ListServices godoc
// @Summary List Docker services
// @Description Returns list of all Docker services/containers. Deprecated: use GET /apps instead.
// @Tags Services
// @Deprecated
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
// @Description Returns details of a specific Docker service/container. Deprecated: use GET /apps/{name} instead.
// @Tags Services
// @Deprecated
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
// @Description Starts a Docker service/container. Deprecated: use POST /apps/{name}/start instead.
// @Tags Services
// @Deprecated
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
// @Description Stops a Docker service/container. Deprecated: use POST /apps/{name}/stop instead.
// @Tags Services
// @Deprecated
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
// @Description Restarts a Docker service/container. Deprecated: use POST /apps/{name}/restart instead.
// @Tags Services
// @Deprecated
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
// @Description Enables a Docker service for auto-start. Deprecated: use POST /apps/{name}/enable instead.
// @Tags Services
// @Deprecated
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
// @Description Disables a Docker service from auto-start. Deprecated: use POST /apps/{name}/disable instead.
// @Tags Services
// @Deprecated
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

// GetWiFiAPWhitelist godoc
// @Summary Get WiFi AP whitelist
// @Description Returns USB WiFi adapters that have passed AP capability testing
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {array} hal.WiFiAPTestResult
// @Failure 500 {object} ErrorResponse
// @Router /system/wifi-ap/whitelist [get]
func (h *Handlers) GetWiFiAPWhitelist(w http.ResponseWriter, r *http.Request) {
	list, err := h.hal.GetWiFiAPWhitelist(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get whitelist: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// GetWiFiAPBlacklist godoc
// @Summary Get WiFi AP blacklist
// @Description Returns USB WiFi adapters that have failed AP capability testing
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {array} hal.WiFiAPTestResult
// @Failure 500 {object} ErrorResponse
// @Router /system/wifi-ap/blacklist [get]
func (h *Handlers) GetWiFiAPBlacklist(w http.ResponseWriter, r *http.Request) {
	list, err := h.hal.GetWiFiAPBlacklist(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get blacklist: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// RetestWiFiAdapter godoc
// @Summary Re-test a blacklisted WiFi adapter
// @Description Removes adapter from blacklist and re-runs AP capability test
// @Tags System
// @Produce json
// @Param device_id path string true "Vendor:Product ID (e.g. 0bda:8812)"
// @Security BearerAuth
// @Success 200 {object} hal.WiFiAPTestResult
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /system/wifi-ap/retest/{device_id} [post]
func (h *Handlers) RetestWiFiAdapter(w http.ResponseWriter, r *http.Request) {
	// Extract device_id from the wildcard path
	deviceID := strings.TrimPrefix(r.URL.Path, "/api/v1/system/wifi-ap/retest/")
	if deviceID == "" || !strings.Contains(deviceID, ":") {
		writeError(w, http.StatusBadRequest, "Invalid device_id, expected vendor:product (e.g. 0bda:8812)")
		return
	}
	result, err := h.hal.RetestWiFiAdapter(r.Context(), deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Re-test failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
