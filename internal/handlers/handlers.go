package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
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

// NewHandlers creates a new Handlers instance
func NewHandlers(cfg *config.Config, db *sqlx.DB, docker *managers.DockerManager, halClient *hal.Client) *Handlers {
	return &Handlers{
		cfg:       cfg,
		db:        db,
		system:    managers.NewSystemManager(),
		network:   managers.NewNetworkManager(cfg, halClient, db),
		docker:    docker,
		hal:       halClient,
		startTime: time.Now(),
	}
}

// Helper functions
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, models.ErrorResponse{Error: message, Code: status})
}

// =============================================================================
// Health
// =============================================================================

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

	// Get current password hash
	var currentHash string
	err := h.db.Get(&currentHash, "SELECT password_hash FROM users WHERE username = ?", claims.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
		writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	// Hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	// Update password
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

func (h *Handlers) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	info := h.system.GetSystemInfo()
	writeJSON(w, http.StatusOK, info)
}

func (h *Handlers) GetSystemStats(w http.ResponseWriter, r *http.Request) {
	stats := h.system.GetSystemStats()
	writeJSON(w, http.StatusOK, stats)
}

func (h *Handlers) GetTemperature(w http.ResponseWriter, r *http.Request) {
	temp := h.system.GetTemperature()
	writeJSON(w, http.StatusOK, temp)
}

func (h *Handlers) Reboot(w http.ResponseWriter, r *http.Request) {
	delay, _ := strconv.Atoi(r.URL.Query().Get("delay"))

	result, err := h.system.Reboot(delay)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handlers) Shutdown(w http.ResponseWriter, r *http.Request) {
	delay, _ := strconv.Atoi(r.URL.Query().Get("delay"))

	result, err := h.system.Shutdown(delay)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handlers) CancelShutdown(w http.ResponseWriter, r *http.Request) {
	result, _ := h.system.CancelShutdown()
	writeJSON(w, http.StatusOK, result)
}

func (h *Handlers) GetUptime(w http.ResponseWriter, r *http.Request) {
	secs, human := h.system.GetUptime()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"uptime_seconds": secs,
		"uptime_human":   human,
		"boot_time":      h.system.GetBootTime(),
	})
}

func (h *Handlers) GetHostname(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"hostname": h.system.GetHostname(),
	})
}

func (h *Handlers) GetDateTime(w http.ResponseWriter, r *http.Request) {
	dt, tz := h.system.GetDateTime()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"datetime":  dt.Format(time.RFC3339),
		"timestamp": dt.Unix(),
		"timezone":  tz,
	})
}

func (h *Handlers) GetSystemdServices(w http.ResponseWriter, r *http.Request) {
	services := []string{"hostapd", "dnsmasq", "docker", "nginx", "pihole-FTL"}
	statuses := make(map[string]interface{})

	for _, svc := range services {
		statuses[svc] = h.system.GetServiceStatus(svc)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"services": statuses})
}

func (h *Handlers) GetSystemdService(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")
	status := h.system.GetServiceStatus(service)
	writeJSON(w, http.StatusOK, status)
}

func (h *Handlers) RestartSystemdService(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")

	// Allowed services
	allowed := map[string]bool{
		"hostapd": true, "dnsmasq": true, "docker": true, "nginx": true, "pihole-FTL": true,
	}

	if !allowed[service] {
		writeError(w, http.StatusForbidden, "Service not allowed")
		return
	}

	if err := h.system.RestartService(service); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, models.SuccessResponse{
		Status:  "success",
		Message: "Service " + service + " restarted",
	})
}

// =============================================================================
// Network
// =============================================================================

func (h *Handlers) GetNetworkInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces := h.system.GetNetworkInterfaces()
	writeJSON(w, http.StatusOK, interfaces)
}

func (h *Handlers) GetNetworkInterface(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	interfaces := h.system.GetNetworkInterfaces()

	for _, iface := range interfaces {
		if iface.Name == name {
			writeJSON(w, http.StatusOK, iface)
			return
		}
	}

	writeError(w, http.StatusNotFound, "Interface not found")
}

func (h *Handlers) GetAPStatus(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement via HAL when AP management is added
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "running",
		"ssid":    "CubeOS",
		"message": "AP status via HAL not yet implemented",
	})
}

func (h *Handlers) GetAPConfig(w http.ResponseWriter, r *http.Request) {
	// Return current config from environment
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ssid":    "CubeOS",
		"channel": 7, // Default
		"hidden":  false,
	})
}

func (h *Handlers) UpdateAPConfig(w http.ResponseWriter, r *http.Request) {
	var cfg models.WiFiAPConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// TODO: Implement via HAL
	writeError(w, http.StatusNotImplemented, "AP configuration update not yet implemented")
}

func (h *Handlers) RestartAP(w http.ResponseWriter, r *http.Request) {
	if err := h.network.RestartAP(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, models.SuccessResponse{
		Status:  "success",
		Message: "WiFi AP restarted",
	})
}

func (h *Handlers) GetDHCPLeases(w http.ResponseWriter, r *http.Request) {
	// DHCP is managed by Pi-hole - return stub
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"leases":  []interface{}{},
		"count":   0,
		"message": "DHCP leases managed by Pi-hole",
	})
}

func (h *Handlers) RestartDHCP(w http.ResponseWriter, r *http.Request) {
	// DHCP is managed by Pi-hole
	if h.hal != nil {
		if err := h.hal.RestartService(r.Context(), "pihole-FTL"); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, models.SuccessResponse{
		Status:  "success",
		Message: "DHCP server restart requested",
	})
}

func (h *Handlers) CheckInternet(w http.ResponseWriter, r *http.Request) {
	connected := h.network.CheckInternetConnectivity(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"connected": connected,
		"timestamp": time.Now(),
	})
}

func (h *Handlers) GetWiFiQR(w http.ResponseWriter, r *http.Request) {
	// Return WiFi credentials for QR generation on frontend
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ssid":      "CubeOS",
		"auth_type": "WPA",
		"message":   "Generate QR on frontend",
	})
}

func (h *Handlers) GetNetworkInterfacesDetailed(w http.ResponseWriter, r *http.Request) {
	interfaces, err := h.network.GetInterfaces(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interfaces": interfaces,
		"count":      len(interfaces),
		"timestamp":  time.Now(),
	})
}

func (h *Handlers) GetTrafficStats(w http.ResponseWriter, r *http.Request) {
	// Traffic stats from interfaces
	interfaces, _ := h.network.GetInterfaces(r.Context())
	stats := make(map[string]interface{})
	for _, iface := range interfaces {
		stats[iface.Name] = map[string]interface{}{
			"rx_bytes": 0,
			"tx_bytes": 0,
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"stats":     stats,
		"timestamp": time.Now(),
	})
}

func (h *Handlers) GetTrafficHistory(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "interface")
	minutes, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if minutes == 0 {
		minutes = 60
	}

	// Traffic history not implemented - return empty
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interface": iface,
		"minutes":   minutes,
		"history":   []interface{}{},
		"count":     0,
	})
}

// =============================================================================
// Clients (WiFi)
// =============================================================================

func (h *Handlers) GetClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.network.GetConnectedClients()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// GetConnectedClients returns []interface{}, wrap manually
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_count": len(clients),
		"clients":     clients,
		"timestamp":   time.Now(),
	})
}

func (h *Handlers) GetClientCount(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.network.GetConnectedClients()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":     len(clients),
		"timestamp": time.Now(),
	})
}

func (h *Handlers) GetClientStats(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.network.GetConnectedClients()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_clients": len(clients),
		"timestamp":     time.Now(),
	})
}

func (h *Handlers) BlockClient(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	// Client blocking not implemented via HAL yet
	writeError(w, http.StatusNotImplemented, "Client blocking not yet implemented for MAC: "+mac)
}

func (h *Handlers) UnblockClient(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	// Client unblocking not implemented via HAL yet
	writeError(w, http.StatusNotImplemented, "Client unblocking not yet implemented for MAC: "+mac)
}

func (h *Handlers) KickClient(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	// Client kicking not implemented via HAL yet
	writeError(w, http.StatusNotImplemented, "Client kicking not yet implemented for MAC: "+mac)
}

func (h *Handlers) GetBlockedClients(w http.ResponseWriter, r *http.Request) {
	// Return empty list - blocking not implemented
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"blocked_macs": []string{},
		"count":        0,
	})
}

// =============================================================================
// Storage
// =============================================================================

func (h *Handlers) GetDisks(w http.ResponseWriter, r *http.Request) {
	disks := h.system.GetDisks()
	writeJSON(w, http.StatusOK, disks)
}

func (h *Handlers) GetStorageOverview(w http.ResponseWriter, r *http.Request) {
	overview := h.system.GetStorageOverview()
	writeJSON(w, http.StatusOK, overview)
}

func (h *Handlers) GetServiceDataSizes(w http.ResponseWriter, r *http.Request) {
	sizes := h.system.GetServiceDataSizes("/cubeos/apps")

	// Calculate totals
	var totalSize int64
	for _, s := range sizes {
		totalSize += s.Size
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"services":    sizes,
		"count":       len(sizes),
		"total_size":  totalSize,
		"total_human": formatByteSize(totalSize),
	})
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

// =============================================================================
// Docker Services
// =============================================================================

func (h *Handlers) GetServices(w http.ResponseWriter, r *http.Request) {
	resp, err := h.docker.GetServicesResponse(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) GetAllContainerStatus(w http.ResponseWriter, r *http.Request) {
	statusMap, err := h.docker.GetAllContainerStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"containers": statusMap,
		"count":      len(statusMap),
	})
}

func (h *Handlers) GetService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	container, err := h.docker.GetContainer(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Service not found")
		return
	}

	writeJSON(w, http.StatusOK, container)
}

func (h *Handlers) StartService(w http.ResponseWriter, r *http.Request) {
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

func (h *Handlers) StopService(w http.ResponseWriter, r *http.Request) {
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

func (h *Handlers) RestartService(w http.ResponseWriter, r *http.Request) {
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

func (h *Handlers) EnableService(w http.ResponseWriter, r *http.Request) {
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

func (h *Handlers) DisableService(w http.ResponseWriter, r *http.Request) {
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

func (h *Handlers) GetServiceLogs(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	if tail == 0 {
		tail = 100
	}
	since := r.URL.Query().Get("since")

	logs, err := h.docker.GetContainerLogs(r.Context(), name, tail, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"service": name,
		"logs":    logs,
		"tail":    tail,
	})
}

func (h *Handlers) GetServiceStats(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	stats, err := h.docker.GetContainerStats(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// =============================================================================
// Categories
// =============================================================================

func (h *Handlers) GetCategories(w http.ResponseWriter, r *http.Request) {
	categories := make([]map[string]interface{}, 0)

	for id, info := range config.Categories {
		categories = append(categories, map[string]interface{}{
			"id":          id,
			"name":        info.Name,
			"description": info.Description,
			"icon":        info.Icon,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"categories": categories,
	})
}

// =============================================================================
// Docker Management
// =============================================================================

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
