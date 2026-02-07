package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// ExtendedHandlers holds handlers for extended functionality
type ExtendedHandlers struct {
	logs        *managers.LogManager
	firewall    *managers.FirewallManager
	backup      *managers.BackupManager
	processes   *managers.ProcessManager
	wizard      *managers.WizardManager
	monitoring  *managers.MonitoringManager
	preferences *managers.PreferencesManager
	power       *managers.PowerManager
	storage     *managers.StorageManager
	halClient   *hal.Client
}

// NewExtendedHandlers creates extended handlers
func NewExtendedHandlers(
	logs *managers.LogManager,
	firewall *managers.FirewallManager,
	backup *managers.BackupManager,
	processes *managers.ProcessManager,
	wizard *managers.WizardManager,
	monitoring *managers.MonitoringManager,
	preferences *managers.PreferencesManager,
	power *managers.PowerManager,
	storage *managers.StorageManager,
	halClient *hal.Client,
) *ExtendedHandlers {
	return &ExtendedHandlers{
		logs:        logs,
		firewall:    firewall,
		backup:      backup,
		processes:   processes,
		wizard:      wizard,
		monitoring:  monitoring,
		preferences: preferences,
		power:       power,
		storage:     storage,
		halClient:   halClient,
	}
}

// =============================================================================
// Logs
// =============================================================================

// GetJournalLogs godoc
// @Summary Get journal logs
// @Description Returns system journal logs with optional filtering
// @Tags Logs
// @Produce json
// @Security BearerAuth
// @Param unit query string false "Filter by systemd unit"
// @Param lines query int false "Number of lines" default(100)
// @Param since query string false "Since timestamp"
// @Param until query string false "Until timestamp"
// @Param priority query string false "Log priority filter"
// @Param grep query string false "Text filter"
// @Success 200 {object} models.LogsResponse "Journal log entries"
// @Router /logs/journal [get]
func (h *ExtendedHandlers) GetJournalLogs(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines == 0 {
		lines = 100
	}
	since := r.URL.Query().Get("since")
	until := r.URL.Query().Get("until")
	priority := r.URL.Query().Get("priority")
	grep := r.URL.Query().Get("grep")

	entries := h.logs.GetJournalLogs(unit, lines, since, until, priority, grep)

	writeJSON(w, http.StatusOK, models.LogsResponse{
		Entries: entries,
		Count:   len(entries),
	})
}

// GetLogUnits godoc
// @Summary List available log units
// @Description Returns list of available systemd units for log filtering
// @Tags Logs
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.LogUnitsResponse "Available log units"
// @Router /logs/units [get]
func (h *ExtendedHandlers) GetLogUnits(w http.ResponseWriter, r *http.Request) {
	units := h.logs.GetAvailableUnits()

	writeJSON(w, http.StatusOK, models.LogUnitsResponse{
		Units: units,
		Count: len(units),
	})
}

// GetServiceLogs godoc
// @Summary Get service logs
// @Description Returns logs for a specific systemd service
// @Tags Logs
// @Produce json
// @Security BearerAuth
// @Param service path string true "Service name"
// @Param lines query int false "Number of lines" default(100)
// @Param since query string false "Since timestamp"
// @Param priority query string false "Log priority filter"
// @Success 200 {object} map[string]interface{} "Service log entries"
// @Router /logs/service/{service} [get]
func (h *ExtendedHandlers) GetServiceLogs(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines == 0 {
		lines = 100
	}
	since := r.URL.Query().Get("since")
	priority := r.URL.Query().Get("priority")

	// Ensure .service suffix
	if len(service) > 0 && !strings.HasSuffix(service, ".service") {
		service = service + ".service"
	}

	entries := h.logs.GetJournalLogs(service, lines, since, "", priority, "")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"service": service,
		"entries": entries,
		"count":   len(entries),
	})
}

// GetContainerLogs godoc
// @Summary Get container logs
// @Description Returns logs for a specific Docker container
// @Tags Logs
// @Produce json
// @Security BearerAuth
// @Param container path string true "Container name or ID"
// @Param lines query int false "Number of lines" default(100)
// @Param since query string false "Since timestamp"
// @Param timestamps query bool false "Include timestamps" default(true)
// @Success 200 {object} models.ContainerLogsResponse "Container log entries"
// @Router /logs/container/{container} [get]
func (h *ExtendedHandlers) GetContainerLogs(w http.ResponseWriter, r *http.Request) {
	container := chi.URLParam(r, "container")
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines == 0 {
		lines = 100
	}
	since := r.URL.Query().Get("since")
	timestamps := r.URL.Query().Get("timestamps") != "false"

	entries := h.logs.GetContainerLogs(r.Context(), container, lines, since, timestamps)

	writeJSON(w, http.StatusOK, models.ContainerLogsResponse{
		Container: container,
		Entries:   entries,
		Count:     len(entries),
	})
}

// GetKernelLogs godoc
// @Summary Get kernel logs
// @Description Returns kernel (dmesg) log messages
// @Tags Logs
// @Produce json
// @Security BearerAuth
// @Param lines query int false "Number of lines" default(200)
// @Success 200 {object} map[string]interface{} "Kernel log entries"
// @Router /logs/kernel [get]
func (h *ExtendedHandlers) GetKernelLogs(w http.ResponseWriter, r *http.Request) {
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines == 0 {
		lines = 200
	}

	entries := h.logs.GetKernelLogs(lines)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

// GetBootLogs godoc
// @Summary Get boot logs
// @Description Returns logs from a specific boot session
// @Tags Logs
// @Produce json
// @Security BearerAuth
// @Param boot query int false "Boot ID (0=current, -1=previous)" default(0)
// @Param lines query int false "Number of lines" default(500)
// @Success 200 {object} map[string]interface{} "Boot log entries"
// @Router /logs/boot [get]
func (h *ExtendedHandlers) GetBootLogs(w http.ResponseWriter, r *http.Request) {
	boot, _ := strconv.Atoi(r.URL.Query().Get("boot"))
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines == 0 {
		lines = 500
	}

	entries := h.logs.GetBootLogs(boot, lines)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"boot_id": boot,
		"entries": entries,
		"count":   len(entries),
	})
}

// ReadLogFile godoc
// @Summary Read log file
// @Description Reads content from a specific log file (restricted paths)
// @Tags Logs
// @Produce json
// @Security BearerAuth
// @Param path query string true "Log file path"
// @Param lines query int false "Number of lines" default(100)
// @Param grep query string false "Text filter"
// @Success 200 {object} map[string]interface{} "Log file content"
// @Failure 400 {object} ErrorResponse "Path parameter required"
// @Failure 403 {object} ErrorResponse "Access denied"
// @Router /logs/file [get]
func (h *ExtendedHandlers) ReadLogFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeError(w, http.StatusBadRequest, "path parameter required")
		return
	}

	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines == 0 {
		lines = 100
	}
	grep := r.URL.Query().Get("grep")

	entries, err := h.logs.ReadLogFile(path, lines, grep)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"path":    path,
		"entries": entries,
		"count":   len(entries),
	})
}

// GetRecentErrors godoc
// @Summary Get recent errors
// @Description Returns recent error log entries across all services
// @Tags Logs
// @Produce json
// @Security BearerAuth
// @Param lines query int false "Number of lines" default(50)
// @Param hours query int false "Hours to look back" default(24)
// @Success 200 {object} map[string]interface{} "Recent error entries"
// @Router /logs/errors [get]
func (h *ExtendedHandlers) GetRecentErrors(w http.ResponseWriter, r *http.Request) {
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines == 0 {
		lines = 50
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours == 0 {
		hours = 24
	}

	entries := h.logs.GetRecentErrors(lines, hours)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
		"hours":   hours,
	})
}

// =============================================================================
// Firewall
// =============================================================================

// GetFirewallStatus godoc
// @Summary Get firewall status
// @Description Returns current firewall (iptables) status
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Firewall status"
// @Failure 500 {object} ErrorResponse "Failed to get status"
// REMOVED: @Router /firewall/status [get]
func (h *ExtendedHandlers) GetFirewallStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.firewall.GetStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// GetFirewallRules godoc
// @Summary Get firewall rules
// @Description Returns firewall rules for a specific table
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param table query string false "Table name (filter, nat, mangle, raw)" default(filter)
// @Param all query bool false "Show all rules including Docker auto-generated"
// @Success 200 {object} map[string]interface{} "Firewall rules"
// @Failure 400 {object} ErrorResponse "Invalid table name"
// @Failure 500 {object} ErrorResponse "Failed to get rules"
// REMOVED: @Router /firewall/rules [get]
func (h *ExtendedHandlers) GetFirewallRules(w http.ResponseWriter, r *http.Request) {
	table := r.URL.Query().Get("table")
	if table == "" {
		table = "filter"
	}

	if table != "filter" && table != "nat" && table != "mangle" && table != "raw" {
		writeError(w, http.StatusBadRequest, "Invalid table name")
		return
	}

	// Check if user wants all rules including Docker auto-generated
	showAll := r.URL.Query().Get("all") == "true"
	_ = showAll // Unused for now - GetUserRules not available

	rules, err := h.firewall.GetRules(r.Context(), table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"table":    table,
		"rules":    rules,
		"count":    len(rules),
		"filtered": false, // All rules returned, filtering not available
	})
}

// GetNATStatus godoc
// @Summary Get NAT status
// @Description Returns NAT/masquerading status
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "NAT status"
// REMOVED: @Router /firewall/nat/status [get]
func (h *ExtendedHandlers) GetNATStatus(w http.ResponseWriter, r *http.Request) {
	status, _ := h.firewall.GetNATStatus(r.Context())
	writeJSON(w, http.StatusOK, status)
}

// EnableNAT godoc
// @Summary Enable NAT
// @Description Enables NAT/masquerading for internet sharing
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse "NAT enabled"
// @Failure 500 {object} ErrorResponse "Failed to enable NAT"
// REMOVED: @Router /firewall/nat/enable [post]
func (h *ExtendedHandlers) EnableNAT(w http.ResponseWriter, r *http.Request) {
	result := h.firewall.EnableNAT(r.Context())
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// DisableNAT godoc
// @Summary Disable NAT
// @Description Disables NAT/masquerading
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse "NAT disabled"
// @Failure 500 {object} ErrorResponse "Failed to disable NAT"
// REMOVED: @Router /firewall/nat/disable [post]
func (h *ExtendedHandlers) DisableNAT(w http.ResponseWriter, r *http.Request) {
	result := h.firewall.DisableNAT(r.Context())
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// AllowPort godoc
// @Summary Allow port
// @Description Adds firewall rule to allow traffic on a port
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param port query int true "Port number (1-65535)"
// @Param protocol query string false "Protocol (tcp/udp)" default(tcp)
// @Param comment query string false "Rule comment"
// @Success 200 {object} models.SuccessResponse "Port allowed"
// @Failure 400 {object} ErrorResponse "Invalid port"
// @Failure 500 {object} ErrorResponse "Failed to add rule"
// REMOVED: @Router /firewall/port/allow [post]
func (h *ExtendedHandlers) AllowPort(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		writeError(w, http.StatusBadRequest, "Invalid port")
		return
	}

	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "tcp"
	}
	comment := r.URL.Query().Get("comment")

	result := h.firewall.AllowPort(r.Context(), port, protocol, comment)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// BlockPort godoc
// @Summary Block port
// @Description Adds firewall rule to block traffic on a port
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param port query int true "Port number (1-65535)"
// @Param protocol query string false "Protocol (tcp/udp)" default(tcp)
// @Success 200 {object} models.SuccessResponse "Port blocked"
// @Failure 400 {object} ErrorResponse "Invalid port"
// @Failure 500 {object} ErrorResponse "Failed to add rule"
// REMOVED: @Router /firewall/port/block [post]
func (h *ExtendedHandlers) BlockPort(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		writeError(w, http.StatusBadRequest, "Invalid port")
		return
	}

	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "tcp"
	}

	result := h.firewall.BlockPort(r.Context(), port, protocol)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// RemovePortRule godoc
// @Summary Remove port rule
// @Description Removes a firewall rule for a port
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param port path int true "Port number"
// @Param protocol query string false "Protocol (tcp/udp)" default(tcp)
// @Param action query string false "Rule action (ACCEPT/DROP)" default(ACCEPT)
// @Success 200 {object} models.SuccessResponse "Rule removed"
// @Failure 400 {object} ErrorResponse "Invalid port"
// @Failure 500 {object} ErrorResponse "Failed to remove rule"
// REMOVED: @Router /firewall/port/{port} [delete]
func (h *ExtendedHandlers) RemovePortRule(w http.ResponseWriter, r *http.Request) {
	portStr := chi.URLParam(r, "port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid port")
		return
	}

	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "tcp"
	}
	action := r.URL.Query().Get("action")
	if action == "" {
		action = "ACCEPT"
	}

	result := h.firewall.RemovePortRule(r.Context(), port, protocol, action)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// AllowService godoc
// @Summary Allow service
// @Description Adds firewall rule to allow a known service (http, https, ssh, etc.)
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param service path string true "Service name"
// @Success 200 {object} models.SuccessResponse "Service allowed"
// @Failure 400 {object} ErrorResponse "Unknown service"
// REMOVED: @Router /firewall/service/{service}/allow [post]
func (h *ExtendedHandlers) AllowService(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")
	result := h.firewall.AllowService(r.Context(), service)
	if result.Status == "error" {
		writeError(w, http.StatusBadRequest, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// SaveFirewallRules godoc
// @Summary Save firewall rules
// @Description Persists current firewall rules to survive reboot
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse "Rules saved"
// REMOVED: @Router /firewall/save [post]
func (h *ExtendedHandlers) SaveFirewallRules(w http.ResponseWriter, r *http.Request) {
	result := h.firewall.SaveRules(r.Context())
	writeJSON(w, http.StatusOK, result)
}

// RestoreFirewallRules godoc
// @Summary Restore firewall rules
// @Description Restores firewall rules from saved configuration
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse "Rules restored"
// REMOVED: @Router /firewall/restore [post]
func (h *ExtendedHandlers) RestoreFirewallRules(w http.ResponseWriter, r *http.Request) {
	result := h.firewall.RestoreRules(r.Context())
	writeJSON(w, http.StatusOK, result)
}

// GetIPForward godoc
// @Summary Get IP forwarding status
// @Description Returns IPv4 forwarding status
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "IP forward status"
// REMOVED: @Router /firewall/ipforward [get]
func (h *ExtendedHandlers) GetIPForward(w http.ResponseWriter, r *http.Request) {
	status, _ := h.firewall.GetNATStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ip_forward_enabled": status["ip_forward"],
	})
}

// SetIPForward godoc
// @Summary Set IP forwarding
// @Description Enables or disables IPv4 forwarding
// @Tags Firewall
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "Enable state" example({"enabled": true})
// @Success 200 {object} models.SuccessResponse "IP forward updated"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// REMOVED: @Router /firewall/ipforward [put]
func (h *ExtendedHandlers) SetIPForward(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	result := h.firewall.SetIPForward(r.Context(), req.Enabled)
	writeJSON(w, http.StatusOK, result)
}

// ResetFirewall godoc
// @Summary Reset firewall
// @Description Resets firewall to default state (requires confirmation)
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param confirm query bool true "Confirmation flag" example(true)
// @Success 200 {object} models.SuccessResponse "Firewall reset"
// @Failure 400 {object} ErrorResponse "Confirmation required"
// REMOVED: @Router /firewall/reset [post]
func (h *ExtendedHandlers) ResetFirewall(w http.ResponseWriter, r *http.Request) {
	confirm := r.URL.Query().Get("confirm") == "true"
	if !confirm {
		writeError(w, http.StatusBadRequest, "Set confirm=true to reset")
		return
	}

	result := h.firewall.ResetFirewall(r.Context())
	writeJSON(w, http.StatusOK, result)
}

// =============================================================================
// Backup
// =============================================================================

// ListBackups godoc
// @Summary List backups
// @Description Returns list of all available backups
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.BackupListResponse "Backup list"
// REMOVED: @Router /backups [get]
func (h *ExtendedHandlers) ListBackups(w http.ResponseWriter, r *http.Request) {
	backups := h.backup.ListBackups()
	totalSize := h.backup.GetTotalSize()

	writeJSON(w, http.StatusOK, models.BackupListResponse{
		Backups:        backups,
		TotalCount:     len(backups),
		TotalSizeBytes: totalSize,
	})
}

// GetBackup godoc
// @Summary Get backup details
// @Description Returns details of a specific backup
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Success 200 {object} models.BackupInfo "Backup details"
// @Failure 404 {object} ErrorResponse "Backup not found"
// REMOVED: @Router /backups/{backup_id} [get]
func (h *ExtendedHandlers) GetBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	backup := h.backup.GetBackup(backupID)
	if backup == nil {
		writeError(w, http.StatusNotFound, "Backup not found")
		return
	}
	writeJSON(w, http.StatusOK, backup)
}

// CreateBackup godoc
// @Summary Create backup
// @Description Creates a new system backup
// @Tags Backup
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.BackupCreateRequest false "Backup options"
// @Success 200 {object} models.BackupInfo "Created backup"
// @Failure 500 {object} ErrorResponse "Failed to create backup"
// REMOVED: @Router /backups [post]
func (h *ExtendedHandlers) CreateBackup(w http.ResponseWriter, r *http.Request) {
	var req models.BackupCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Use defaults
		req.Type = "config"
		req.Compress = true
	}

	if req.Type == "" {
		req.Type = "config"
	}

	result, err := h.backup.CreateBackup(req.Type, req.Description, req.IncludeDockerVolumes, req.Compress)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// QuickBackup godoc
// @Summary Quick backup
// @Description Creates a quick backup with defaults
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_type query string false "Backup type" default(config)
// @Param description query string false "Backup description"
// @Success 200 {object} models.BackupInfo "Created backup"
// @Failure 500 {object} ErrorResponse "Failed to create backup"
// REMOVED: @Router /backups/quick [post]
func (h *ExtendedHandlers) QuickBackup(w http.ResponseWriter, r *http.Request) {
	backupType := r.URL.Query().Get("backup_type")
	if backupType == "" {
		backupType = "config"
	}
	description := r.URL.Query().Get("description")
	if description == "" {
		description = "Quick " + backupType + " backup"
	}

	result, err := h.backup.CreateBackup(backupType, description, false, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// RestoreBackup godoc
// @Summary Restore backup
// @Description Restores system from a backup (requires confirmation)
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Param confirm query bool true "Confirmation flag" example(true)
// @Param restart_services query bool false "Restart services after restore" default(true)
// @Success 200 {object} models.SuccessResponse "Backup restored"
// @Failure 400 {object} ErrorResponse "Confirmation required"
// @Failure 500 {object} ErrorResponse "Failed to restore backup"
// REMOVED: @Router /backups/{backup_id}/restore [post]
func (h *ExtendedHandlers) RestoreBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	confirm := r.URL.Query().Get("confirm") == "true"

	if !confirm {
		writeError(w, http.StatusBadRequest, "Set confirm=true to restore")
		return
	}

	restartServices := r.URL.Query().Get("restart_services") != "false"

	result, err := h.backup.RestoreBackup(backupID, restartServices)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// DeleteBackup godoc
// @Summary Delete backup
// @Description Deletes a specific backup
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Success 200 {object} models.SuccessResponse "Backup deleted"
// @Failure 404 {object} ErrorResponse "Backup not found"
// REMOVED: @Router /backups/{backup_id} [delete]
func (h *ExtendedHandlers) DeleteBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	result := h.backup.DeleteBackup(backupID)
	if result.Status == "error" {
		writeError(w, http.StatusNotFound, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// DownloadBackup godoc
// @Summary Download backup
// @Description Downloads a backup file
// @Tags Backup
// @Produce application/gzip
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Success 200 {file} binary "Backup file"
// @Failure 404 {object} ErrorResponse "Backup not found"
// REMOVED: @Router /backups/{backup_id}/download [get]
func (h *ExtendedHandlers) DownloadBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	backup := h.backup.GetBackup(backupID)
	if backup == nil {
		writeError(w, http.StatusNotFound, "Backup not found")
		return
	}

	filepath := h.backup.GetBackupFilePath(backupID)
	if filepath == "" {
		writeError(w, http.StatusNotFound, "Backup file not found")
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+backup.Filename)
	w.Header().Set("Content-Type", "application/gzip")
	http.ServeFile(w, r, filepath)
}

// GetBackupStats godoc
// @Summary Get backup statistics
// @Description Returns backup storage statistics
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Backup statistics"
// REMOVED: @Router /backups/stats [get]
func (h *ExtendedHandlers) GetBackupStats(w http.ResponseWriter, r *http.Request) {
	stats := h.backup.GetStats()
	writeJSON(w, http.StatusOK, stats)
}

// =============================================================================
// Processes
// =============================================================================

// ListProcesses godoc
// @Summary List processes
// @Description Returns list of running processes
// @Tags Processes
// @Produce json
// @Security BearerAuth
// @Param sort_by query string false "Sort field (cpu, memory, pid)" default(cpu)
// @Param limit query int false "Maximum processes to return" default(50)
// @Param filter_name query string false "Filter by process name"
// @Success 200 {object} models.ProcessListResponse "Process list"
// @Router /processes [get]
func (h *ExtendedHandlers) ListProcesses(w http.ResponseWriter, r *http.Request) {
	sortBy := r.URL.Query().Get("sort_by")
	if sortBy == "" {
		sortBy = "cpu"
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 50
	}

	filterName := r.URL.Query().Get("filter_name")

	processes := h.processes.ListProcesses(sortBy, limit, filterName)

	writeJSON(w, http.StatusOK, models.ProcessListResponse{
		Processes:  processes,
		TotalCount: len(processes),
		SortBy:     sortBy,
	})
}

// GetProcess godoc
// @Summary Get process details
// @Description Returns details of a specific process by PID
// @Tags Processes
// @Produce json
// @Security BearerAuth
// @Param pid path int true "Process ID"
// @Success 200 {object} models.ProcessInfo "Process details"
// @Failure 400 {object} ErrorResponse "Invalid PID"
// @Failure 404 {object} ErrorResponse "Process not found"
// @Router /processes/{pid} [get]
func (h *ExtendedHandlers) GetProcess(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid PID")
		return
	}

	proc := h.processes.GetProcess(pid)
	if proc == nil {
		writeError(w, http.StatusNotFound, "Process not found")
		return
	}

	writeJSON(w, http.StatusOK, proc)
}

// KillProcess godoc
// @Summary Kill process
// @Description Sends a signal to terminate a process
// @Tags Processes
// @Produce json
// @Security BearerAuth
// @Param pid path int true "Process ID"
// @Param sig query string false "Signal to send" default(SIGTERM)
// @Success 200 {object} models.SuccessResponse "Process killed"
// @Failure 400 {object} ErrorResponse "Invalid PID"
// @Failure 403 {object} ErrorResponse "Cannot kill protected process"
// @Router /processes/{pid}/kill [post]
func (h *ExtendedHandlers) KillProcess(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid PID")
		return
	}

	signal := r.URL.Query().Get("sig")
	if signal == "" {
		signal = "SIGTERM"
	}

	result := h.processes.KillProcess(pid, signal)
	if result.Status == "error" {
		writeError(w, http.StatusForbidden, result.Message)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// TerminateProcess godoc
// @Summary Terminate process
// @Description Sends SIGTERM to gracefully terminate a process
// @Tags Processes
// @Produce json
// @Security BearerAuth
// @Param pid path int true "Process ID"
// @Success 200 {object} models.SuccessResponse "Process terminated"
// @Failure 400 {object} ErrorResponse "Invalid PID"
// @Failure 403 {object} ErrorResponse "Cannot terminate protected process"
// @Router /processes/{pid}/terminate [post]
func (h *ExtendedHandlers) TerminateProcess(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid PID")
		return
	}

	result := h.processes.KillProcess(pid, "SIGTERM")
	if result.Status == "error" {
		writeError(w, http.StatusForbidden, result.Message)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetProcessStats godoc
// @Summary Get process statistics
// @Description Returns overall process statistics
// @Tags Processes
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Process statistics"
// @Router /processes/stats/summary [get]
func (h *ExtendedHandlers) GetProcessStats(w http.ResponseWriter, r *http.Request) {
	stats := h.processes.GetProcessStats()
	writeJSON(w, http.StatusOK, stats)
}

// TopCPUProcesses godoc
// @Summary Top CPU processes
// @Description Returns processes with highest CPU usage
// @Tags Processes
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Number of processes" default(10)
// @Success 200 {object} models.ProcessListResponse "Top CPU processes"
// @Router /processes/top/cpu [get]
func (h *ExtendedHandlers) TopCPUProcesses(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 10
	}

	processes := h.processes.TopCPU(limit)
	writeJSON(w, http.StatusOK, models.ProcessListResponse{
		Processes:  processes,
		TotalCount: len(processes),
		SortBy:     "cpu",
	})
}

// TopMemoryProcesses godoc
// @Summary Top memory processes
// @Description Returns processes with highest memory usage
// @Tags Processes
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Number of processes" default(10)
// @Success 200 {object} models.ProcessListResponse "Top memory processes"
// @Router /processes/top/memory [get]
func (h *ExtendedHandlers) TopMemoryProcesses(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 10
	}

	processes := h.processes.TopMemory(limit)
	writeJSON(w, http.StatusOK, models.ProcessListResponse{
		Processes:  processes,
		TotalCount: len(processes),
		SortBy:     "memory",
	})
}

// SearchProcesses godoc
// @Summary Search processes
// @Description Searches for processes by name
// @Tags Processes
// @Produce json
// @Security BearerAuth
// @Param name path string true "Process name to search"
// @Param exact query bool false "Exact match only"
// @Success 200 {object} map[string]interface{} "Matching processes"
// @Router /processes/search/{name} [get]
func (h *ExtendedHandlers) SearchProcesses(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	exact := r.URL.Query().Get("exact") == "true"

	processes := h.processes.SearchProcesses(name, exact)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"query":     name,
		"exact":     exact,
		"processes": processes,
		"count":     len(processes),
	})
}

// =============================================================================
// Wizard
// =============================================================================

// GetProfiles godoc
// @Summary List wizard profiles
// @Description Returns available setup profiles
// @Tags Wizard
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Available profiles"
// @Router /wizard/profiles [get]
func (h *ExtendedHandlers) GetProfiles(w http.ResponseWriter, r *http.Request) {
	profiles := h.wizard.GetProfiles()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profiles": profiles,
	})
}

// GetWizardServices godoc
// @Summary List wizard services
// @Description Returns services available for wizard configuration
// @Tags Wizard
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Available services"
// @Router /wizard/services [get]
func (h *ExtendedHandlers) GetWizardServices(w http.ResponseWriter, r *http.Request) {
	response := h.wizard.GetWizardServices()
	writeJSON(w, http.StatusOK, response)
}

// ApplyProfile godoc
// @Summary Apply wizard profile
// @Description Applies a setup profile to configure services
// @Tags Wizard
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.ApplyProfileRequest true "Profile configuration"
// @Success 200 {object} models.ApplyProfileResponse "Profile applied"
// @Failure 400 {object} ErrorResponse "Invalid request or profile"
// @Router /wizard/apply [post]
func (h *ExtendedHandlers) ApplyProfile(w http.ResponseWriter, r *http.Request) {
	var req models.ApplyProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.ProfileID == "" {
		writeError(w, http.StatusBadRequest, "profile_id required")
		return
	}

	response := h.wizard.ApplyProfile(req.ProfileID, req.AdditionalServices, req.ExcludedServices)
	if !response.Success {
		writeError(w, http.StatusBadRequest, response.Message)
		return
	}

	writeJSON(w, http.StatusOK, response)
}

// GetRecommendations godoc
// @Summary Get service recommendations
// @Description Returns service recommendations based on available resources
// @Tags Wizard
// @Produce json
// @Security BearerAuth
// @Param available_ram_mb query int false "Available RAM in MB" default(4096)
// @Success 200 {object} map[string]interface{} "Recommendations"
// @Router /wizard/recommendations [get]
func (h *ExtendedHandlers) GetRecommendations(w http.ResponseWriter, r *http.Request) {
	ramStr := r.URL.Query().Get("available_ram_mb")
	ram, _ := strconv.Atoi(ramStr)
	if ram == 0 {
		ram = 4096
	}

	recommendations := h.wizard.GetRecommendations(ram)
	writeJSON(w, http.StatusOK, recommendations)
}

// EstimateResources godoc
// @Summary Estimate resource usage
// @Description Estimates resource requirements for selected services
// @Tags Wizard
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "Service list" example({"services": ["pihole", "nginx"]})
// @Success 200 {object} map[string]interface{} "Resource estimate"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Router /wizard/estimate [post]
func (h *ExtendedHandlers) EstimateResources(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Services []string `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	estimate := h.wizard.EstimateResources(req.Services)
	writeJSON(w, http.StatusOK, estimate)
}

// =============================================================================
// Monitoring
// =============================================================================

// GetMonitoringStats godoc
// @Summary Get monitoring statistics
// @Description Returns current system monitoring statistics
// @Tags Monitoring
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Monitoring statistics"
// @Router /monitoring/stats [get]
func (h *ExtendedHandlers) GetMonitoringStats(w http.ResponseWriter, r *http.Request) {
	stats := h.monitoring.GetCurrentStats()
	writeJSON(w, http.StatusOK, stats)
}

// GetWSConnections godoc
// @Summary Get WebSocket connections
// @Description Returns count of active WebSocket connections
// @Tags Monitoring
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "WebSocket connections"
// @Router /monitoring/websocket [get]
func (h *ExtendedHandlers) GetWSConnections(w http.ResponseWriter, r *http.Request) {
	// This would need access to WebSocket manager
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_connections": 0,
	})
}

// GetStatsHistory godoc
// @Summary Get statistics history
// @Description Returns historical monitoring statistics
// @Tags Monitoring
// @Produce json
// @Security BearerAuth
// @Param minutes query int false "Minutes of history (max 60)" default(60)
// @Success 200 {object} models.StatsHistoryResponse "Statistics history"
// @Router /monitoring/history [get]
func (h *ExtendedHandlers) GetStatsHistory(w http.ResponseWriter, r *http.Request) {
	minutes, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if minutes == 0 || minutes > 60 {
		minutes = 60
	}

	history := h.monitoring.GetHistory(minutes)

	writeJSON(w, http.StatusOK, models.StatsHistoryResponse{
		History: history,
		Count:   len(history),
	})
}

// GetAlertThresholds godoc
// @Summary Get alert thresholds
// @Description Returns current monitoring alert thresholds
// @Tags Monitoring
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]float64 "Alert thresholds"
// @Router /monitoring/thresholds [get]
func (h *ExtendedHandlers) GetAlertThresholds(w http.ResponseWriter, r *http.Request) {
	thresholds := h.monitoring.GetThresholds()
	writeJSON(w, http.StatusOK, thresholds)
}

// SetAlertThresholds godoc
// @Summary Set alert thresholds
// @Description Updates monitoring alert thresholds
// @Tags Monitoring
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param thresholds body map[string]float64 true "Threshold values"
// @Success 200 {object} map[string]float64 "Updated thresholds"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Router /monitoring/thresholds [put]
func (h *ExtendedHandlers) SetAlertThresholds(w http.ResponseWriter, r *http.Request) {
	var thresholds map[string]float64
	if err := json.NewDecoder(r.Body).Decode(&thresholds); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	updated := h.monitoring.SetThresholds(thresholds)
	writeJSON(w, http.StatusOK, updated)
}

// GetCurrentAlerts godoc
// @Summary Get current alerts
// @Description Returns currently active monitoring alerts
// @Tags Monitoring
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Active alerts"
// @Router /monitoring/alerts [get]
func (h *ExtendedHandlers) GetCurrentAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := h.monitoring.GetCurrentAlerts()
	writeJSON(w, http.StatusOK, alerts)
}

// =============================================================================
// Preferences
// =============================================================================

// GetPreferences godoc
// @Summary Get user preferences
// @Description Returns current user preferences
// @Tags Preferences
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.Preferences "User preferences"
// @Router /preferences [get]
func (h *ExtendedHandlers) GetPreferences(w http.ResponseWriter, r *http.Request) {
	prefs := h.preferences.Get()
	writeJSON(w, http.StatusOK, prefs)
}

// SetPreferences godoc
// @Summary Update user preferences
// @Description Updates user preferences
// @Tags Preferences
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param preferences body models.PreferencesUpdate true "Preference updates"
// @Success 200 {object} map[string]interface{} "Updated preferences"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to save preferences"
// @Router /preferences [post]
func (h *ExtendedHandlers) SetPreferences(w http.ResponseWriter, r *http.Request) {
	var update models.PreferencesUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	prefs, err := h.preferences.Update(update)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save preferences")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"preferences": prefs,
	})
}

// ResetPreferences godoc
// @Summary Reset preferences
// @Description Resets user preferences to defaults
// @Tags Preferences
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Reset preferences"
// @Router /preferences/reset [post]
func (h *ExtendedHandlers) ResetPreferences(w http.ResponseWriter, r *http.Request) {
	prefs := h.preferences.Reset()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"preferences": prefs,
	})
}

// =============================================================================
// Favorites
// =============================================================================

// GetFavorites godoc
// @Summary Get favorites
// @Description Returns list of favorite services
// @Tags Favorites
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Favorite services"
// @Router /favorites [get]
func (h *ExtendedHandlers) GetFavorites(w http.ResponseWriter, r *http.Request) {
	prefs := h.preferences.Get()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"favorites": prefs.Favorites,
	})
}

// AddFavorite godoc
// @Summary Add favorite
// @Description Adds a service to favorites
// @Tags Favorites
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} map[string]interface{} "Updated favorites"
// @Failure 400 {object} ErrorResponse "Service name required"
// @Router /favorites/{name} [post]
func (h *ExtendedHandlers) AddFavorite(w http.ResponseWriter, r *http.Request) {
	serviceName := chi.URLParam(r, "name")
	if serviceName == "" {
		writeError(w, http.StatusBadRequest, "Service name required")
		return
	}

	prefs := h.preferences.AddFavorite(serviceName)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"favorites": prefs.Favorites,
	})
}

// RemoveFavorite godoc
// @Summary Remove favorite
// @Description Removes a service from favorites
// @Tags Favorites
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} map[string]interface{} "Updated favorites"
// @Failure 400 {object} ErrorResponse "Service name required"
// @Router /favorites/{name} [delete]
func (h *ExtendedHandlers) RemoveFavorite(w http.ResponseWriter, r *http.Request) {
	serviceName := chi.URLParam(r, "name")
	if serviceName == "" {
		writeError(w, http.StatusBadRequest, "Service name required")
		return
	}

	prefs := h.preferences.RemoveFavorite(serviceName)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"favorites": prefs.Favorites,
	})
}

// ToggleFavorite godoc
// @Summary Toggle favorite
// @Description Toggles a service's favorite status
// @Tags Favorites
// @Produce json
// @Security BearerAuth
// @Param name path string true "Service name"
// @Success 200 {object} map[string]interface{} "Updated favorites with new status"
// @Failure 400 {object} ErrorResponse "Service name required"
// @Router /favorites/{name}/toggle [post]
func (h *ExtendedHandlers) ToggleFavorite(w http.ResponseWriter, r *http.Request) {
	serviceName := chi.URLParam(r, "name")
	if serviceName == "" {
		writeError(w, http.StatusBadRequest, "Service name required")
		return
	}

	prefs := h.preferences.Get()

	// Check if already in favorites
	isFavorite := false
	for _, f := range prefs.Favorites {
		if f == serviceName {
			isFavorite = true
			break
		}
	}

	if isFavorite {
		prefs = h.preferences.RemoveFavorite(serviceName)
	} else {
		prefs = h.preferences.AddFavorite(serviceName)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"is_favorite": !isFavorite,
		"favorites":   prefs.Favorites,
	})
}

// =============================================================================
// Power/UPS (Geekworm X1202)
// =============================================================================

// GetPowerStatus godoc
// @Summary Get power/UPS status
// @Description Returns UPS battery and power status (Geekworm X1202)
// @Tags Power
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Power/UPS status"
// @Router /power/status [get]
func (h *ExtendedHandlers) GetPowerStatus(w http.ResponseWriter, r *http.Request) {
	if h.power == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"message":   "Power manager not initialized",
		})
		return
	}

	status := h.power.GetStatus()

	// Convert to API response format
	response := map[string]interface{}{
		"available":       status.Available,
		"battery_percent": status.BatteryPercent,
		"battery_voltage": status.BatteryVoltage,
		"is_charging":     status.IsCharging,
		"on_battery":      status.OnBattery,
		"power_good":      status.PowerGood,
		"cell_count":      status.CellCount,
		"estimated_mins":  status.EstimatedMins,
		"last_updated":    status.LastUpdated,
	}

	if status.Error != "" {
		response["error"] = status.Error
	}

	// Add human-readable status
	if !status.Available {
		response["status"] = "unavailable"
	} else if status.IsCharging {
		response["status"] = "charging"
	} else if status.OnBattery {
		if status.BatteryPercent < 10 {
			response["status"] = "critical"
		} else if status.BatteryPercent < 20 {
			response["status"] = "low"
		} else {
			response["status"] = "discharging"
		}
	} else if status.BatteryPercent >= 95 {
		response["status"] = "full"
	} else {
		response["status"] = "plugged_in"
	}

	// Add time remaining estimate
	if status.EstimatedMins > 0 {
		hours := status.EstimatedMins / 60
		mins := status.EstimatedMins % 60
		if hours > 0 {
			response["time_remaining"] = fmt.Sprintf("%dh %dm", hours, mins)
		} else {
			response["time_remaining"] = fmt.Sprintf("%dm", mins)
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// SetCharging godoc
// @Summary Set charging state
// @Description Enables or disables battery charging
// @Tags Power
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "Charging state" example({"enable": true})
// @Success 200 {object} map[string]interface{} "Charging state updated"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to set charging"
// @Failure 503 {object} ErrorResponse "Power manager not available"
// @Router /power/charging [put]
func (h *ExtendedHandlers) SetCharging(w http.ResponseWriter, r *http.Request) {
	if h.power == nil {
		writeError(w, http.StatusServiceUnavailable, "Power manager not available")
		return
	}

	var req struct {
		Enable bool `json:"enable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.power.SetCharging(req.Enable); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"charging": req.Enable,
	})
}

// =============================================================================
// SMB Share Handlers
// =============================================================================

// GetSMBStatus godoc
// @Summary Get SMB status
// @Description Returns SMB/Samba server status
// @Tags SMB
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "SMB server status"
// REMOVED: @Router /smb/status [get]
func (h *ExtendedHandlers) GetSMBStatus(w http.ResponseWriter, r *http.Request) {
	status := h.storage.GetSMBStatus()
	writeJSON(w, http.StatusOK, status)
}

// GetSMBShares godoc
// @Summary List SMB shares
// @Description Returns list of configured SMB shares
// @Tags SMB
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "SMB shares"
// @Failure 500 {object} ErrorResponse "Failed to get shares"
// REMOVED: @Router /smb/shares [get]
func (h *ExtendedHandlers) GetSMBShares(w http.ResponseWriter, r *http.Request) {
	shares, err := h.storage.GetSMBShares()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"shares": shares,
		"count":  len(shares),
	})
}

// GetSMBShare godoc
// @Summary Get SMB share
// @Description Returns details of a specific SMB share
// @Tags SMB
// @Produce json
// @Security BearerAuth
// @Param name path string true "Share name"
// @Success 200 {object} managers.SMBShare "SMB share details"
// @Failure 404 {object} ErrorResponse "Share not found"
// @Failure 500 {object} ErrorResponse "Failed to get share"
// REMOVED: @Router /smb/shares/{name} [get]
func (h *ExtendedHandlers) GetSMBShare(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	shares, err := h.storage.GetSMBShares()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	for _, share := range shares {
		if share.Name == name {
			writeJSON(w, http.StatusOK, share)
			return
		}
	}

	writeError(w, http.StatusNotFound, "Share not found")
}

// CreateSMBShare godoc
// @Summary Create SMB share
// @Description Creates a new SMB share
// @Tags SMB
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param share body managers.SMBShare true "SMB share configuration"
// @Success 201 {object} map[string]interface{} "Share created"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to create share"
// REMOVED: @Router /smb/shares [post]
func (h *ExtendedHandlers) CreateSMBShare(w http.ResponseWriter, r *http.Request) {
	var share managers.SMBShare
	if err := json.NewDecoder(r.Body).Decode(&share); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.storage.CreateSMBShare(share); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":  "success",
		"message": "Share created successfully",
		"share":   share.Name,
	})
}

// UpdateSMBShare godoc
// @Summary Update SMB share
// @Description Updates an existing SMB share
// @Tags SMB
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param name path string true "Share name"
// @Param share body managers.SMBShare true "SMB share configuration"
// @Success 200 {object} map[string]interface{} "Share updated"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to update share"
// REMOVED: @Router /smb/shares/{name} [put]
func (h *ExtendedHandlers) UpdateSMBShare(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var share managers.SMBShare
	if err := json.NewDecoder(r.Body).Decode(&share); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.storage.UpdateSMBShare(name, share); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Share updated successfully",
	})
}

// DeleteSMBShare godoc
// @Summary Delete SMB share
// @Description Deletes an SMB share
// @Tags SMB
// @Produce json
// @Security BearerAuth
// @Param name path string true "Share name"
// @Success 200 {object} map[string]interface{} "Share deleted"
// @Failure 500 {object} ErrorResponse "Failed to delete share"
// REMOVED: @Router /smb/shares/{name} [delete]
func (h *ExtendedHandlers) DeleteSMBShare(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if err := h.storage.DeleteSMBShare(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Share deleted successfully",
	})
}

// =============================================================================
// Disk Health (S.M.A.R.T.) Handlers
// =============================================================================

// GetDiskHealth godoc
// @Summary Get disk health
// @Description Returns S.M.A.R.T. health status for all disks
// @Tags Storage
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Disk health status"
// @Failure 500 {object} ErrorResponse "Failed to get disk health"
// @Router /storage/health [get]
func (h *ExtendedHandlers) GetDiskHealth(w http.ResponseWriter, r *http.Request) {
	disks, err := h.storage.GetDiskHealth()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Count warnings and calculate overall status
	totalWarnings := 0
	overallHealth := "PASSED"
	for _, disk := range disks {
		totalWarnings += len(disk.Warnings)
		if disk.Health == "FAILED" {
			overallHealth = "FAILED"
		} else if disk.Health == "UNKNOWN" && overallHealth != "FAILED" {
			overallHealth = "UNKNOWN"
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"disks":          disks,
		"count":          len(disks),
		"overall_health": overallHealth,
		"total_warnings": totalWarnings,
	})
}

// GetDiskHealthByDevice godoc
// @Summary Get disk health by device
// @Description Returns S.M.A.R.T. health status for a specific disk
// @Tags Storage
// @Produce json
// @Security BearerAuth
// @Param device path string true "Device name (e.g., sda)"
// @Success 200 {object} managers.DiskHealth "Disk health details"
// @Failure 500 {object} ErrorResponse "Failed to get disk health"
// @Router /storage/health/{device} [get]
func (h *ExtendedHandlers) GetDiskHealthByDevice(w http.ResponseWriter, r *http.Request) {
	device := chi.URLParam(r, "device")

	// Reconstruct device path
	if !strings.HasPrefix(device, "/dev/") {
		device = "/dev/" + device
	}

	// Try HAL first (it has smartctl installed)
	if h.halClient != nil {
		smartInfo, err := h.halClient.GetStorageDeviceSMART(r.Context(), device)
		if err != nil {
			// HAL is available but returned an error - return it directly
			// Don't fall through to local smartctl which won't exist in container
			if strings.Contains(err.Error(), "not found") {
				writeError(w, http.StatusNotFound, "device not found: "+device)
			} else {
				writeError(w, http.StatusInternalServerError, "Failed to get SMART info: "+err.Error())
			}
			return
		}
		// Convert HAL SMARTInfo to DiskHealth format
		health := managers.DiskHealth{
			Device:       smartInfo.Device,
			Health:       smartInfo.Health,
			Temperature:  smartInfo.Temperature,
			PowerOnHours: smartInfo.PowerOnHours,
		}
		if smartInfo.Health == "" {
			health.Health = "UNKNOWN"
		}
		writeJSON(w, http.StatusOK, health)
		return
	}

	// Fall back to local storage manager (only when HAL is unavailable)
	health, err := h.storage.GetDiskHealthByDevice(device)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, health)
}
