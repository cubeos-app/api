package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	
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
	}
}

// =============================================================================
// Logs
// =============================================================================

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

func (h *ExtendedHandlers) GetLogUnits(w http.ResponseWriter, r *http.Request) {
	units := h.logs.GetAvailableUnits()
	
	writeJSON(w, http.StatusOK, models.LogUnitsResponse{
		Units: units,
		Count: len(units),
	})
}

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

func (h *ExtendedHandlers) GetFirewallStatus(w http.ResponseWriter, r *http.Request) {
	status := h.firewall.GetStatus()
	writeJSON(w, http.StatusOK, status)
}

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
	
	var rules []models.FirewallRule
	if showAll {
		rules = h.firewall.GetRules(table)
	} else {
		rules = h.firewall.GetUserRules(table)
	}
	
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"table":    table,
		"rules":    rules,
		"count":    len(rules),
		"filtered": !showAll,
	})
}

func (h *ExtendedHandlers) GetNATStatus(w http.ResponseWriter, r *http.Request) {
	status := h.firewall.GetNATStatus()
	writeJSON(w, http.StatusOK, status)
}

func (h *ExtendedHandlers) EnableNAT(w http.ResponseWriter, r *http.Request) {
	result := h.firewall.EnableNAT()
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *ExtendedHandlers) DisableNAT(w http.ResponseWriter, r *http.Request) {
	result := h.firewall.DisableNAT()
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

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
	
	result := h.firewall.AllowPort(port, protocol, comment)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

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
	
	result := h.firewall.BlockPort(port, protocol)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

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
	
	result := h.firewall.RemovePortRule(port, protocol, action)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *ExtendedHandlers) AllowService(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")
	result := h.firewall.AllowService(service)
	if result.Status == "error" {
		writeError(w, http.StatusBadRequest, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *ExtendedHandlers) SaveFirewallRules(w http.ResponseWriter, r *http.Request) {
	result := h.firewall.SaveRules()
	writeJSON(w, http.StatusOK, result)
}

func (h *ExtendedHandlers) RestoreFirewallRules(w http.ResponseWriter, r *http.Request) {
	result := h.firewall.RestoreRules()
	writeJSON(w, http.StatusOK, result)
}

func (h *ExtendedHandlers) GetIPForward(w http.ResponseWriter, r *http.Request) {
	status := h.firewall.GetNATStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ip_forward_enabled": status["ip_forward"],
	})
}

func (h *ExtendedHandlers) SetIPForward(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	result := h.firewall.SetIPForward(req.Enabled)
	writeJSON(w, http.StatusOK, result)
}

func (h *ExtendedHandlers) ResetFirewall(w http.ResponseWriter, r *http.Request) {
	confirm := r.URL.Query().Get("confirm") == "true"
	if !confirm {
		writeError(w, http.StatusBadRequest, "Set confirm=true to reset")
		return
	}
	
	result := h.firewall.ResetFirewall()
	writeJSON(w, http.StatusOK, result)
}

// =============================================================================
// Backup
// =============================================================================

func (h *ExtendedHandlers) ListBackups(w http.ResponseWriter, r *http.Request) {
	backups := h.backup.ListBackups()
	totalSize := h.backup.GetTotalSize()
	
	writeJSON(w, http.StatusOK, models.BackupListResponse{
		Backups:        backups,
		TotalCount:     len(backups),
		TotalSizeBytes: totalSize,
	})
}

func (h *ExtendedHandlers) GetBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	backup := h.backup.GetBackup(backupID)
	if backup == nil {
		writeError(w, http.StatusNotFound, "Backup not found")
		return
	}
	writeJSON(w, http.StatusOK, backup)
}

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

func (h *ExtendedHandlers) DeleteBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	result := h.backup.DeleteBackup(backupID)
	if result.Status == "error" {
		writeError(w, http.StatusNotFound, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

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

func (h *ExtendedHandlers) GetBackupStats(w http.ResponseWriter, r *http.Request) {
	stats := h.backup.GetStats()
	writeJSON(w, http.StatusOK, stats)
}

// =============================================================================
// Processes
// =============================================================================

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

func (h *ExtendedHandlers) GetProcessStats(w http.ResponseWriter, r *http.Request) {
	stats := h.processes.GetProcessStats()
	writeJSON(w, http.StatusOK, stats)
}

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

func (h *ExtendedHandlers) GetProfiles(w http.ResponseWriter, r *http.Request) {
	profiles := h.wizard.GetProfiles()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profiles": profiles,
	})
}

func (h *ExtendedHandlers) GetWizardServices(w http.ResponseWriter, r *http.Request) {
	response := h.wizard.GetWizardServices()
	writeJSON(w, http.StatusOK, response)
}

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

func (h *ExtendedHandlers) GetRecommendations(w http.ResponseWriter, r *http.Request) {
	ramStr := r.URL.Query().Get("available_ram_mb")
	ram, _ := strconv.Atoi(ramStr)
	if ram == 0 {
		ram = 4096
	}
	
	recommendations := h.wizard.GetRecommendations(ram)
	writeJSON(w, http.StatusOK, recommendations)
}

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

func (h *ExtendedHandlers) GetMonitoringStats(w http.ResponseWriter, r *http.Request) {
	stats := h.monitoring.GetCurrentStats()
	writeJSON(w, http.StatusOK, stats)
}

func (h *ExtendedHandlers) GetWSConnections(w http.ResponseWriter, r *http.Request) {
	// This would need access to WebSocket manager
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_connections": 0,
	})
}

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

func (h *ExtendedHandlers) GetAlertThresholds(w http.ResponseWriter, r *http.Request) {
	thresholds := h.monitoring.GetThresholds()
	writeJSON(w, http.StatusOK, thresholds)
}

func (h *ExtendedHandlers) SetAlertThresholds(w http.ResponseWriter, r *http.Request) {
	var thresholds map[string]float64
	if err := json.NewDecoder(r.Body).Decode(&thresholds); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	updated := h.monitoring.SetThresholds(thresholds)
	writeJSON(w, http.StatusOK, updated)
}

func (h *ExtendedHandlers) GetCurrentAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := h.monitoring.GetCurrentAlerts()
	writeJSON(w, http.StatusOK, alerts)
}

// =============================================================================
// Preferences
// =============================================================================

func (h *ExtendedHandlers) GetPreferences(w http.ResponseWriter, r *http.Request) {
	prefs := h.preferences.Get()
	writeJSON(w, http.StatusOK, prefs)
}

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

// GetFavorites returns the list of favorite services
func (h *ExtendedHandlers) GetFavorites(w http.ResponseWriter, r *http.Request) {
	prefs := h.preferences.Get()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"favorites": prefs.Favorites,
	})
}

// AddFavorite adds a service to favorites
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

// RemoveFavorite removes a service from favorites
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

// ToggleFavorite toggles a service's favorite status
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

func (h *ExtendedHandlers) GetSMBStatus(w http.ResponseWriter, r *http.Request) {
	status := h.storage.GetSMBStatus()
	writeJSON(w, http.StatusOK, status)
}

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

func (h *ExtendedHandlers) GetDiskHealthByDevice(w http.ResponseWriter, r *http.Request) {
	device := chi.URLParam(r, "device")
	
	// Reconstruct device path
	if !strings.HasPrefix(device, "/dev/") {
		device = "/dev/" + device
	}
	
	health, err := h.storage.GetDiskHealthByDevice(device)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	
	writeJSON(w, http.StatusOK, health)
}
