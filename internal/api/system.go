package api

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/nuclearlighters/cubeos/internal/system"
)

// SystemHandler handles system-related API endpoints.
type SystemHandler struct{}

// NewSystemHandler creates a new SystemHandler.
func NewSystemHandler() *SystemHandler {
	return &SystemHandler{}
}

// GetInfo handles GET /api/v1/system/info
// Returns static system information (hostname, OS, CPU, Pi model, etc.)
func (h *SystemHandler) GetInfo(w http.ResponseWriter, r *http.Request) {
	info, err := system.GetInfo()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get system info")
		writeError(w, http.StatusInternalServerError, "Failed to get system info")
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// GetStats handles GET /api/v1/system/stats
// Returns real-time system statistics (CPU%, memory%, disk%, temperature)
func (h *SystemHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := system.GetStats()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get system stats")
		writeError(w, http.StatusInternalServerError, "Failed to get system stats")
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// Reboot handles POST /api/v1/system/reboot
// Triggers a system reboot (requires root/sudo).
func (h *SystemHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	// Parse optional delay from request body
	var req struct {
		Delay   int    `json:"delay"`   // Delay in seconds before reboot
		Message string `json:"message"` // Optional message
	}
	
	// Ignore parse errors - use defaults
	json.NewDecoder(r.Body).Decode(&req)

	log.Warn().Int("delay", req.Delay).Str("message", req.Message).Msg("System reboot requested")

	// Build shutdown command
	args := []string{"shutdown", "-r"}
	if req.Delay > 0 {
		args = append(args, "+"+string(rune(req.Delay)))
	} else {
		args = append(args, "now")
	}
	if req.Message != "" {
		args = append(args, req.Message)
	}

	// Execute reboot command
	cmd := exec.Command("sudo", args...)
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("Failed to initiate reboot")
		writeError(w, http.StatusInternalServerError, "Failed to initiate reboot: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "System reboot initiated",
		"delay":   req.Delay,
	})
}

// Shutdown handles POST /api/v1/system/shutdown
// Triggers a system shutdown (requires root/sudo).
func (h *SystemHandler) Shutdown(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	log.Warn().Int("delay", req.Delay).Str("message", req.Message).Msg("System shutdown requested")

	args := []string{"shutdown", "-h"}
	if req.Delay > 0 {
		args = append(args, "+"+string(rune(req.Delay)))
	} else {
		args = append(args, "now")
	}
	if req.Message != "" {
		args = append(args, req.Message)
	}

	cmd := exec.Command("sudo", args...)
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("Failed to initiate shutdown")
		writeError(w, http.StatusInternalServerError, "Failed to initiate shutdown: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "System shutdown initiated",
		"delay":   req.Delay,
	})
}

// GetHostname handles GET /api/v1/system/hostname
// Returns just the hostname (lightweight endpoint for status checks).
func (h *SystemHandler) GetHostname(w http.ResponseWriter, r *http.Request) {
	info, err := system.GetInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get hostname")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"hostname": info.Hostname,
	})
}

// --- Helper functions ---

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   http.StatusText(status),
		"message": message,
	})
}

// --- Additional utility endpoints ---

// GetVersion handles GET /api/v1/system/version
// Returns CubeOS version information.
func (h *SystemHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	// TODO: Get version from build flags or config
	writeJSON(w, http.StatusOK, map[string]string{
		"version":    "0.1.0",
		"api_version": "v1",
		"go_version": strings.TrimPrefix(getGoVersion(), "go"),
	})
}

func getGoVersion() string {
	cmd := exec.Command("go", "version")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	parts := strings.Fields(string(out))
	if len(parts) >= 3 {
		return parts[2]
	}
	return "unknown"
}
