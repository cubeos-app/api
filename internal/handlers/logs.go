package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
)

// LogsHandler handles log-related HTTP requests via HAL.
type LogsHandler struct {
	halClient *hal.Client
}

// NewLogsHandler creates a new logs handler.
func NewLogsHandler(halClient *hal.Client) *LogsHandler {
	return &LogsHandler{
		halClient: halClient,
	}
}

// Routes returns the logs routes.
func (h *LogsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/kernel", h.GetKernelLogs)
	r.Get("/journal", h.GetJournalLogs)
	r.Get("/hardware", h.GetHardwareLogs)
	r.Get("/hardware/{category}", h.GetHardwareLogsByCategory)

	return r
}

// GetKernelLogs godoc
// @Summary Get kernel logs
// @Description Returns kernel ring buffer (dmesg) logs
// @Tags Logs
// @Accept json
// @Produce json
// @Param lines query int false "Number of lines to return" default(100)
// @Param level query string false "Filter by log level" Enums(emerg, alert, crit, err, warn, notice, info, debug)
// @Success 200 {object} hal.LogsResponse
// @Failure 500 {object} models.ErrorResponse "Failed to get kernel logs"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/logs/kernel [get]
func (h *LogsHandler) GetKernelLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	lines := 100
	if l := r.URL.Query().Get("lines"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			lines = parsed
		}
	}

	level := r.URL.Query().Get("level")

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	logs, err := h.halClient.GetKernelLogs(ctx, lines, level)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get kernel logs: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, logs)
}

// GetJournalLogs godoc
// @Summary Get journal logs
// @Description Returns systemd journal logs with filtering options
// @Tags Logs
// @Accept json
// @Produce json
// @Param lines query int false "Number of lines to return" default(100)
// @Param unit query string false "Filter by systemd unit" example(cubeos-api.service)
// @Param since query string false "Show logs since time" example(1h)
// @Param priority query int false "Filter by priority (0-7, lower is more severe)" default(6)
// @Success 200 {object} hal.LogsResponse
// @Failure 500 {object} models.ErrorResponse "Failed to get journal logs"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/logs/journal [get]
func (h *LogsHandler) GetJournalLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	lines := 100
	if l := r.URL.Query().Get("lines"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			lines = parsed
		}
	}

	unit := r.URL.Query().Get("unit")
	since := r.URL.Query().Get("since")

	priority := 6 // Default to info and above
	if p := r.URL.Query().Get("priority"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed >= 0 && parsed <= 7 {
			priority = parsed
		}
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	logs, err := h.halClient.GetJournalLogs(ctx, lines, unit, since, priority)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get journal logs: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, logs)
}

// GetHardwareLogs godoc
// @Summary Get hardware logs
// @Description Returns all hardware-related logs from various sources
// @Tags Logs
// @Accept json
// @Produce json
// @Success 200 {object} hal.HardwareLogsResponse
// @Failure 500 {object} models.ErrorResponse "Failed to get hardware logs"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/logs/hardware [get]
func (h *LogsHandler) GetHardwareLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	logs, err := h.halClient.GetHardwareLogs(ctx, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get hardware logs: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, logs)
}

// GetHardwareLogsByCategory godoc
// @Summary Get hardware logs by category
// @Description Returns hardware logs filtered by category
// @Tags Logs
// @Accept json
// @Produce json
// @Param category path string true "Log category" Enums(usb, pci, gpio, i2c, spi, thermal, power, storage)
// @Success 200 {object} hal.HardwareLogsResponse
// @Failure 400 {object} models.ErrorResponse "Category required"
// @Failure 500 {object} models.ErrorResponse "Failed to get hardware logs"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/logs/hardware/{category} [get]
func (h *LogsHandler) GetHardwareLogsByCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	category := chi.URLParam(r, "category")

	if category == "" {
		writeError(w, http.StatusBadRequest, "Log category is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	logs, err := h.halClient.GetHardwareLogs(ctx, category)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get hardware logs: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, logs)
}
