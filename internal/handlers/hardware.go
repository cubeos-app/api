package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
)

// HardwareHandler handles hardware-related HTTP requests via HAL.
type HardwareHandler struct {
	halClient *hal.Client
}

// NewHardwareHandler creates a new hardware handler.
func NewHardwareHandler(halClient *hal.Client) *HardwareHandler {
	return &HardwareHandler{
		halClient: halClient,
	}
}

// isHALUnsupported checks if a HAL error indicates the hardware feature
// is not supported/available, as opposed to a real service error.
func isHALUnsupported(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "not available") ||
		strings.Contains(msg, "no such device") ||
		strings.Contains(msg, "no rtc") ||
		strings.Contains(msg, "no watchdog") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not detected") ||
		strings.Contains(msg, "status 501")
}

// writeHALError writes the appropriate HTTP status for a HAL error:
// 501 for unsupported hardware, 500 for genuine errors.
func writeHALError(w http.ResponseWriter, err error, feature string) {
	if isHALUnsupported(err) {
		writeError(w, http.StatusNotImplemented, feature+" not available on this hardware")
		return
	}
	writeError(w, http.StatusInternalServerError, "Failed to "+strings.ToLower(feature)+": "+err.Error())
}

// Routes returns the hardware routes.
func (h *HardwareHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// System Info
	r.Get("/overview", h.GetOverview)
	r.Get("/temperature", h.GetTemperature)
	r.Get("/throttle", h.GetThrottleStatus)
	r.Get("/eeprom", h.GetEEPROMInfo)
	r.Get("/bootconfig", h.GetBootConfig)
	r.Get("/uptime", h.GetUptime)

	// Power Control
	r.Post("/reboot", h.Reboot)
	r.Post("/shutdown", h.Shutdown)

	// Power Status
	r.Get("/power", h.GetPowerStatus)
	r.Get("/battery", h.GetBatteryStatus)
	r.Get("/ups", h.GetUPSInfo)
	r.Post("/charging", h.SetChargingEnabled)
	r.Post("/battery/quickstart", h.QuickStartBattery)

	// Power Monitor (UPS monitoring daemon)
	r.Get("/power/monitor", h.GetPowerMonitorStatus)
	r.Post("/power/monitor/start", h.StartPowerMonitor)
	r.Post("/power/monitor/stop", h.StopPowerMonitor)

	// RTC
	r.Get("/rtc", h.GetRTCStatus)
	r.Post("/rtc/sync", h.SyncRTCTime)
	r.Post("/rtc/wake", h.SetWakeAlarm)
	r.Delete("/rtc/wake", h.ClearWakeAlarm)

	// Watchdog
	r.Get("/watchdog", h.GetWatchdogStatus)
	r.Post("/watchdog/pet", h.PetWatchdog)
	r.Post("/watchdog/enable", h.EnableWatchdog)

	// Services
	r.Get("/services/{name}", h.GetServiceStatus)
	r.Post("/services/{name}/start", h.StartService)
	r.Post("/services/{name}/stop", h.StopService)
	r.Post("/services/{name}/restart", h.RestartService)

	// GPIO
	r.Get("/gpio", h.GetGPIOPins)
	r.Get("/gpio/{pin}", h.GetGPIOPin)
	r.Post("/gpio/{pin}", h.SetGPIOPin)
	r.Post("/gpio/{pin}/mode", h.SetGPIOMode)

	// I2C
	r.Get("/i2c", h.ListI2CBuses)
	r.Get("/i2c/{bus}/scan", h.ScanI2CBus)
	r.Get("/i2c/{bus}/{addr}", h.GetI2CDevice)

	// Sensors
	r.Get("/sensors", h.GetAllSensors)
	r.Get("/sensors/1wire", h.Get1WireDevices)
	r.Get("/sensors/1wire/{id}", h.Read1WireDevice)
	r.Get("/sensors/bme280", h.ReadBME280)

	return r
}

// =============================================================================
// System Info Endpoints
// =============================================================================

// GetOverview godoc
// @Summary Get hardware overview
// @Description Returns comprehensive hardware status including temperature, throttle, power, and uptime
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} HardwareOverviewResponse
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/overview [get]
func (h *HardwareHandler) GetOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	overview := HardwareOverviewResponse{}

	// Gather all hardware info (best effort - don't fail on individual errors)
	if temp, err := h.halClient.GetTemperature(ctx); err == nil {
		overview.Temperature = temp
	}

	if throttle, err := h.halClient.GetThrottleStatus(ctx); err == nil {
		overview.Throttle = throttle
	}

	if uptime, err := h.halClient.GetUptime(ctx); err == nil {
		overview.Uptime = uptime
	}

	if power, err := h.halClient.GetPowerStatus(ctx); err == nil {
		overview.Power = power
	}

	if battery, err := h.halClient.GetBatteryStatus(ctx); err == nil {
		overview.Battery = battery
	}

	if watchdog, err := h.halClient.GetWatchdogStatus(ctx); err == nil {
		overview.Watchdog = watchdog
	}

	writeJSON(w, http.StatusOK, overview)
}

// HardwareOverviewResponse contains comprehensive hardware status
type HardwareOverviewResponse struct {
	Temperature *hal.TemperatureResponse `json:"temperature,omitempty"`
	Throttle    *hal.ThrottleStatus      `json:"throttle,omitempty"`
	Uptime      *hal.UptimeInfo          `json:"uptime,omitempty"`
	Power       *hal.PowerStatus         `json:"power,omitempty"`
	Battery     *hal.BatteryStatus       `json:"battery,omitempty"`
	Watchdog    *hal.WatchdogInfo        `json:"watchdog,omitempty"`
}

// GetTemperature godoc
// @Summary Get CPU temperature
// @Description Returns current CPU temperature from thermal sensors
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.TemperatureResponse
// @Failure 500 {object} ErrorResponse "Failed to read temperature"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/temperature [get]
func (h *HardwareHandler) GetTemperature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	temp, err := h.halClient.GetTemperature(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get temperature: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, temp)
}

// GetThrottleStatus godoc
// @Summary Get throttle status
// @Description Returns CPU throttling status (under-voltage, frequency capping, thermal throttling)
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.ThrottleStatus
// @Failure 500 {object} ErrorResponse "Failed to read throttle status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/throttle [get]
func (h *HardwareHandler) GetThrottleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetThrottleStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get throttle status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetEEPROMInfo godoc
// @Summary Get EEPROM information
// @Description Returns Raspberry Pi EEPROM version and configuration
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.EEPROMInfo
// @Failure 500 {object} ErrorResponse "Failed to read EEPROM"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/eeprom [get]
func (h *HardwareHandler) GetEEPROMInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	info, err := h.halClient.GetEEPROMInfo(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get EEPROM info: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// GetBootConfig godoc
// @Summary Get boot configuration
// @Description Returns Raspberry Pi boot configuration (config.txt settings)
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.BootConfig
// @Failure 500 {object} ErrorResponse "Failed to read boot config"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/bootconfig [get]
func (h *HardwareHandler) GetBootConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	config, err := h.halClient.GetBootConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get boot config: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, config)
}

// GetUptime godoc
// @Summary Get system uptime
// @Description Returns system uptime, load averages, and boot time
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.UptimeInfo
// @Failure 500 {object} ErrorResponse "Failed to read uptime"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/uptime [get]
func (h *HardwareHandler) GetUptime(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	info, err := h.halClient.GetUptime(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get uptime: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// =============================================================================
// Power Control Endpoints
// =============================================================================

// Reboot godoc
// @Summary Reboot system
// @Description Initiates a system reboot (requires admin privileges)
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to initiate reboot"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/reboot [post]
func (h *HardwareHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.Reboot(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to initiate reboot: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "System rebooting...",
	})
}

// Shutdown godoc
// @Summary Shutdown system
// @Description Initiates a system shutdown (requires admin privileges)
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to initiate shutdown"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/shutdown [post]
func (h *HardwareHandler) Shutdown(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.Shutdown(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to initiate shutdown: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "System shutting down...",
	})
}

// SuccessResponse is a generic success response
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// =============================================================================
// Power Status Endpoints
// =============================================================================

// GetPowerStatus godoc
// @Summary Get power status
// @Description Returns overall power status including input voltage and power source
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.PowerStatus
// @Failure 500 {object} ErrorResponse "Failed to read power status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/power [get]
func (h *HardwareHandler) GetPowerStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetPowerStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get power status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetBatteryStatus godoc
// @Summary Get battery status
// @Description Returns UPS-HAT battery level, charging state, and estimated time remaining
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.BatteryStatus
// @Failure 500 {object} ErrorResponse "Failed to read battery status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/battery [get]
func (h *HardwareHandler) GetBatteryStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetBatteryStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get battery status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetUPSInfo godoc
// @Summary Get UPS information
// @Description Returns detailed UPS-HAT information including model, firmware, and capabilities
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.UPSInfo
// @Failure 500 {object} ErrorResponse "Failed to read UPS info"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/ups [get]
func (h *HardwareHandler) GetUPSInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	info, err := h.halClient.GetUPSInfo(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get UPS info: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// ChargingRequest represents a charging control request
type ChargingRequest struct {
	Enabled bool `json:"enabled"`
}

// SetChargingEnabled godoc
// @Summary Enable or disable battery charging
// @Description Controls UPS-HAT battery charging (useful for battery conditioning)
// @Tags Hardware
// @Accept json
// @Produce json
// @Param request body ChargingRequest true "Charging control"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to set charging"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/charging [post]
func (h *HardwareHandler) SetChargingEnabled(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req ChargingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SetChargingEnabled(ctx, req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set charging: "+err.Error())
		return
	}

	msg := "Charging disabled"
	if req.Enabled {
		msg = "Charging enabled"
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: msg,
	})
}

// QuickStartBattery godoc
// @Summary Quick start battery
// @Description Initiates UPS-HAT battery quick start procedure for deeply discharged batteries
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to quick start battery"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/battery/quickstart [post]
func (h *HardwareHandler) QuickStartBattery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.QuickStartBattery(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to quick start battery: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Battery quick start initiated",
	})
}

// =============================================================================
// Power Monitor Endpoints
// =============================================================================

// GetPowerMonitorStatus godoc
// @Summary Get power monitor status
// @Description Returns UPS power monitoring daemon status including battery percent, charging state, UPS model, and AC power status
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.PowerMonitorStatus
// @Failure 500 {object} ErrorResponse "Failed to get power monitor status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/power/monitor [get]
func (h *HardwareHandler) GetPowerMonitorStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetPowerMonitorStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get power monitor status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// StartPowerMonitor godoc
// @Summary Start power monitor
// @Description Starts the UPS power monitoring daemon for continuous battery and charging state tracking
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to start power monitor"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/power/monitor/start [post]
func (h *HardwareHandler) StartPowerMonitor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.StartPowerMonitor(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to start power monitor: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Power monitor started",
	})
}

// StopPowerMonitor godoc
// @Summary Stop power monitor
// @Description Stops the UPS power monitoring daemon
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to stop power monitor"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/power/monitor/stop [post]
func (h *HardwareHandler) StopPowerMonitor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.StopPowerMonitor(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to stop power monitor: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Power monitor stopped",
	})
}

// =============================================================================
// RTC Endpoints
// =============================================================================

// GetRTCStatus godoc
// @Summary Get RTC status
// @Description Returns Real-Time Clock status and current time
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.RTCStatus
// @Failure 500 {object} ErrorResponse "Failed to read RTC"
// @Failure 501 {object} ErrorResponse "RTC not available on this hardware"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/rtc [get]
func (h *HardwareHandler) GetRTCStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetRTCStatus(ctx)
	if err != nil {
		writeHALError(w, err, "RTC status")
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// SyncRTCTime godoc
// @Summary Sync system time from RTC
// @Description Sets system time from Real-Time Clock (useful after boot without network)
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to sync time"
// @Failure 501 {object} ErrorResponse "RTC not available on this hardware"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/rtc/sync [post]
func (h *HardwareHandler) SyncRTCTime(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SyncTimeFromRTC(ctx); err != nil {
		writeHALError(w, err, "RTC time sync")
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "System time synced from RTC",
	})
}

// WakeAlarmRequest represents a wake alarm request
type WakeAlarmRequest struct {
	Time string `json:"time"` // ISO 8601 format
}

// SetWakeAlarm godoc
// @Summary Set RTC wake alarm
// @Description Sets a wake alarm to power on the system at a specific time
// @Tags Hardware
// @Accept json
// @Produce json
// @Param request body WakeAlarmRequest true "Wake alarm time (ISO 8601)"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid time format"
// @Failure 500 {object} ErrorResponse "Failed to set wake alarm"
// @Failure 501 {object} ErrorResponse "Wake alarm not available on this hardware"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/rtc/wake [post]
func (h *HardwareHandler) SetWakeAlarm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req WakeAlarmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	wakeTime, err := time.Parse(time.RFC3339, req.Time)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid time format. Use ISO 8601 (e.g., 2024-01-15T08:00:00Z)")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SetWakeAlarm(ctx, wakeTime); err != nil {
		writeHALError(w, err, "Wake alarm")
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Wake alarm set for " + wakeTime.Format(time.RFC3339),
	})
}

// ClearWakeAlarm godoc
// @Summary Clear RTC wake alarm
// @Description Clears any scheduled wake alarm
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to clear wake alarm"
// @Failure 501 {object} ErrorResponse "Wake alarm not available on this hardware"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/rtc/wake [delete]
func (h *HardwareHandler) ClearWakeAlarm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.ClearWakeAlarm(ctx); err != nil {
		writeHALError(w, err, "Wake alarm clear")
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Wake alarm cleared",
	})
}

// =============================================================================
// Watchdog Endpoints
// =============================================================================

// GetWatchdogStatus godoc
// @Summary Get watchdog status
// @Description Returns hardware watchdog status and configuration
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.WatchdogInfo
// @Failure 500 {object} ErrorResponse "Failed to read watchdog status"
// @Failure 501 {object} ErrorResponse "Watchdog not available on this hardware"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/watchdog [get]
func (h *HardwareHandler) GetWatchdogStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetWatchdogStatus(ctx)
	if err != nil {
		writeHALError(w, err, "Watchdog status")
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// PetWatchdog godoc
// @Summary Pet the watchdog
// @Description Resets the hardware watchdog timer to prevent system reset
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to pet watchdog"
// @Failure 501 {object} ErrorResponse "Watchdog not available on this hardware"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/watchdog/pet [post]
func (h *HardwareHandler) PetWatchdog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.PetWatchdog(ctx); err != nil {
		writeHALError(w, err, "Watchdog pet")
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Watchdog timer reset",
	})
}

// EnableWatchdog godoc
// @Summary Enable watchdog
// @Description Enables the hardware watchdog timer
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to enable watchdog"
// @Failure 501 {object} ErrorResponse "Watchdog not available on this hardware"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/watchdog/enable [post]
func (h *HardwareHandler) EnableWatchdog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.EnableWatchdog(ctx); err != nil {
		writeHALError(w, err, "Watchdog enable")
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Watchdog enabled",
	})
}

// =============================================================================
// Service Control Endpoints
// =============================================================================

// GetServiceStatus godoc
// @Summary Get service status
// @Description Returns status of a systemd service
// @Tags Hardware
// @Accept json
// @Produce json
// @Param name path string true "Service name" example(hostapd)
// @Success 200 {object} hal.ServiceStatus
// @Failure 400 {object} ErrorResponse "Service name required"
// @Failure 500 {object} ErrorResponse "Failed to get service status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/services/{name} [get]
func (h *HardwareHandler) GetServiceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")

	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetServiceStatus(ctx, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get service status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// StartService godoc
// @Summary Start a service
// @Description Starts a systemd service
// @Tags Hardware
// @Accept json
// @Produce json
// @Param name path string true "Service name" example(hostapd)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Service name required"
// @Failure 500 {object} ErrorResponse "Failed to start service"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/services/{name}/start [post]
func (h *HardwareHandler) StartService(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")

	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.StartService(ctx, name); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to start service: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Service " + name + " started",
	})
}

// StopService godoc
// @Summary Stop a service
// @Description Stops a systemd service
// @Tags Hardware
// @Accept json
// @Produce json
// @Param name path string true "Service name" example(hostapd)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Service name required"
// @Failure 500 {object} ErrorResponse "Failed to stop service"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/services/{name}/stop [post]
func (h *HardwareHandler) StopService(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")

	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.StopService(ctx, name); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to stop service: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Service " + name + " stopped",
	})
}

// RestartService godoc
// @Summary Restart a service
// @Description Restarts a systemd service
// @Tags Hardware
// @Accept json
// @Produce json
// @Param name path string true "Service name" example(hostapd)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Service name required"
// @Failure 500 {object} ErrorResponse "Failed to restart service"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/services/{name}/restart [post]
func (h *HardwareHandler) RestartService(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")

	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.RestartService(ctx, name); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to restart service: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Service " + name + " restarted",
	})
}

// =============================================================================
// GPIO Endpoints
// =============================================================================

// GetGPIOPins godoc
// @Summary List GPIO pins
// @Description Returns status of all GPIO pins
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} GPIOPinsResponse
// @Failure 500 {object} ErrorResponse "Failed to read GPIO"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/gpio [get]
func (h *HardwareHandler) GetGPIOPins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	pins, err := h.halClient.GetGPIOPins(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get GPIO pins: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, pins)
}

// GPIOPinsResponse contains GPIO pin list
type GPIOPinsResponse struct {
	Pins []hal.GPIOPin `json:"pins"`
}

// GetGPIOPin godoc
// @Summary Get GPIO pin status
// @Description Returns status of a specific GPIO pin
// @Tags Hardware
// @Accept json
// @Produce json
// @Param pin path int true "GPIO pin number" example(17)
// @Success 200 {object} hal.GPIOPin
// @Failure 400 {object} ErrorResponse "Invalid pin number"
// @Failure 500 {object} ErrorResponse "Failed to read GPIO pin"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/gpio/{pin} [get]
func (h *HardwareHandler) GetGPIOPin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pinStr := chi.URLParam(r, "pin")

	pin, err := strconv.Atoi(pinStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid pin number")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	pinStatus, err := h.halClient.GetGPIOPin(ctx, pin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get GPIO pin: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, pinStatus)
}

// GPIOSetRequest represents a GPIO set request
type GPIOSetRequest struct {
	Value bool `json:"value"`
}

// SetGPIOPin godoc
// @Summary Set GPIO pin value
// @Description Sets a GPIO pin high or low
// @Tags Hardware
// @Accept json
// @Produce json
// @Param pin path int true "GPIO pin number" example(17)
// @Param request body GPIOSetRequest true "Pin value"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to set GPIO pin"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/gpio/{pin} [post]
func (h *HardwareHandler) SetGPIOPin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pinStr := chi.URLParam(r, "pin")

	pin, err := strconv.Atoi(pinStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid pin number")
		return
	}

	var req GPIOSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SetGPIOPin(ctx, pin, func() int {
		if req.Value {
			return 1
		}
		return 0
	}()); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set GPIO pin: "+err.Error())
		return
	}

	value := "LOW"
	if req.Value {
		value = "HIGH"
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "GPIO " + pinStr + " set to " + value,
	})
}

// GPIOModeRequest represents a GPIO mode request
type GPIOModeRequest struct {
	Mode string `json:"mode"` // "input" or "output"
}

// SetGPIOMode godoc
// @Summary Set GPIO pin mode
// @Description Sets a GPIO pin to input or output mode
// @Tags Hardware
// @Accept json
// @Produce json
// @Param pin path int true "GPIO pin number" example(17)
// @Param request body GPIOModeRequest true "Pin mode (input/output)"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to set GPIO mode"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/gpio/{pin}/mode [post]
func (h *HardwareHandler) SetGPIOMode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pinStr := chi.URLParam(r, "pin")

	pin, err := strconv.Atoi(pinStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid pin number")
		return
	}

	var req GPIOModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Mode != "input" && req.Mode != "output" {
		writeError(w, http.StatusBadRequest, "Mode must be 'input' or 'output'")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SetGPIOMode(ctx, pin, req.Mode); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set GPIO mode: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "GPIO " + pinStr + " set to " + req.Mode,
	})
}

// =============================================================================
// I2C Endpoints
// =============================================================================

// ListI2CBuses godoc
// @Summary List I2C buses
// @Description Returns list of available I2C buses
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} I2CBusesResponse
// @Failure 500 {object} ErrorResponse "Failed to list I2C buses"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/i2c [get]
func (h *HardwareHandler) ListI2CBuses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	buses, err := h.halClient.ListI2CBuses(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list I2C buses: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, buses)
}

// I2CBusesResponse contains I2C bus list
type I2CBusesResponse struct {
	Buses []hal.I2CBus `json:"buses"`
}

// ScanI2CBus godoc
// @Summary Scan I2C bus
// @Description Scans an I2C bus for connected devices
// @Tags Hardware
// @Accept json
// @Produce json
// @Param bus path int true "I2C bus number" example(1)
// @Success 200 {object} hal.I2CScanResult
// @Failure 400 {object} ErrorResponse "Invalid bus number"
// @Failure 500 {object} ErrorResponse "Failed to scan I2C bus"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/i2c/{bus}/scan [get]
func (h *HardwareHandler) ScanI2CBus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	busStr := chi.URLParam(r, "bus")

	bus, err := strconv.Atoi(busStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid bus number")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	result, err := h.halClient.ScanI2CBus(ctx, bus)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to scan I2C bus: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetI2CDevice godoc
// @Summary Read I2C device
// @Description Reads data from an I2C device at a specific address
// @Tags Hardware
// @Accept json
// @Produce json
// @Param bus path int true "I2C bus number" example(1)
// @Param addr path string true "I2C device address (hex)" example(0x48)
// @Success 200 {object} hal.I2CDevice
// @Failure 400 {object} ErrorResponse "Invalid bus or address"
// @Failure 500 {object} ErrorResponse "Failed to read I2C device"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/i2c/{bus}/{addr} [get]
func (h *HardwareHandler) GetI2CDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	busStr := chi.URLParam(r, "bus")
	addrStr := chi.URLParam(r, "addr")

	bus, err := strconv.Atoi(busStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid bus number")
		return
	}

	// Parse address (supports 0x prefix)
	addr, err := strconv.ParseInt(addrStr, 0, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid device address")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	device, err := h.halClient.GetI2CDevice(ctx, bus, int(addr))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read I2C device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// =============================================================================
// Sensor Endpoints
// =============================================================================

// GetAllSensors godoc
// @Summary Get all sensors
// @Description Returns readings from all detected sensors (1-Wire, BME280, etc.)
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.AllSensorsResponse
// @Failure 500 {object} ErrorResponse "Failed to read sensors"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/sensors [get]
func (h *HardwareHandler) GetAllSensors(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	sensors, err := h.halClient.GetAllSensors(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get sensors: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, sensors)
}

// Get1WireDevices godoc
// @Summary List 1-Wire devices
// @Description Returns list of detected 1-Wire devices (temperature sensors, etc.)
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} OneWireDevicesResponse
// @Failure 500 {object} ErrorResponse "Failed to list 1-Wire devices"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/sensors/1wire [get]
func (h *HardwareHandler) Get1WireDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.Get1WireDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get 1-Wire devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// OneWireDevicesResponse contains 1-Wire device list
type OneWireDevicesResponse struct {
	Devices []hal.OneWireDevice `json:"devices"`
}

// Read1WireDevice godoc
// @Summary Read 1-Wire device
// @Description Reads data from a specific 1-Wire device
// @Tags Hardware
// @Accept json
// @Produce json
// @Param id path string true "1-Wire device ID" example(28-000005a3b3f1)
// @Success 200 {object} hal.OneWireDevice
// @Failure 400 {object} ErrorResponse "Device ID required"
// @Failure 500 {object} ErrorResponse "Failed to read 1-Wire device"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/sensors/1wire/{id} [get]
func (h *HardwareHandler) Read1WireDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if id == "" {
		writeError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	device, err := h.halClient.Read1WireDevice(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read 1-Wire device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// ReadBME280 godoc
// @Summary Read BME280 sensor
// @Description Returns temperature, humidity, and pressure from BME280 sensor
// @Tags Hardware
// @Accept json
// @Produce json
// @Success 200 {object} hal.BME280Reading
// @Failure 500 {object} ErrorResponse "Failed to read BME280"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hardware/sensors/bme280 [get]
func (h *HardwareHandler) ReadBME280(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	reading, err := h.halClient.ReadBME280(ctx, 1, "0x76")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read BME280: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, reading)
}

// =============================================================================
// Support Bundle Endpoint
// =============================================================================

// GetSupportBundle godoc
// @Summary Download support bundle
// @Description Downloads a zip archive containing system logs, configuration, and diagnostic data for troubleshooting
// @Tags Support
// @Produce application/zip
// @Success 200 {file} binary "Support bundle zip file"
// @Failure 500 {object} ErrorResponse "Failed to generate support bundle"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /support/bundle.zip [get]
func (h *HardwareHandler) GetSupportBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	data, err := h.halClient.GetSupportBundle(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get support bundle: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="cubeos-support-bundle.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
