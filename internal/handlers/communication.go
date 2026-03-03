package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"

	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
)

// CommunicationHandler handles communication device HTTP requests via HAL.
type CommunicationHandler struct {
	halClient  *hal.Client
	db         *sqlx.DB
	tleManager tleManagerIface
}

// tleManagerIface is the interface used by CommunicationHandler for pass prediction.
type tleManagerIface interface {
	ComputePasses(ctx context.Context, lat, lon, altM float64, hours int, minElevDeg float64) ([]managers.PassSummary, error)
	GetLocations(ctx context.Context) ([]managers.IridiumLocation, error)
	AddLocation(ctx context.Context, name string, lat, lon, altM float64) (int64, error)
	DeleteLocation(ctx context.Context, id int64) error
	CacheInfo(ctx context.Context) (count int, fetchedAt time.Time, err error)
	RefreshTLEs(ctx context.Context) error
}

// NewCommunicationHandler creates a new communication handler.
func NewCommunicationHandler(halClient *hal.Client, db *sqlx.DB) *CommunicationHandler {
	return &CommunicationHandler{
		halClient: halClient,
		db:        db,
	}
}

// SetTLEManager attaches the TLE manager for pass prediction endpoints.
func (h *CommunicationHandler) SetTLEManager(m tleManagerIface) {
	h.tleManager = m
}

// Routes returns the communication routes.
func (h *CommunicationHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// GPS — port passed as query param (device paths like /dev/ttyACM0 break chi path params)
	r.Get("/gps", h.GetGPSDevices)
	r.Get("/gps/status", h.GetGPSStatus)
	r.Get("/gps/position", h.GetGPSPosition)

	// Cellular
	r.Get("/cellular", h.GetCellularModems)
	r.Get("/cellular/status", h.GetCellularStatus)
	r.Get("/cellular/{modem}/signal", h.GetCellularSignal)
	r.Post("/cellular/{modem}/connect", h.ConnectCellular)
	r.Post("/cellular/{modem}/disconnect", h.DisconnectCellular)

	// Android Tethering
	r.Get("/cellular/android", h.GetAndroidTetheringStatus)
	r.Get("/cellular/android/status", h.GetAndroidTetheringStatus) // Alias to match HAL route naming
	r.Post("/cellular/android/enable", h.EnableAndroidTethering)
	r.Post("/cellular/android/disable", h.DisableAndroidTethering)

	// Meshtastic — full lifecycle routes (no {port}, uses connect/disconnect pattern)
	r.Get("/meshtastic/devices", h.GetMeshtasticDevices)
	r.Post("/meshtastic/connect", h.ConnectMeshtastic)
	r.Post("/meshtastic/disconnect", h.DisconnectMeshtastic)
	r.Get("/meshtastic/status", h.GetMeshtasticStatus)
	r.Get("/meshtastic/nodes", h.GetMeshtasticNodes)
	r.Get("/meshtastic/position", h.GetMeshtasticPosition)
	r.Get("/meshtastic/messages", h.GetMeshtasticMessages)
	r.Post("/meshtastic/messages/send", h.SendMeshtasticMessage)
	r.Post("/meshtastic/messages/send_raw", h.SendMeshtasticRaw)
	r.Get("/meshtastic/config", h.GetMeshtasticConfig)
	r.Post("/meshtastic/channel", h.SetMeshtasticChannel)
	r.Get("/meshtastic/events", h.StreamMeshtasticEvents)

	// Iridium — new lifecycle routes (no {port}, uses connect/disconnect pattern)
	r.Get("/iridium/devices", h.GetIridiumDevices)
	r.Post("/iridium/connect", h.ConnectIridium)
	r.Post("/iridium/disconnect", h.DisconnectIridium)
	r.Get("/iridium/status", h.GetIridiumStatus)
	r.Get("/iridium/signal", h.GetIridiumSignal)
	r.Get("/iridium/signal/fast", h.GetIridiumSignalFast)
	r.Post("/iridium/send", h.SendIridiumSBD)
	r.Post("/iridium/mailbox_check", h.CheckIridiumMailbox)
	r.Get("/iridium/receive", h.ReceiveIridiumMessage)
	r.Get("/iridium/messages", h.GetIridiumMessages)
	r.Post("/iridium/clear", h.ClearIridiumBuffers)
	r.Get("/iridium/events", h.StreamIridiumEvents)

	// Iridium signal history + credit tracker
	r.Get("/iridium/signal/history", h.GetIridiumSignalHistory)
	r.Get("/iridium/credits", h.GetIridiumCredits)
	r.Post("/iridium/credits/budget", h.SetIridiumBudget)

	// MeshSat — proxy to meshsat coreapp (:6050)
	r.Get("/meshsat/status", h.GetMeshsatStatus)
	r.Get("/meshsat/messages", h.GetMeshsatMessages)
	r.Get("/meshsat/telemetry", h.GetMeshsatTelemetry)
	r.Get("/meshsat/positions", h.GetMeshsatPositions)
	r.Get("/meshsat/nodes", h.GetMeshsatNodes)
	r.Get("/meshsat/messages/stats", h.GetMeshsatMessageStats)
	r.Get("/meshsat/events", h.StreamMeshsatEvents)
	r.Post("/meshsat/admin/reboot", h.PostMeshsatAdminReboot)
	r.Post("/meshsat/admin/factory_reset", h.PostMeshsatAdminFactoryReset)
	r.Post("/meshsat/admin/traceroute", h.PostMeshsatAdminTraceroute)
	r.Post("/meshsat/config/radio", h.PostMeshsatConfigRadio)
	r.Post("/meshsat/config/module", h.PostMeshsatConfigModule)
	r.Post("/meshsat/waypoints", h.PostMeshsatWaypoint)

	// MeshSat Gateway management — proxy to meshsat coreapp (:6050)
	r.Get("/meshsat/gateways", h.GetMeshsatGateways)
	r.Get("/meshsat/gateways/{type}", h.GetMeshsatGateway)
	r.Put("/meshsat/gateways/{type}", h.PutMeshsatGateway)
	r.Delete("/meshsat/gateways/{type}", h.DeleteMeshsatGateway)
	r.Post("/meshsat/gateways/{type}/start", h.PostMeshsatGatewayStart)
	r.Post("/meshsat/gateways/{type}/stop", h.PostMeshsatGatewayStop)
	r.Post("/meshsat/gateways/{type}/test", h.PostMeshsatGatewayTest)

	// MeshSat Iridium queue — offline compose and priority management
	r.Get("/meshsat/iridium/queue", h.GetMeshsatIridiumQueue)
	r.Post("/meshsat/iridium/queue", h.PostMeshsatIridiumQueue)
	r.Post("/meshsat/iridium/queue/{id}/cancel", h.PostMeshsatIridiumQueueCancel)
	r.Post("/meshsat/iridium/queue/{id}/priority", h.PostMeshsatIridiumQueuePriority)

	// Iridium pass predictor (SGP4 + Celestrak TLEs)
	r.Get("/iridium/passes", h.GetIridiumPasses)
	r.Post("/iridium/passes/refresh", h.PostIridiumPassesRefresh)
	r.Get("/iridium/locations", h.GetIridiumLocations)
	r.Post("/iridium/locations", h.PostIridiumLocation)
	r.Delete("/iridium/locations/{id}", h.DeleteIridiumLocation)

	// Bluetooth
	r.Get("/bluetooth", h.GetBluetoothStatus)
	r.Get("/bluetooth/coexistence", h.GetBluetoothCoexistence)
	r.Post("/bluetooth/override", h.SetBluetoothOverride)
	r.Post("/bluetooth/power/on", h.PowerOnBluetooth)
	r.Post("/bluetooth/power/off", h.PowerOffBluetooth)
	r.Get("/bluetooth/devices", h.GetBluetoothDevices)
	r.Post("/bluetooth/scan", h.ScanBluetoothDevices)
	r.Post("/bluetooth/pair/{address}", h.PairBluetoothDevice)
	r.Post("/bluetooth/connect/{address}", h.ConnectBluetoothDevice)
	r.Post("/bluetooth/disconnect/{address}", h.DisconnectBluetoothDevice)
	r.Delete("/bluetooth/devices/{address}", h.RemoveBluetoothDevice)

	return r
}

// =============================================================================
// GPS Endpoints
// =============================================================================

// GetGPSDevices godoc
// @Summary List GPS devices
// @Description Returns list of detected GPS devices (USB, serial)
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.GPSDevicesResponse
// @Failure 500 {object} ErrorResponse "Failed to list GPS devices"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/gps [get]
func (h *CommunicationHandler) GetGPSDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetGPSDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get GPS devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// GetGPSStatus godoc
// @Summary Get GPS status
// @Description Returns GPS receiver status (fix, satellites, HDOP)
// @Tags Communication
// @Accept json
// @Produce json
// @Param port query string true "GPS device port" example("/dev/ttyUSB0")
// @Success 200 {object} hal.GPSStatus
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get GPS status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/gps/status [get]
func (h *CommunicationHandler) GetGPSStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := r.URL.Query().Get("port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "GPS port is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetGPSStatus(ctx, port)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get GPS status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetGPSPosition godoc
// @Summary Get GPS position
// @Description Returns current GPS position (lat, lon, alt, speed, heading)
// @Tags Communication
// @Accept json
// @Produce json
// @Param port query string true "GPS device port" example("/dev/ttyUSB0")
// @Param timeout query int false "Timeout in seconds" default(10)
// @Success 200 {object} hal.GPSPosition
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get GPS position"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/gps/position [get]
func (h *CommunicationHandler) GetGPSPosition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := r.URL.Query().Get("port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "GPS port is required")
		return
	}

	timeout := 10
	if t := r.URL.Query().Get("timeout"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	position, err := h.halClient.GetGPSPosition(ctx, port, timeout)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get GPS position: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, position)
}

// =============================================================================
// Cellular Endpoints
// =============================================================================

// GetCellularModems godoc
// @Summary List cellular modems
// @Description Returns list of detected cellular modems (4G/LTE)
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.CellularModemsResponse
// @Failure 500 {object} ErrorResponse "Failed to list cellular modems"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular [get]
func (h *CommunicationHandler) GetCellularModems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	modems, err := h.halClient.GetCellularModems(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cellular modems: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, modems)
}

// GetCellularStatus godoc
// @Summary Get cellular status
// @Description Returns overall cellular connection status
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.CellularStatus
// @Failure 500 {object} ErrorResponse "Failed to get cellular status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular/status [get]
func (h *CommunicationHandler) GetCellularStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetCellularStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cellular status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetCellularSignal godoc
// @Summary Get cellular signal strength
// @Description Returns signal strength and quality for a modem
// @Tags Communication
// @Accept json
// @Produce json
// @Param modem path int true "Modem index" example(0)
// @Success 200 {object} hal.CellularSignal
// @Failure 400 {object} ErrorResponse "Invalid modem index"
// @Failure 500 {object} ErrorResponse "Failed to get signal"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular/{modem}/signal [get]
func (h *CommunicationHandler) GetCellularSignal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modemStr := chi.URLParam(r, "modem")

	modemIndex, err := strconv.Atoi(modemStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid modem index")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	signal, err := h.halClient.GetCellularSignal(ctx, modemIndex)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cellular signal: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, signal)
}

// CellularConnectRequest represents a cellular connection request
type CellularConnectRequest struct {
	APN      string `json:"apn"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// ConnectCellular godoc
// @Summary Connect cellular modem
// @Description Establishes cellular data connection
// @Tags Communication
// @Accept json
// @Produce json
// @Param modem path int true "Modem index" example(0)
// @Param request body CellularConnectRequest true "APN settings"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to connect"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular/{modem}/connect [post]
func (h *CommunicationHandler) ConnectCellular(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modemStr := chi.URLParam(r, "modem")

	modemIndex, err := strconv.Atoi(modemStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid modem index")
		return
	}

	var req CellularConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.APN == "" {
		writeError(w, http.StatusBadRequest, "APN is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.ConnectCellular(ctx, modemIndex, req.APN, req.Username, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to connect cellular: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Cellular connection established",
	})
}

// DisconnectCellular godoc
// @Summary Disconnect cellular modem
// @Description Disconnects cellular data connection
// @Tags Communication
// @Accept json
// @Produce json
// @Param modem path int true "Modem index" example(0)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid modem index"
// @Failure 500 {object} ErrorResponse "Failed to disconnect"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular/{modem}/disconnect [post]
func (h *CommunicationHandler) DisconnectCellular(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modemStr := chi.URLParam(r, "modem")

	modemIndex, err := strconv.Atoi(modemStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid modem index")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.DisconnectCellular(ctx, modemIndex); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disconnect cellular: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Cellular disconnected",
	})
}

// =============================================================================
// Android Tethering Endpoints
// =============================================================================

// GetAndroidTetheringStatus godoc
// @Summary Get Android tethering status
// @Description Returns USB tethering status for connected Android phone. Also available at /communication/cellular/android for backward compatibility.
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.AndroidTetheringStatus
// @Failure 500 {object} ErrorResponse "Failed to get status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular/android/status [get]
func (h *CommunicationHandler) GetAndroidTetheringStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetAndroidTetheringStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Android tethering status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// EnableAndroidTethering godoc
// @Summary Enable Android tethering
// @Description Enables USB tethering on connected Android phone via ADB
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to enable tethering"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular/android/enable [post]
func (h *CommunicationHandler) EnableAndroidTethering(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.EnableAndroidTethering(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to enable Android tethering: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Android tethering enabled",
	})
}

// DisableAndroidTethering godoc
// @Summary Disable Android tethering
// @Description Disables USB tethering on connected Android phone via ADB
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to disable tethering"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular/android/disable [post]
func (h *CommunicationHandler) DisableAndroidTethering(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.DisableAndroidTethering(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disable Android tethering: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Android tethering disabled",
	})
}

// =============================================================================
// Meshtastic Endpoints
// =============================================================================

// GetMeshtasticDevices godoc
// @Summary List Meshtastic devices
// @Description Returns list of detected Meshtastic radios (USB serial and BLE)
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.MeshtasticDevicesResponse
// @Failure 500 {object} ErrorResponse "Failed to list Meshtastic devices"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/devices [get]
func (h *CommunicationHandler) GetMeshtasticDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetMeshtasticDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Meshtastic devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// MeshtasticConnectAPIRequest represents a Meshtastic connect request at the API level.
// Supports auto-detect (empty body), explicit serial (port + transport), or BLE (address + transport).
type MeshtasticConnectAPIRequest struct {
	Port      string `json:"port,omitempty"`
	Address   string `json:"address,omitempty"`
	Transport string `json:"transport,omitempty"` // "auto", "serial", "ble"
}

// ConnectMeshtastic godoc
// @Summary Connect to Meshtastic radio
// @Description Connects to a Meshtastic radio. Supports auto-detect (empty body), explicit serial port, or BLE address. When transport is "ble", connection may fail if WiFi AP is active due to shared radio hardware.
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body MeshtasticConnectAPIRequest false "Connection parameters (all optional for auto-detect)"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid transport or missing parameters"
// @Failure 409 {object} ErrorResponse "BLE unavailable (WiFi AP active)"
// @Failure 500 {object} ErrorResponse "Failed to connect"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/connect [post]
func (h *CommunicationHandler) ConnectMeshtastic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var apiReq MeshtasticConnectAPIRequest
	// Body is optional — ignore decode errors for empty body (auto-detect mode)
	_ = json.NewDecoder(r.Body).Decode(&apiReq)

	// Validate transport if provided
	if apiReq.Transport != "" && apiReq.Transport != "auto" && apiReq.Transport != "serial" && apiReq.Transport != "ble" {
		writeError(w, http.StatusBadRequest, "Transport must be 'auto', 'serial', or 'ble'")
		return
	}

	// Validate that BLE has an address and serial has a port
	if apiReq.Transport == "ble" && apiReq.Address == "" {
		writeError(w, http.StatusBadRequest, "BLE address is required when transport is 'ble'")
		return
	}
	if apiReq.Transport == "serial" && apiReq.Port == "" {
		writeError(w, http.StatusBadRequest, "Port is required when transport is 'serial'")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	halReq := &hal.MeshtasticConnectRequest{
		Port:      apiReq.Port,
		Address:   apiReq.Address,
		Transport: apiReq.Transport,
	}

	if err := h.halClient.ConnectMeshtastic(ctx, halReq); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to connect to Meshtastic radio: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Meshtastic radio connected",
	})
}

// DisconnectMeshtastic godoc
// @Summary Disconnect Meshtastic radio
// @Description Disconnects from the currently connected Meshtastic radio
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to disconnect"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/disconnect [post]
func (h *CommunicationHandler) DisconnectMeshtastic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.DisconnectMeshtastic(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disconnect Meshtastic radio: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Meshtastic radio disconnected",
	})
}

// GetMeshtasticStatus godoc
// @Summary Get Meshtastic status
// @Description Returns Meshtastic radio status including connection state, device info, node count, and channel URL
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.MeshtasticStatus
// @Failure 500 {object} ErrorResponse "Failed to get status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/status [get]
func (h *CommunicationHandler) GetMeshtasticStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetMeshtasticStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Meshtastic status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetMeshtasticNodes godoc
// @Summary Get Meshtastic nodes
// @Description Returns list of discovered Meshtastic nodes in the mesh including signal, battery, and position data
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.MeshtasticNodesResponse
// @Failure 500 {object} ErrorResponse "Failed to get nodes"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/nodes [get]
func (h *CommunicationHandler) GetMeshtasticNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	nodes, err := h.halClient.GetMeshtasticNodes(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Meshtastic nodes: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, nodes)
}

// GetMeshtasticPosition godoc
// @Summary Get Meshtastic position
// @Description Returns GPS position from the connected Meshtastic radio (latitude, longitude, altitude, time)
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.MeshtasticPosition
// @Failure 500 {object} ErrorResponse "Failed to get position"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/position [get]
func (h *CommunicationHandler) GetMeshtasticPosition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	position, err := h.halClient.GetMeshtasticPosition(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Meshtastic position: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, position)
}

// GetMeshtasticMessages godoc
// @Summary Get Meshtastic messages
// @Description Returns message history from the connected Meshtastic radio
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.MeshtasticMessagesResponse
// @Failure 500 {object} ErrorResponse "Failed to get messages"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/messages [get]
func (h *CommunicationHandler) GetMeshtasticMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	messages, err := h.halClient.GetMeshtasticMessages(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Meshtastic messages: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, messages)
}

// SendMeshtasticMessage godoc
// @Summary Send Meshtastic message
// @Description Sends a text message via Meshtastic mesh network. Optionally specify destination node and channel.
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body hal.MeshtasticMessageRequest true "Message with text, optional to (node ID) and channel"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request or empty text"
// @Failure 500 {object} ErrorResponse "Failed to send message"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/messages/send [post]
func (h *CommunicationHandler) SendMeshtasticMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req hal.MeshtasticMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Text == "" {
		writeError(w, http.StatusBadRequest, "Message text is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SendMeshtasticMessage(ctx, &req); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to send Meshtastic message: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Message sent",
	})
}

// SendMeshtasticRaw godoc
// @Summary Send raw Meshtastic packet
// @Description Sends a raw protobuf packet via Meshtastic mesh network. Requires portnum and base64-encoded payload.
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body hal.MeshtasticRawRequest true "Raw packet with portnum, payload, optional to/channel/want_ack"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request or missing portnum/payload"
// @Failure 500 {object} ErrorResponse "Failed to send raw packet"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/messages/send_raw [post]
func (h *CommunicationHandler) SendMeshtasticRaw(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req hal.MeshtasticRawRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.PortNum == 0 {
		writeError(w, http.StatusBadRequest, "Portnum is required")
		return
	}

	if req.Payload == "" {
		writeError(w, http.StatusBadRequest, "Payload is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SendMeshtasticRaw(ctx, &req); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to send Meshtastic raw packet: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Raw packet sent",
	})
}

// GetMeshtasticConfig godoc
// @Summary Get Meshtastic config
// @Description Returns the full radio and module configuration from the connected Meshtastic device handshake data
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Radio and module configuration"
// @Failure 500 {object} ErrorResponse "Failed to get config"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/config [get]
func (h *CommunicationHandler) GetMeshtasticConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	config, err := h.halClient.GetMeshtasticConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Meshtastic config: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, config)
}

// SetMeshtasticChannel godoc
// @Summary Set Meshtastic channel
// @Description Configures a Meshtastic channel with index (0-7), name, PSK, and role. Role must be PRIMARY, SECONDARY, or DISABLED.
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body hal.MeshtasticChannelRequest true "Channel configuration with index, name, role, optional PSK and uplink/downlink"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request, missing name/role, or invalid index"
// @Failure 500 {object} ErrorResponse "Failed to set channel"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/channel [post]
func (h *CommunicationHandler) SetMeshtasticChannel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req hal.MeshtasticChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate index range (0-7)
	if req.Index < 0 || req.Index > 7 {
		writeError(w, http.StatusBadRequest, "Channel index must be between 0 and 7")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Channel name is required")
		return
	}

	if req.Role == "" {
		writeError(w, http.StatusBadRequest, "Channel role is required")
		return
	}

	// Validate role enum
	if req.Role != "PRIMARY" && req.Role != "SECONDARY" && req.Role != "DISABLED" {
		writeError(w, http.StatusBadRequest, "Channel role must be 'PRIMARY', 'SECONDARY', or 'DISABLED'")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SetMeshtasticChannel(ctx, &req); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set Meshtastic channel: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Channel configured",
	})
}

// StreamMeshtasticEvents godoc
// @Summary Stream Meshtastic events
// @Description Opens a Server-Sent Events (SSE) stream for real-time Meshtastic events including incoming messages, node updates, and position reports
// @Tags Communication
// @Produce text/event-stream
// @Success 200 {string} string "SSE event stream"
// @Failure 500 {object} ErrorResponse "Failed to connect to event stream"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/events [get]
func (h *CommunicationHandler) StreamMeshtasticEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	halResp, err := h.halClient.StreamMeshtasticEvents(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to connect to Meshtastic event stream: "+err.Error())
		return
	}

	proxySSE(w, r, halResp)
}

// =============================================================================
// Iridium Endpoints
// =============================================================================

// GetIridiumDevices godoc
// @Summary List Iridium devices
// @Description Returns list of detected Iridium satellite modems (USB serial)
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.IridiumDevicesResponse
// @Failure 500 {object} ErrorResponse "Failed to list Iridium devices"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/devices [get]
func (h *CommunicationHandler) GetIridiumDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetIridiumDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Iridium devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// IridiumConnectRequest represents an Iridium connect request at the API level.
// The port field is optional — if empty, HAL auto-detects the device.
type IridiumConnectRequest struct {
	Port string `json:"port,omitempty"`
}

// ConnectIridium godoc
// @Summary Connect to Iridium modem
// @Description Connects to an Iridium satellite modem. If port is omitted, HAL auto-detects the device.
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body IridiumConnectRequest false "Optional device port for explicit selection"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to connect"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/connect [post]
func (h *CommunicationHandler) ConnectIridium(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req IridiumConnectRequest
	// Body is optional — ignore decode errors for empty body
	_ = json.NewDecoder(r.Body).Decode(&req)

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.ConnectIridium(ctx, req.Port); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to connect to Iridium modem: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Iridium modem connected",
	})
}

// DisconnectIridium godoc
// @Summary Disconnect Iridium modem
// @Description Disconnects from the currently connected Iridium satellite modem
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to disconnect"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/disconnect [post]
func (h *CommunicationHandler) DisconnectIridium(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.DisconnectIridium(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disconnect Iridium modem: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Iridium modem disconnected",
	})
}

// GetIridiumStatus godoc
// @Summary Get Iridium status
// @Description Returns Iridium satellite modem status including connection state and registration
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.IridiumStatus
// @Failure 500 {object} ErrorResponse "Failed to get status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/status [get]
func (h *CommunicationHandler) GetIridiumStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetIridiumStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Iridium status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetIridiumSignal godoc
// @Summary Get Iridium signal strength
// @Description Returns Iridium satellite signal strength (0-5 bars)
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.IridiumSignal
// @Failure 500 {object} ErrorResponse "Failed to get signal"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/signal [get]
func (h *CommunicationHandler) GetIridiumSignal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	signal, err := h.halClient.GetIridiumSignal(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Iridium signal: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, signal)
}

// GetIridiumSignalFast godoc
// @Summary Get Iridium signal strength (cached)
// @Description Returns cached Iridium signal strength via AT+CSQF (~100ms, non-blocking). Safe to poll every 10s. Use /signal for a fresh blocking measurement (up to 60s).
// @Tags Communication
// @Produce json
// @Success 200 {object} hal.IridiumSignal
// @Failure 500 {object} ErrorResponse "Failed to get signal"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/signal/fast [get]
func (h *CommunicationHandler) GetIridiumSignalFast(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	signal, err := h.halClient.GetIridiumSignalFast(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Iridium signal: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, signal)
}

// SendIridiumSBD godoc
// @Summary Send Iridium SBD message
// @Description Sends a Short Burst Data message via Iridium satellite. Supports text (max 120 chars via AT+SBDWT) and binary (max 340 bytes, base64-encoded) formats.
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body hal.IridiumSendRequest true "SBD message with text or binary data and format"
// @Success 200 {object} hal.IridiumSendResponse "SBD transmission result with MO status and MT queue info"
// @Failure 400 {object} ErrorResponse "Invalid request or message too large"
// @Failure 500 {object} ErrorResponse "Failed to send SBD"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/send [post]
func (h *CommunicationHandler) SendIridiumSBD(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req hal.IridiumSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate: must have either text or data
	if req.Text == "" && req.Data == "" {
		writeError(w, http.StatusBadRequest, "Either text or data is required")
		return
	}

	// Validate format field
	if req.Format != "text" && req.Format != "binary" {
		writeError(w, http.StatusBadRequest, "Format must be 'text' or 'binary'")
		return
	}

	// Text messages are limited to 120 chars (AT+SBDWT limit)
	if req.Format == "text" && len(req.Text) > 120 {
		writeError(w, http.StatusBadRequest, "SBD text message exceeds 120 character limit (use binary format for larger payloads)")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	result, err := h.halClient.SendIridiumSBD(ctx, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to send Iridium SBD: "+err.Error())
		return
	}

	// Record SBD credit usage (best-effort, non-blocking)
	if h.db != nil {
		msgBytes := len(req.Text)
		if req.Format == "binary" {
			msgBytes = len(req.Data)
		}
		now := time.Now().Unix()
		h.db.ExecContext(ctx,
			`INSERT INTO sbd_credits (direction, timestamp, mo_status, bytes) VALUES ('mo', ?, ?, ?)`,
			now, result.MOStatus, msgBytes,
		)
	}

	writeJSON(w, http.StatusOK, result)
}

// CheckIridiumMailbox godoc
// @Summary Check Iridium mailbox
// @Description Initiates a mailbox check (SBD session) to retrieve incoming MT messages from the Iridium gateway
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.IridiumMailboxResponse "Mailbox check result with MT message info"
// @Failure 500 {object} ErrorResponse "Failed to check mailbox"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/mailbox_check [post]
func (h *CommunicationHandler) CheckIridiumMailbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	result, err := h.halClient.CheckIridiumMailbox(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check Iridium mailbox: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ReceiveIridiumMessage godoc
// @Summary Receive Iridium message
// @Description Retrieves the most recently received MT (Mobile-Terminated) message from the Iridium modem buffer
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.IridiumReceiveResponse "Received message data with length and format"
// @Failure 500 {object} ErrorResponse "Failed to receive message"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/receive [get]
func (h *CommunicationHandler) ReceiveIridiumMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	result, err := h.halClient.ReceiveIridiumMessage(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to receive Iridium message: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetIridiumMessages godoc
// @Summary Get Iridium messages
// @Description Returns received Iridium SBD messages (alias for receive endpoint)
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.IridiumMessagesResponse
// @Failure 500 {object} ErrorResponse "Failed to get messages"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/messages [get]
func (h *CommunicationHandler) GetIridiumMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	messages, err := h.halClient.GetIridiumMessages(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Iridium messages: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, messages)
}

// IridiumClearRequest represents a request to clear Iridium modem buffers at the API level.
type IridiumClearRequest struct {
	Buffer string `json:"buffer"` // "mo", "mt", or "both"
}

// ClearIridiumBuffers godoc
// @Summary Clear Iridium buffers
// @Description Clears MO (Mobile-Originated) and/or MT (Mobile-Terminated) message buffers on the Iridium modem
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body IridiumClearRequest true "Buffer to clear: mo, mt, or both"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid buffer value"
// @Failure 500 {object} ErrorResponse "Failed to clear buffers"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/clear [post]
func (h *CommunicationHandler) ClearIridiumBuffers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req IridiumClearRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Buffer != "mo" && req.Buffer != "mt" && req.Buffer != "both" {
		writeError(w, http.StatusBadRequest, "Buffer must be 'mo', 'mt', or 'both'")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.ClearIridiumBuffers(ctx, req.Buffer); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to clear Iridium buffers: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Iridium buffers cleared",
	})
}

// StreamIridiumEvents godoc
// @Summary Stream Iridium events
// @Description Opens a Server-Sent Events (SSE) stream for real-time Iridium modem events including signal changes, incoming messages, and connection state transitions
// @Tags Communication
// @Produce text/event-stream
// @Success 200 {string} string "SSE event stream"
// @Failure 500 {object} ErrorResponse "Failed to connect to event stream"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/events [get]
func (h *CommunicationHandler) StreamIridiumEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	halResp, err := h.halClient.StreamIridiumEvents(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to connect to Iridium event stream: "+err.Error())
		return
	}

	proxySSE(w, r, halResp)
}

// =============================================================================
// Iridium Signal History + Credit Tracker Endpoints
// =============================================================================

// signalHistoryPoint is a response DTO for signal history data.
type signalHistoryPoint struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
	Min       float64 `json:"min,omitempty"`
	Max       float64 `json:"max,omitempty"`
	Count     int     `json:"count,omitempty"`
}

// GetIridiumSignalHistory godoc
// @Summary Get Iridium signal history
// @Description Returns historical signal quality readings for the Iridium modem. Supports raw samples or time-bucketed aggregation.
// @Tags Communication
// @Accept json
// @Produce json
// @Param from  query int    false "Start timestamp (Unix epoch seconds, default: 24h ago)"
// @Param to    query int    false "End timestamp (Unix epoch seconds, default: now)"
// @Param interval query string false "Aggregation interval: raw, hour, day" Enums(raw,hour,day)
// @Success 200 {object} map[string]interface{} "Signal history with from/to/interval/history fields"
// @Failure 500 {object} ErrorResponse "Database error"
// @Security BearerAuth
// @Router /communication/iridium/signal/history [get]
func (h *CommunicationHandler) GetIridiumSignalHistory(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"history":  []signalHistoryPoint{},
			"from":     0,
			"to":       0,
			"interval": "raw",
		})
		return
	}

	now := time.Now().Unix()
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	interval := r.URL.Query().Get("interval")

	from := now - 86400 // default: 24h ago
	to := now

	if fromStr != "" {
		if v, err := strconv.ParseInt(fromStr, 10, 64); err == nil {
			from = v
		}
	}
	if toStr != "" {
		if v, err := strconv.ParseInt(toStr, 10, 64); err == nil {
			to = v
		}
	}
	if interval == "" {
		interval = "raw"
	}
	if interval != "raw" && interval != "hour" && interval != "day" {
		interval = "raw"
	}

	points, err := querySignalHistory(h.db, "iridium", from, to, interval)
	if err != nil {
		log.Error().Err(err).Msg("GetIridiumSignalHistory: DB query failed")
		writeError(w, http.StatusInternalServerError, "Failed to query signal history")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"history":  points,
		"from":     from,
		"to":       to,
		"interval": interval,
	})
}

// GetIridiumCredits godoc
// @Summary Get Iridium SBD credit usage
// @Description Returns SBD message counts for today, this month, and all time along with budget settings
// @Tags Communication
// @Produce json
// @Success 200 {object} map[string]interface{} "SBD credit usage and budget"
// @Failure 500 {object} ErrorResponse "Database error"
// @Security BearerAuth
// @Router /communication/iridium/credits [get]
func (h *CommunicationHandler) GetIridiumCredits(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"today": 0, "this_month": 0, "all_time": 0, "budget": 0, "warning_threshold": 0,
		})
		return
	}

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()

	var today, month, allTime int
	h.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM sbd_credits WHERE direction = 'mo' AND mo_status = 0 AND timestamp >= ?`,
		todayStart,
	).Scan(&today)
	h.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM sbd_credits WHERE direction = 'mo' AND mo_status = 0 AND timestamp >= ?`,
		monthStart,
	).Scan(&month)
	h.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM sbd_credits WHERE direction = 'mo' AND mo_status = 0`,
	).Scan(&allTime)

	var budget, warnThresh int
	h.db.QueryRowContext(r.Context(),
		`SELECT CAST(value AS INTEGER) FROM system_config WHERE key = 'sbd_monthly_budget'`,
	).Scan(&budget)
	h.db.QueryRowContext(r.Context(),
		`SELECT CAST(value AS INTEGER) FROM system_config WHERE key = 'sbd_warning_threshold'`,
	).Scan(&warnThresh)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"today":             today,
		"this_month":        month,
		"all_time":          allTime,
		"budget":            budget,
		"warning_threshold": warnThresh,
	})
}

// SetIridiumBudgetRequest is the request body for setting the SBD monthly budget.
type SetIridiumBudgetRequest struct {
	Budget           int `json:"budget"`
	WarningThreshold int `json:"warning_threshold"`
}

// SetIridiumBudget godoc
// @Summary Set Iridium SBD monthly budget
// @Description Sets the monthly SBD credit budget and optional warning threshold
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body SetIridiumBudgetRequest true "Budget settings"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Database error"
// @Security BearerAuth
// @Router /communication/iridium/credits/budget [post]
func (h *CommunicationHandler) SetIridiumBudget(w http.ResponseWriter, r *http.Request) {
	var req SetIridiumBudgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Budget < 0 || req.WarningThreshold < 0 {
		writeError(w, http.StatusBadRequest, "Budget and warning_threshold must be non-negative")
		return
	}

	if h.db == nil {
		writeError(w, http.StatusInternalServerError, "Database unavailable")
		return
	}

	_, err := h.db.ExecContext(r.Context(),
		`INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('sbd_monthly_budget', ?, CURRENT_TIMESTAMP)`,
		req.Budget,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save budget")
		return
	}
	_, err = h.db.ExecContext(r.Context(),
		`INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('sbd_warning_threshold', ?, CURRENT_TIMESTAMP)`,
		req.WarningThreshold,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save warning threshold")
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{Success: true, Message: "Budget updated"})
}

// querySignalHistory queries signal_history with optional time-bucketed aggregation.
func querySignalHistory(db *sqlx.DB, source string, from, to int64, interval string) ([]signalHistoryPoint, error) {
	var rows *sqlx.Rows
	var err error

	switch interval {
	case "hour":
		rows, err = db.Queryx(
			`SELECT (timestamp/3600)*3600 AS ts, AVG(value), MIN(value), MAX(value), COUNT(*)
			 FROM signal_history
			 WHERE source = ? AND timestamp >= ? AND timestamp <= ?
			 GROUP BY ts ORDER BY ts ASC`,
			source, from, to,
		)
	case "day":
		rows, err = db.Queryx(
			`SELECT (timestamp/86400)*86400 AS ts, AVG(value), MIN(value), MAX(value), COUNT(*)
			 FROM signal_history
			 WHERE source = ? AND timestamp >= ? AND timestamp <= ?
			 GROUP BY ts ORDER BY ts ASC`,
			source, from, to,
		)
	default: // raw
		rows, err = db.Queryx(
			`SELECT timestamp, value, NULL, NULL, NULL
			 FROM signal_history
			 WHERE source = ? AND timestamp >= ? AND timestamp <= ?
			 ORDER BY timestamp ASC LIMIT 2000`,
			source, from, to,
		)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []signalHistoryPoint
	for rows.Next() {
		var p signalHistoryPoint
		var minVal, maxVal *float64
		var cnt *int
		if err := rows.Scan(&p.Timestamp, &p.Value, &minVal, &maxVal, &cnt); err != nil {
			return nil, err
		}
		if minVal != nil {
			p.Min = *minVal
		}
		if maxVal != nil {
			p.Max = *maxVal
		}
		if cnt != nil {
			p.Count = *cnt
		}
		points = append(points, p)
	}
	if points == nil {
		points = []signalHistoryPoint{}
	}
	return points, rows.Err()
}

// =============================================================================
// Bluetooth Endpoints
// =============================================================================

// isHardwareAbsentError checks if a HAL error indicates missing hardware
// (vs a transient/internal failure). Hardware absence won't resolve on retry.
func isHardwareAbsentError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no adapter") ||
		strings.Contains(msg, "not available") ||
		strings.Contains(msg, "not detected") ||
		strings.Contains(msg, "no such device") ||
		strings.Contains(msg, "not present")
}

// GetBluetoothStatus godoc
// @Summary Get Bluetooth status
// @Description Returns Bluetooth adapter status and power state
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.BluetoothStatus
// @Failure 500 {object} ErrorResponse "Failed to get Bluetooth status"
// @Failure 503 {object} ErrorResponse "Bluetooth hardware not available"
// @Security BearerAuth
// @Router /communication/bluetooth [get]
func (h *CommunicationHandler) GetBluetoothStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetBluetoothStatus(ctx)
	if err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get Bluetooth status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// PowerOnBluetooth godoc
// @Summary Power on Bluetooth
// @Description Powers on the Bluetooth adapter
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to power on Bluetooth"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/bluetooth/power/on [post]
func (h *CommunicationHandler) PowerOnBluetooth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.PowerOnBluetooth(ctx); err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to power on Bluetooth: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Bluetooth powered on",
	})
}

// PowerOffBluetooth godoc
// @Summary Power off Bluetooth
// @Description Powers off the Bluetooth adapter
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to power off Bluetooth"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/bluetooth/power/off [post]
func (h *CommunicationHandler) PowerOffBluetooth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.PowerOffBluetooth(ctx); err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to power off Bluetooth: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Bluetooth powered off",
	})
}

// GetBluetoothDevices godoc
// @Summary List Bluetooth devices
// @Description Returns list of paired and discovered Bluetooth devices
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.BluetoothDevicesResponse
// @Failure 500 {object} ErrorResponse "Failed to list Bluetooth devices"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/bluetooth/devices [get]
func (h *CommunicationHandler) GetBluetoothDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetBluetoothDevices(ctx)
	if err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get Bluetooth devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// BluetoothScanRequest represents a Bluetooth scan request
type BluetoothScanRequest struct {
	Duration int `json:"duration"` // Scan duration in seconds
}

// BluetoothOverrideRequest represents a Bluetooth override toggle request
type BluetoothOverrideRequest struct {
	Override bool `json:"override"` // Force-enable Bluetooth when built-in WiFi is AP
}

// ScanBluetoothDevices godoc
// @Summary Scan for Bluetooth devices
// @Description Initiates a Bluetooth device discovery scan
// @Tags Communication
// @Accept json
// @Produce json
// @Param request body BluetoothScanRequest false "Scan parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to start scan"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/bluetooth/scan [post]
func (h *CommunicationHandler) ScanBluetoothDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req BluetoothScanRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	duration := 10 // Default 10 seconds
	if req.Duration > 0 {
		duration = req.Duration
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.ScanBluetoothDevices(ctx, duration); err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to start Bluetooth scan: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Bluetooth scan started",
	})
}

// PairBluetoothDevice godoc
// @Summary Pair Bluetooth device
// @Description Initiates pairing with a Bluetooth device
// @Tags Communication
// @Accept json
// @Produce json
// @Param address path string true "Bluetooth device address" example(AA:BB:CC:DD:EE:FF)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Address required"
// @Failure 500 {object} ErrorResponse "Failed to pair"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/bluetooth/pair/{address} [post]
func (h *CommunicationHandler) PairBluetoothDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	address, _ := url.PathUnescape(chi.URLParam(r, "address"))

	if address == "" {
		writeError(w, http.StatusBadRequest, "Bluetooth address is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.PairBluetoothDevice(ctx, address); err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to pair Bluetooth device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Pairing initiated",
	})
}

// ConnectBluetoothDevice godoc
// @Summary Connect Bluetooth device
// @Description Connects to a paired Bluetooth device
// @Tags Communication
// @Accept json
// @Produce json
// @Param address path string true "Bluetooth device address" example(AA:BB:CC:DD:EE:FF)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Address required"
// @Failure 500 {object} ErrorResponse "Failed to connect"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/bluetooth/connect/{address} [post]
func (h *CommunicationHandler) ConnectBluetoothDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	address, _ := url.PathUnescape(chi.URLParam(r, "address"))

	if address == "" {
		writeError(w, http.StatusBadRequest, "Bluetooth address is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.ConnectBluetoothDevice(ctx, address); err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to connect Bluetooth device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Device connected",
	})
}

// DisconnectBluetoothDevice godoc
// @Summary Disconnect Bluetooth device
// @Description Disconnects a connected Bluetooth device
// @Tags Communication
// @Accept json
// @Produce json
// @Param address path string true "Bluetooth device address" example(AA:BB:CC:DD:EE:FF)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Address required"
// @Failure 500 {object} ErrorResponse "Failed to disconnect"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/bluetooth/disconnect/{address} [post]
func (h *CommunicationHandler) DisconnectBluetoothDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	address, _ := url.PathUnescape(chi.URLParam(r, "address"))

	if address == "" {
		writeError(w, http.StatusBadRequest, "Bluetooth address is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.DisconnectBluetoothDevice(ctx, address); err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to disconnect Bluetooth device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Device disconnected",
	})
}

// RemoveBluetoothDevice godoc
// @Summary Remove Bluetooth device
// @Description Removes a paired Bluetooth device
// @Tags Communication
// @Accept json
// @Produce json
// @Param address path string true "Bluetooth device address" example(AA:BB:CC:DD:EE:FF)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Address required"
// @Failure 500 {object} ErrorResponse "Failed to remove"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/bluetooth/devices/{address} [delete]
func (h *CommunicationHandler) RemoveBluetoothDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	address, _ := url.PathUnescape(chi.URLParam(r, "address"))

	if address == "" {
		writeError(w, http.StatusBadRequest, "Bluetooth address is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.RemoveBluetoothDevice(ctx, address); err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth hardware not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to remove Bluetooth device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Device removed",
	})
}

// GetBluetoothCoexistence godoc
// @Summary Get Bluetooth/WiFi coexistence status
// @Description Returns Bluetooth state relative to WiFi AP role for SDIO bus conflict management
// @Tags Communication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} hal.BluetoothCoexistenceStatus
// @Failure 500 {object} ErrorResponse
// @Router /communication/bluetooth/coexistence [get]
func (h *CommunicationHandler) GetBluetoothCoexistence(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status, err := h.halClient.GetBluetoothCoexistence(ctx)
	if err != nil {
		if isHardwareAbsentError(err) {
			writeError(w, http.StatusServiceUnavailable, "Bluetooth not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get coexistence status: "+err.Error())
		return
	}

	// Enrich with override from DB
	override := h.db.QueryRowx("SELECT value FROM system_config WHERE key = 'bluetooth_override'")
	var overrideVal string
	if override.Scan(&overrideVal) == nil && overrideVal == "true" {
		status.OverrideActive = status.ShouldBeDisabled && status.BluetoothEnabled
	}

	writeJSON(w, http.StatusOK, status)
}

// SetBluetoothOverride godoc
// @Summary Set Bluetooth override
// @Description Force-enable/disable Bluetooth when built-in WiFi is AP. Persisted across reboots.
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body BluetoothOverrideRequest true "Override state"
// @Security BearerAuth
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /communication/bluetooth/override [post]
func (h *CommunicationHandler) SetBluetoothOverride(w http.ResponseWriter, r *http.Request) {
	var req BluetoothOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Persist override in system_config
	val := "false"
	if req.Override {
		val = "true"
	}
	_, err := h.db.Exec(
		`INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('bluetooth_override', ?, datetime('now'))`,
		val,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save override: "+err.Error())
		return
	}

	// Apply immediately via HAL rfkill
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if req.Override {
		// Unblock Bluetooth (override — user accepts performance hit)
		_ = h.halClient.SetBluetoothRFKill(ctx, false)
	} else {
		// Re-block if built-in WiFi is AP
		coex, err := h.halClient.GetBluetoothCoexistence(ctx)
		if err == nil && coex.ShouldBeDisabled {
			_ = h.halClient.SetBluetoothRFKill(ctx, true)
		}
	}

	msg := "Bluetooth override disabled"
	if req.Override {
		msg = "Bluetooth override enabled — WiFi AP performance may be affected"
	}
	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: msg,
	})
}

// =============================================================================
// SSE Proxy Helper
// =============================================================================

// proxySSE forwards a Server-Sent Events stream from HAL to the API client.
// The halResp must be an open *http.Response from a HAL SSE endpoint.
// This function blocks until the client disconnects or the HAL stream ends.
// It is reused by both Iridium and Meshtastic event stream handlers.
func proxySSE(w http.ResponseWriter, r *http.Request, halResp *http.Response) {
	defer halResp.Body.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Streaming not supported")
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	scanner := bufio.NewScanner(halResp.Body)
	for {
		select {
		case <-r.Context().Done():
			// Client disconnected
			return
		default:
			if !scanner.Scan() {
				// HAL stream ended or read error
				if err := scanner.Err(); err != nil {
					log.Error().Err(err).Msg("SSE proxy read error")
				}
				return
			}
			line := scanner.Text()
			// Forward the line as-is (SSE lines include "data:", "event:", "id:", or empty lines)
			if _, err := io.WriteString(w, line+"\n"); err != nil {
				// Client write failed (likely disconnected)
				return
			}
			// Flush after every line for low latency
			flusher.Flush()
		}
	}
}

// =============================================================================
// MeshSat Proxy Endpoints (→ meshsat coreapp at :6050)
// =============================================================================

const meshsatBaseURL = "http://cubeos-meshsat:6050"

// GetMeshsatStatus godoc
// @Summary MeshSat service status
// @Description Returns MeshSat coreapp health and database status
// @Tags Communication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/status [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatStatus(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatGET(w, r, "/health")
}

// GetMeshsatMessages godoc
// @Summary Get MeshSat message history
// @Description Returns paginated mesh messages from MeshSat's persistent storage
// @Tags Communication
// @Produce json
// @Param node query string false "Filter by node ID"
// @Param since query string false "Start time (RFC3339)"
// @Param until query string false "End time (RFC3339)"
// @Param portnum query int false "Filter by port number"
// @Param transport query string false "Filter by transport (radio, mqtt, satellite)"
// @Param limit query int false "Results per page (default 50)"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} map[string]interface{}
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/messages [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatMessages(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatGET(w, r, "/api/messages?"+r.URL.RawQuery)
}

// GetMeshsatMessageStats godoc
// @Summary Get MeshSat message statistics
// @Description Returns aggregate message counts by transport and port number
// @Tags Communication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/messages/stats [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatMessageStats(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatGET(w, r, "/api/messages/stats")
}

// GetMeshsatTelemetry godoc
// @Summary Get MeshSat telemetry history
// @Description Returns time-series telemetry data from MeshSat's persistent storage
// @Tags Communication
// @Produce json
// @Param node query string false "Node ID"
// @Param since query string false "Start time (RFC3339)"
// @Param until query string false "End time (RFC3339)"
// @Param limit query int false "Max records (default 100)"
// @Success 200 {object} map[string]interface{}
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/telemetry [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatTelemetry(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatGET(w, r, "/api/telemetry?"+r.URL.RawQuery)
}

// GetMeshsatPositions godoc
// @Summary Get MeshSat position history
// @Description Returns GPS track data from MeshSat's persistent storage
// @Tags Communication
// @Produce json
// @Param node query string false "Node ID"
// @Param since query string false "Start time (RFC3339)"
// @Param until query string false "End time (RFC3339)"
// @Param limit query int false "Max records (default 100)"
// @Success 200 {object} map[string]interface{}
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/positions [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatPositions(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatGET(w, r, "/api/positions?"+r.URL.RawQuery)
}

// GetMeshsatNodes godoc
// @Summary Get mesh nodes via MeshSat
// @Description Returns mesh nodes with signal quality enrichment from MeshSat
// @Tags Communication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/nodes [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatNodes(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatGET(w, r, "/api/nodes")
}

// StreamMeshsatEvents godoc
// @Summary Subscribe to MeshSat events (SSE)
// @Description Proxies Server-Sent Events from the MeshSat coreapp
// @Tags Communication
// @Produce text/event-stream
// @Success 200 {string} string "SSE stream"
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/events [get]
// @Security BearerAuth
func (h *CommunicationHandler) StreamMeshsatEvents(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatSSE(w, r, "/api/events")
}

// =============================================================================
// MeshSat Gateway Proxy Endpoints (→ meshsat coreapp :6050/api/gateways)
// =============================================================================

// GetMeshsatGateways godoc
// @Summary List MeshSat gateways
// @Description Returns status and config of all gateways (MQTT, Iridium) via MeshSat proxy
// @Tags Communication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/gateways [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatGateways(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatGET(w, r, "/api/gateways")
}

// GetMeshsatGateway godoc
// @Summary Get MeshSat gateway status
// @Description Returns status and config for a specific gateway type
// @Tags Communication
// @Produce json
// @Param type path string true "Gateway type (mqtt, iridium)"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/gateways/{type} [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatGateway(w http.ResponseWriter, r *http.Request) {
	gwType := chi.URLParam(r, "type")
	proxyMeshsatGET(w, r, "/api/gateways/"+gwType)
}

// PutMeshsatGateway godoc
// @Summary Configure MeshSat gateway
// @Description Create or update a gateway configuration
// @Tags Communication
// @Accept json
// @Produce json
// @Param type path string true "Gateway type (mqtt, iridium)"
// @Param body body object true "Gateway config with enabled flag"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/gateways/{type} [put]
// @Security BearerAuth
func (h *CommunicationHandler) PutMeshsatGateway(w http.ResponseWriter, r *http.Request) {
	gwType := chi.URLParam(r, "type")
	proxyMeshsatPUT(w, r, "/api/gateways/"+gwType)
}

// DeleteMeshsatGateway godoc
// @Summary Delete MeshSat gateway
// @Description Stop and remove a gateway configuration
// @Tags Communication
// @Produce json
// @Param type path string true "Gateway type (mqtt, iridium)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/gateways/{type} [delete]
// @Security BearerAuth
func (h *CommunicationHandler) DeleteMeshsatGateway(w http.ResponseWriter, r *http.Request) {
	gwType := chi.URLParam(r, "type")
	proxyMeshsatDELETE(w, r, "/api/gateways/"+gwType)
}

// PostMeshsatGatewayStart godoc
// @Summary Start MeshSat gateway
// @Description Start a configured gateway
// @Tags Communication
// @Produce json
// @Param type path string true "Gateway type (mqtt, iridium)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/gateways/{type}/start [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatGatewayStart(w http.ResponseWriter, r *http.Request) {
	gwType := chi.URLParam(r, "type")
	proxyMeshsatPOST(w, r, "/api/gateways/"+gwType+"/start")
}

// PostMeshsatGatewayStop godoc
// @Summary Stop MeshSat gateway
// @Description Stop a running gateway
// @Tags Communication
// @Produce json
// @Param type path string true "Gateway type (mqtt, iridium)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/gateways/{type}/stop [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatGatewayStop(w http.ResponseWriter, r *http.Request) {
	gwType := chi.URLParam(r, "type")
	proxyMeshsatPOST(w, r, "/api/gateways/"+gwType+"/stop")
}

// PostMeshsatGatewayTest godoc
// @Summary Test MeshSat gateway connectivity
// @Description Test connectivity for a configured gateway
// @Tags Communication
// @Produce json
// @Param type path string true "Gateway type (mqtt, iridium)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/gateways/{type}/test [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatGatewayTest(w http.ResponseWriter, r *http.Request) {
	gwType := chi.URLParam(r, "type")
	proxyMeshsatPOST(w, r, "/api/gateways/"+gwType+"/test")
}

// =============================================================================
// MeshSat Iridium Queue — offline compose and priority management
// =============================================================================

// GetMeshsatIridiumQueue godoc
// @Summary Get Iridium outbound queue
// @Description Returns all non-sent, non-cancelled messages in the DLQ
// @Tags Communication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/iridium/queue [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetMeshsatIridiumQueue(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatGET(w, r, "/api/iridium/queue")
}

// PostMeshsatIridiumQueue godoc
// @Summary Queue an Iridium message for opportunistic send
// @Description Enqueues a user-composed message in the DLQ; sent when signal is available (works at 0/5 signal)
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body object{message=string,priority=int} true "Message and priority (0=critical,1=normal,2=low)"
// @Success 201 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/iridium/queue [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatIridiumQueue(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatPOST(w, r, "/api/iridium/queue")
}

// PostMeshsatIridiumQueueCancel godoc
// @Summary Cancel a queued Iridium message
// @Description Cancels a pending DLQ entry so it will not be retried
// @Tags Communication
// @Produce json
// @Param id path int true "DLQ entry ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/iridium/queue/{id}/cancel [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatIridiumQueueCancel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	proxyMeshsatPOST(w, r, "/api/iridium/queue/"+id+"/cancel")
}

// PostMeshsatIridiumQueuePriority godoc
// @Summary Set priority for a queued Iridium message
// @Description Changes the send priority for a pending DLQ entry
// @Tags Communication
// @Accept json
// @Produce json
// @Param id path int true "DLQ entry ID"
// @Param body body object{priority=int} true "Priority (0=critical,1=normal,2=low)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/iridium/queue/{id}/priority [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatIridiumQueuePriority(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	proxyMeshsatPOST(w, r, "/api/iridium/queue/"+id+"/priority")
}

// proxyMeshsatGET forwards a GET request to the MeshSat coreapp and returns the response.
func proxyMeshsatGET(w http.ResponseWriter, r *http.Request, path string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meshsatBaseURL+path, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create request: "+err.Error())
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "MeshSat unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// PostMeshsatAdminReboot godoc
// @Summary Reboot a mesh node via MeshSat
// @Description Proxies a reboot command to a mesh node through MeshSat
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body object{node_id=uint32,delay_secs=int} true "Target node and delay"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/admin/reboot [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatAdminReboot(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatPOST(w, r, "/api/admin/reboot")
}

// PostMeshsatAdminFactoryReset godoc
// @Summary Factory reset a mesh node via MeshSat
// @Description Proxies a factory reset command to a mesh node through MeshSat
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body object{node_id=uint32} true "Target node"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/admin/factory_reset [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatAdminFactoryReset(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatPOST(w, r, "/api/admin/factory_reset")
}

// PostMeshsatAdminTraceroute godoc
// @Summary Traceroute to a mesh node via MeshSat
// @Description Proxies a traceroute request through MeshSat
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body object{node_id=uint32} true "Destination node"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/admin/traceroute [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatAdminTraceroute(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatPOST(w, r, "/api/admin/traceroute")
}

// PostMeshsatConfigRadio godoc
// @Summary Set radio configuration via MeshSat
// @Description Proxies a radio config update through MeshSat to the Meshtastic device
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body object{section=string,config=object} true "Radio config section and data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/config/radio [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatConfigRadio(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatPOST(w, r, "/api/config/radio")
}

// PostMeshsatConfigModule godoc
// @Summary Set module configuration via MeshSat
// @Description Proxies a module config update through MeshSat to the Meshtastic device
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body object{section=string,config=object} true "Module config section and data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/config/module [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatConfigModule(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatPOST(w, r, "/api/config/module")
}

// PostMeshsatWaypoint godoc
// @Summary Send a waypoint via MeshSat
// @Description Proxies a waypoint to the mesh network through MeshSat
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body object{id=uint32,name=string,description=string,latitude=float64,longitude=float64,icon=int,expire=int64} true "Waypoint data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /communication/meshsat/waypoints [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostMeshsatWaypoint(w http.ResponseWriter, r *http.Request) {
	proxyMeshsatPOST(w, r, "/api/waypoints")
}

// proxyMeshsatPOST forwards a POST request to the MeshSat coreapp and returns the response.
func proxyMeshsatPOST(w http.ResponseWriter, r *http.Request, path string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meshsatBaseURL+path, r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create request: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "MeshSat unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyMeshsatPUT forwards a PUT request to the MeshSat coreapp and returns the response.
func proxyMeshsatPUT(w http.ResponseWriter, r *http.Request, path string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, meshsatBaseURL+path, r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create request: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "MeshSat unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyMeshsatDELETE forwards a DELETE request to the MeshSat coreapp and returns the response.
func proxyMeshsatDELETE(w http.ResponseWriter, r *http.Request, path string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, meshsatBaseURL+path, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create request: "+err.Error())
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "MeshSat unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyMeshsatSSE proxies an SSE stream from the MeshSat coreapp.
func proxyMeshsatSSE(w http.ResponseWriter, r *http.Request, path string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, meshsatBaseURL+path, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create request: "+err.Error())
		return
	}
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "MeshSat unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for {
		select {
		case <-r.Context().Done():
			return
		default:
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					log.Error().Err(err).Msg("MeshSat SSE proxy read error")
				}
				return
			}
			line := scanner.Text()
			if _, err := io.WriteString(w, line+"\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// =============================================================================
// Iridium Pass Predictor — SGP4-based pass prediction using Celestrak TLEs
// =============================================================================

// GetIridiumPasses godoc
// @Summary Predict upcoming Iridium satellite passes
// @Description Computes upcoming Iridium NEXT passes over a ground location using SGP4 propagation and cached Celestrak TLEs
// @Tags Communication
// @Produce json
// @Param lat query number true "Observer latitude (degrees, -90 to 90)"
// @Param lon query number true "Observer longitude (degrees, -180 to 180)"
// @Param alt_m query number false "Observer altitude above sea level in meters (default 0)"
// @Param hours query int false "Prediction window in hours (default 24, max 72)"
// @Param min_elevation query number false "Minimum peak elevation to include (degrees, default 10)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 503 {object} map[string]string
// @Router /communication/iridium/passes [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetIridiumPasses(w http.ResponseWriter, r *http.Request) {
	if h.tleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "pass predictor not available")
		return
	}

	latStr := r.URL.Query().Get("lat")
	lonStr := r.URL.Query().Get("lon")
	if latStr == "" || lonStr == "" {
		writeError(w, http.StatusBadRequest, "lat and lon are required")
		return
	}

	lat, err := strconv.ParseFloat(latStr, 64)
	if err != nil || lat < -90 || lat > 90 {
		writeError(w, http.StatusBadRequest, "invalid lat")
		return
	}
	lon, err := strconv.ParseFloat(lonStr, 64)
	if err != nil || lon < -180 || lon > 180 {
		writeError(w, http.StatusBadRequest, "invalid lon")
		return
	}

	altM := 0.0
	if s := r.URL.Query().Get("alt_m"); s != "" {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			altM = v
		}
	}

	hours := 24
	if s := r.URL.Query().Get("hours"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= 72 {
			hours = v
		}
	}

	minElev := 10.0
	if s := r.URL.Query().Get("min_elevation"); s != "" {
		if v, err := strconv.ParseFloat(s, 64); err == nil && v >= 0 {
			minElev = v
		}
	}

	passes, err := h.tleManager.ComputePasses(r.Context(), lat, lon, altM, hours, minElev)
	if err != nil {
		log.Error().Err(err).Msg("GetIridiumPasses: compute failed")
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	count, fetchedAt, _ := h.tleManager.CacheInfo(r.Context())

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"passes":     passes,
		"tle_count":  count,
		"fetched_at": fetchedAt,
		"location":   map[string]float64{"lat": lat, "lon": lon, "alt_m": altM},
	})
}

// PostIridiumPassesRefresh godoc
// @Summary Force refresh of Iridium TLE cache
// @Description Fetches fresh TLEs from Celestrak immediately
// @Tags Communication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 503 {object} map[string]string
// @Router /communication/iridium/passes/refresh [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostIridiumPassesRefresh(w http.ResponseWriter, r *http.Request) {
	if h.tleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "pass predictor not available")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := h.tleManager.RefreshTLEs(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	count, fetchedAt, _ := h.tleManager.CacheInfo(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "refreshed",
		"tle_count":  count,
		"fetched_at": fetchedAt,
	})
}

// GetIridiumLocations godoc
// @Summary List Iridium pass prediction locations
// @Description Returns all saved ground locations (built-in and user-defined)
// @Tags Communication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 503 {object} map[string]string
// @Router /communication/iridium/locations [get]
// @Security BearerAuth
func (h *CommunicationHandler) GetIridiumLocations(w http.ResponseWriter, r *http.Request) {
	if h.tleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "pass predictor not available")
		return
	}

	locs, err := h.tleManager.GetLocations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"locations": locs})
}

// PostIridiumLocation godoc
// @Summary Add a custom pass prediction location
// @Description Saves a user-defined ground location for pass prediction
// @Tags Communication
// @Accept json
// @Produce json
// @Param body body managers.IridiumLocation true "Location: {name, lat, lon, alt_m}"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 503 {object} map[string]string
// @Router /communication/iridium/locations [post]
// @Security BearerAuth
func (h *CommunicationHandler) PostIridiumLocation(w http.ResponseWriter, r *http.Request) {
	if h.tleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "pass predictor not available")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}

	var req struct {
		Name string  `json:"name"`
		Lat  float64 `json:"lat"`
		Lon  float64 `json:"lon"`
		AltM float64 `json:"alt_m"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parse body: "+err.Error())
		return
	}

	id, err := h.tleManager.AddLocation(r.Context(), req.Name, req.Lat, req.Lon, req.AltM)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":     id,
		"status": "created",
	})
}

// DeleteIridiumLocation godoc
// @Summary Delete a custom pass prediction location
// @Description Removes a user-defined location (built-in locations cannot be deleted)
// @Tags Communication
// @Produce json
// @Param id path int true "Location ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 503 {object} map[string]string
// @Router /communication/iridium/locations/{id} [delete]
// @Security BearerAuth
func (h *CommunicationHandler) DeleteIridiumLocation(w http.ResponseWriter, r *http.Request) {
	if h.tleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "pass predictor not available")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	if err := h.tleManager.DeleteLocation(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
