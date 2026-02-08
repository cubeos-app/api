package handlers

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
)

// CommunicationHandler handles communication device HTTP requests via HAL.
type CommunicationHandler struct {
	halClient *hal.Client
}

// NewCommunicationHandler creates a new communication handler.
func NewCommunicationHandler(halClient *hal.Client) *CommunicationHandler {
	return &CommunicationHandler{
		halClient: halClient,
	}
}

// Routes returns the communication routes.
func (h *CommunicationHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// GPS
	r.Get("/gps", h.GetGPSDevices)
	r.Get("/gps/{port}/status", h.GetGPSStatus)
	r.Get("/gps/{port}/position", h.GetGPSPosition)

	// Cellular
	r.Get("/cellular", h.GetCellularModems)
	r.Get("/cellular/status", h.GetCellularStatus)
	r.Get("/cellular/{modem}/signal", h.GetCellularSignal)
	r.Post("/cellular/{modem}/connect", h.ConnectCellular)
	r.Post("/cellular/{modem}/disconnect", h.DisconnectCellular)

	// Android Tethering
	r.Get("/cellular/android", h.GetAndroidTetheringStatus)
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
	r.Post("/iridium/send", h.SendIridiumSBD)
	r.Post("/iridium/mailbox_check", h.CheckIridiumMailbox)
	r.Get("/iridium/receive", h.ReceiveIridiumMessage)
	r.Get("/iridium/messages", h.GetIridiumMessages)
	r.Post("/iridium/clear", h.ClearIridiumBuffers)
	r.Get("/iridium/events", h.StreamIridiumEvents)

	// Bluetooth
	r.Get("/bluetooth", h.GetBluetoothStatus)
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
// @Param port path string true "GPS device port" example(ttyUSB0)
// @Success 200 {object} hal.GPSStatus
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get GPS status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/gps/{port}/status [get]
func (h *CommunicationHandler) GetGPSStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

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
// @Param port path string true "GPS device port" example(ttyUSB0)
// @Param timeout query int false "Timeout in seconds" default(10)
// @Success 200 {object} hal.GPSPosition
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get GPS position"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/gps/{port}/position [get]
func (h *CommunicationHandler) GetGPSPosition(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

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
// @Description Returns USB tethering status for connected Android phone
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.AndroidTetheringStatus
// @Failure 500 {object} ErrorResponse "Failed to get status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/cellular/android [get]
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

// SendIridiumSBD godoc
// @Summary Send Iridium SBD message
// @Description Sends a Short Burst Data message via Iridium satellite. Supports text (max 340 bytes) and binary (base64-encoded) formats.
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

	// Text messages are limited to 340 bytes
	if req.Format == "text" && len(req.Text) > 340 {
		writeError(w, http.StatusBadRequest, "SBD text message exceeds 340 byte limit")
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
// Bluetooth Endpoints
// =============================================================================

// GetBluetoothStatus godoc
// @Summary Get Bluetooth status
// @Description Returns Bluetooth adapter status and power state
// @Tags Communication
// @Accept json
// @Produce json
// @Success 200 {object} hal.BluetoothStatus
// @Failure 500 {object} ErrorResponse "Failed to get Bluetooth status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
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
		writeError(w, http.StatusInternalServerError, "Failed to get Bluetooth devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// BluetoothScanRequest represents a Bluetooth scan request
type BluetoothScanRequest struct {
	Duration int `json:"duration"` // Scan duration in seconds
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
	address := chi.URLParam(r, "address")

	if address == "" {
		writeError(w, http.StatusBadRequest, "Bluetooth address is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.PairBluetoothDevice(ctx, address); err != nil {
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
	address := chi.URLParam(r, "address")

	if address == "" {
		writeError(w, http.StatusBadRequest, "Bluetooth address is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.ConnectBluetoothDevice(ctx, address); err != nil {
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
	address := chi.URLParam(r, "address")

	if address == "" {
		writeError(w, http.StatusBadRequest, "Bluetooth address is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.DisconnectBluetoothDevice(ctx, address); err != nil {
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
	address := chi.URLParam(r, "address")

	if address == "" {
		writeError(w, http.StatusBadRequest, "Bluetooth address is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.RemoveBluetoothDevice(ctx, address); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to remove Bluetooth device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Device removed",
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
					log.Printf("SSE proxy read error: %v", err)
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
