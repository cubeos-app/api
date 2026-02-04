package handlers

import (
	"encoding/json"
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

	// Meshtastic
	r.Get("/meshtastic/{port}/status", h.GetMeshtasticStatus)
	r.Get("/meshtastic/{port}/nodes", h.GetMeshtasticNodes)
	r.Post("/meshtastic/{port}/message", h.SendMeshtasticMessage)
	r.Post("/meshtastic/{port}/channel", h.SetMeshtasticChannel)

	// Iridium
	r.Get("/iridium/{port}/status", h.GetIridiumStatus)
	r.Get("/iridium/{port}/signal", h.GetIridiumSignal)
	r.Post("/iridium/{port}/send", h.SendIridiumSBD)
	r.Get("/iridium/{port}/messages", h.GetIridiumMessages)
	r.Post("/iridium/{port}/mailbox", h.CheckIridiumMailbox)

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

// GetMeshtasticStatus godoc
// @Summary Get Meshtastic status
// @Description Returns Meshtastic radio status and configuration
// @Tags Communication
// @Accept json
// @Produce json
// @Param port path string true "Meshtastic device port" example(ttyUSB0)
// @Success 200 {object} hal.MeshtasticStatus
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/{port}/status [get]
func (h *CommunicationHandler) GetMeshtasticStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Meshtastic port is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetMeshtasticStatus(ctx, port)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Meshtastic status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetMeshtasticNodes godoc
// @Summary Get Meshtastic nodes
// @Description Returns list of discovered Meshtastic nodes in the mesh
// @Tags Communication
// @Accept json
// @Produce json
// @Param port path string true "Meshtastic device port" example(ttyUSB0)
// @Success 200 {object} hal.MeshtasticNodesResponse
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get nodes"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/{port}/nodes [get]
func (h *CommunicationHandler) GetMeshtasticNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Meshtastic port is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	nodes, err := h.halClient.GetMeshtasticNodes(ctx, port)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Meshtastic nodes: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, nodes)
}

// MeshtasticMessageRequest represents a Meshtastic message request
type MeshtasticMessageRequest struct {
	Text        string `json:"text"`
	Destination string `json:"destination,omitempty"` // Node ID or "broadcast"
	Channel     int    `json:"channel,omitempty"`     // Default channel 0
}

// SendMeshtasticMessage godoc
// @Summary Send Meshtastic message
// @Description Sends a text message via Meshtastic mesh network
// @Tags Communication
// @Accept json
// @Produce json
// @Param port path string true "Meshtastic device port" example(ttyUSB0)
// @Param request body MeshtasticMessageRequest true "Message to send"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to send message"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/{port}/message [post]
func (h *CommunicationHandler) SendMeshtasticMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Meshtastic port is required")
		return
	}

	var req MeshtasticMessageRequest
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

	if err := h.halClient.SendMeshtasticMessage(ctx, port, req.Text, req.Destination, req.Channel); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to send Meshtastic message: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Message sent",
	})
}

// MeshtasticChannelRequest represents a channel change request
type MeshtasticChannelRequest struct {
	Channel int `json:"channel"`
}

// SetMeshtasticChannel godoc
// @Summary Set Meshtastic channel
// @Description Sets the active Meshtastic channel
// @Tags Communication
// @Accept json
// @Produce json
// @Param port path string true "Meshtastic device port" example(ttyUSB0)
// @Param request body MeshtasticChannelRequest true "Channel number"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to set channel"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/meshtastic/{port}/channel [post]
func (h *CommunicationHandler) SetMeshtasticChannel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Meshtastic port is required")
		return
	}

	var req MeshtasticChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SetMeshtasticChannel(ctx, port, req.Channel); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set Meshtastic channel: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Channel set",
	})
}

// =============================================================================
// Iridium Endpoints
// =============================================================================

// GetIridiumStatus godoc
// @Summary Get Iridium status
// @Description Returns Iridium satellite modem status
// @Tags Communication
// @Accept json
// @Produce json
// @Param port path string true "Iridium device port" example(ttyUSB0)
// @Success 200 {object} hal.IridiumStatus
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get status"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/{port}/status [get]
func (h *CommunicationHandler) GetIridiumStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Iridium port is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetIridiumStatus(ctx, port)
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
// @Param port path string true "Iridium device port" example(ttyUSB0)
// @Success 200 {object} hal.IridiumSignal
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get signal"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/{port}/signal [get]
func (h *CommunicationHandler) GetIridiumSignal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Iridium port is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	signal, err := h.halClient.GetIridiumSignal(ctx, port)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Iridium signal: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, signal)
}

// IridiumSBDRequest represents an Iridium SBD message request
type IridiumSBDRequest struct {
	Message string `json:"message"`
}

// SendIridiumSBD godoc
// @Summary Send Iridium SBD message
// @Description Sends a Short Burst Data message via Iridium satellite
// @Tags Communication
// @Accept json
// @Produce json
// @Param port path string true "Iridium device port" example(ttyUSB0)
// @Param request body IridiumSBDRequest true "SBD message (max 340 bytes)"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to send SBD"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/{port}/send [post]
func (h *CommunicationHandler) SendIridiumSBD(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Iridium port is required")
		return
	}

	var req IridiumSBDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "Message is required")
		return
	}

	if len(req.Message) > 340 {
		writeError(w, http.StatusBadRequest, "SBD message exceeds 340 byte limit")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SendIridiumSBD(ctx, port, req.Message); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to send Iridium SBD: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "SBD message sent",
	})
}

// GetIridiumMessages godoc
// @Summary Get Iridium messages
// @Description Returns received Iridium SBD messages
// @Tags Communication
// @Accept json
// @Produce json
// @Param port path string true "Iridium device port" example(ttyUSB0)
// @Success 200 {object} hal.IridiumMessagesResponse
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to get messages"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/{port}/messages [get]
func (h *CommunicationHandler) GetIridiumMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Iridium port is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	messages, err := h.halClient.GetIridiumMessages(ctx, port)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get Iridium messages: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, messages)
}

// CheckIridiumMailbox godoc
// @Summary Check Iridium mailbox
// @Description Initiates a mailbox check for new incoming messages
// @Tags Communication
// @Accept json
// @Produce json
// @Param port path string true "Iridium device port" example(ttyUSB0)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Port required"
// @Failure 500 {object} ErrorResponse "Failed to check mailbox"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /communication/iridium/{port}/mailbox [post]
func (h *CommunicationHandler) CheckIridiumMailbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	port := chi.URLParam(r, "port")

	if port == "" {
		writeError(w, http.StatusBadRequest, "Iridium port is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.CheckIridiumMailbox(ctx, port); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check Iridium mailbox: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Mailbox check initiated",
	})
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
