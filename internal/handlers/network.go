// Package handlers provides HTTP handlers for the CubeOS API.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// NetworkHandler handles network management endpoints.
type NetworkHandler struct {
	network   *managers.NetworkManager
	halClient *hal.Client
}

// NewNetworkHandler creates a new NetworkHandler instance.
func NewNetworkHandler(network *managers.NetworkManager, halClient *hal.Client) *NetworkHandler {
	return &NetworkHandler{
		network:   network,
		halClient: halClient,
	}
}

// Routes returns the router for network endpoints.
// All routes are mounted under /api/v1/network in main.go
func (h *NetworkHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Network status and mode
	r.Get("/status", h.GetNetworkStatus)
	r.Get("/mode", h.GetNetworkMode) // GET mode - WAS MISSING!
	r.Post("/mode", h.SetNetworkMode)
	r.Get("/modes", h.GetAvailableModes) // List available modes - WAS MISSING!

	// Internet connectivity
	r.Get("/internet", h.GetInternetStatus)
	r.Get("/connectivity", h.CheckConnectivity) // Alias - WAS MISSING!

	// Network interfaces
	r.Get("/interfaces", h.GetInterfaces)
	r.Get("/interfaces/detailed", h.GetInterfacesDetailed)

	// WiFi management
	r.Get("/wifi/scan", h.ScanWiFiNetworks)
	r.Get("/wifi/status", h.GetWiFiStatus) // WAS MISSING!
	r.Post("/wifi/connect", h.ConnectToWiFi)
	r.Post("/wifi/disconnect", h.DisconnectWiFi)    // WAS MISSING!
	r.Get("/wifi/saved", h.GetSavedNetworks)        // WAS MISSING!
	r.Delete("/wifi/saved/{ssid}", h.ForgetNetwork) // WAS MISSING!

	// Access Point management - /wifi/ap/*
	r.Route("/wifi/ap", func(r chi.Router) {
		r.Get("/status", h.GetAPStatus)
		r.Post("/restart", h.RestartAP)
		r.Get("/clients", h.GetAPClients)
		r.Post("/clients/{mac}/kick", h.KickAPClient)
		r.Post("/clients/{mac}/block", h.BlockAPClient)
	})

	// AP configuration - /ap/* (legacy + extended)
	r.Route("/ap", func(r chi.Router) {
		r.Get("/config", h.GetAPConfig)
		r.Put("/config", h.UpdateAPConfig)
		r.Post("/start", h.StartAP) // WAS MISSING!
		r.Post("/stop", h.StopAP)   // WAS MISSING!
	})

	// Traffic statistics
	r.Get("/traffic", h.GetTrafficStats)
	r.Get("/traffic/{iface}/history", h.GetTrafficHistory)

	// Network Settings and VPN overlay
	r.Get("/settings", h.GetNetworkSettings)
	r.Put("/settings", h.UpdateNetworkSettings)
	r.Get("/vpn/mode", h.GetVPNMode)
	r.Post("/vpn/mode", h.SetVPNMode)
	r.Post("/warning/dismiss", h.DismissServerModeWarning)

	// DNS configuration
	r.Get("/dns", h.GetDNSConfig)
	r.Post("/dns", h.SetDNSConfig)

	return r
}

// =============================================================================
// Network Status and Mode
// =============================================================================

// GetNetworkStatus godoc
// @Summary Get network status
// @Description Returns current network status including mode, connectivity, and interface states
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} managers.NetworkStatus "Network status"
// @Failure 500 {object} ErrorResponse "Failed to get status"
// @Router /network/status [get]
func (h *NetworkHandler) GetNetworkStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status, err := h.network.GetStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// GetNetworkMode godoc
// @Summary Get current network mode
// @Description Returns the current network operating mode
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Current network mode"
// @Router /network/mode [get]
func (h *NetworkHandler) GetNetworkMode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status, err := h.network.GetStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mode":        status.Mode,
		"description": getModeDescription(string(status.Mode)),
	})
}

// SetNetworkMode godoc
// @Summary Set network mode
// @Description Changes the network operating mode (offline, online_eth, online_wifi, server_eth, server_wifi)
// @Tags Network
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "Network mode configuration" example({"mode": "online_eth"})
// @Success 200 {object} map[string]interface{} "Mode changed with status"
// @Failure 400 {object} ErrorResponse "Invalid mode or missing parameters"
// @Failure 500 {object} ErrorResponse "Failed to change mode"
// @Router /network/mode [post]
func (h *NetworkHandler) SetNetworkMode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Mode     string `json:"mode"`
		SSID     string `json:"ssid,omitempty"`
		Password string `json:"password,omitempty"`

		// Static IP override (T13 — Network Modes Batch 3)
		UseStaticIP        bool   `json:"use_static_ip,omitempty"`
		StaticIP           string `json:"static_ip,omitempty"`
		StaticNetmask      string `json:"static_netmask,omitempty"`
		StaticGateway      string `json:"static_gateway,omitempty"`
		StaticDNSPrimary   string `json:"static_dns_primary,omitempty"`
		StaticDNSSecondary string `json:"static_dns_secondary,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Mode == "" {
		writeError(w, http.StatusBadRequest, "Network mode is required")
		return
	}

	validModes := map[string]bool{
		"offline":     true,
		"online_eth":  true,
		"online_wifi": true,
		"server_eth":  true,
		"server_wifi": true,
	}

	if !validModes[req.Mode] {
		writeError(w, http.StatusBadRequest, "Invalid network mode. Valid modes: offline, online_eth, online_wifi, server_eth, server_wifi")
		return
	}

	if (req.Mode == "online_wifi" || req.Mode == "server_wifi") && req.SSID == "" {
		writeError(w, http.StatusBadRequest, "SSID is required for WiFi modes")
		return
	}

	// Validate static IP fields if enabled
	if req.UseStaticIP {
		if req.StaticIP == "" {
			writeError(w, http.StatusBadRequest, "static_ip is required when use_static_ip is true")
			return
		}
		if req.StaticGateway == "" {
			writeError(w, http.StatusBadRequest, "static_gateway is required when use_static_ip is true")
			return
		}
		if req.Mode == "offline" {
			writeError(w, http.StatusBadRequest, "Static IP is not applicable in offline mode (no upstream interface)")
			return
		}
	}

	var mode models.NetworkMode
	switch req.Mode {
	case "offline":
		mode = models.NetworkModeOffline
	case "online_eth":
		mode = models.NetworkModeOnlineETH
	case "online_wifi":
		mode = models.NetworkModeOnlineWiFi
	case "server_eth":
		mode = models.NetworkModeServerETH
	case "server_wifi":
		mode = models.NetworkModeServerWiFi
	}

	// Build static IP config
	netmask := req.StaticNetmask
	if netmask == "" {
		netmask = "255.255.255.0"
	}
	staticIP := models.StaticIPConfig{
		UseStaticIP:        req.UseStaticIP,
		StaticIPAddress:    req.StaticIP,
		StaticIPNetmask:    netmask,
		StaticIPGateway:    req.StaticGateway,
		StaticDNSPrimary:   req.StaticDNSPrimary,
		StaticDNSSecondary: req.StaticDNSSecondary,
	}

	if err := h.network.SetMode(ctx, mode, req.SSID, req.Password, staticIP); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	status, _ := h.network.GetStatus(ctx)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Network mode changed to " + req.Mode,
		"status":  status,
	})
}

// GetAvailableModes godoc
// @Summary Get available network modes
// @Description Returns list of available network operating modes
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Available modes"
// @Router /network/modes [get]
func (h *NetworkHandler) GetAvailableModes(w http.ResponseWriter, r *http.Request) {
	modes := []map[string]interface{}{
		{"id": "offline", "name": "Offline (AP Only)", "description": "Air-gapped access point mode"},
		{"id": "online_eth", "name": "Online via Ethernet", "description": "AP + NAT via Ethernet uplink"},
		{"id": "online_wifi", "name": "Online via WiFi", "description": "AP + NAT via USB WiFi dongle"},
		{"id": "server_eth", "name": "Server via Ethernet", "description": "No AP, direct Ethernet connection"},
		{"id": "server_wifi", "name": "Server via WiFi", "description": "No AP, direct WiFi connection"},
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"modes": modes,
		"count": len(modes),
	})
}

// =============================================================================
// WiFi Management
// =============================================================================

// ScanWiFiNetworks godoc
// @Summary Scan WiFi networks
// @Description Scans for available WiFi networks in range
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Param interface query string false "WiFi interface to use for scanning"
// @Success 200 {object} map[string]interface{} "Available WiFi networks"
// @Failure 500 {object} ErrorResponse "Failed to scan networks"
// @Router /network/wifi/scan [get]
func (h *NetworkHandler) ScanWiFiNetworks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	networks, err := h.network.ScanWiFiNetworks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"networks": networks,
		"count":    len(networks),
	})
}

// GetWiFiStatus godoc
// @Summary Get WiFi status
// @Description Returns current WiFi connection status
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "WiFi status"
// @Router /network/wifi/status [get]
func (h *NetworkHandler) GetWiFiStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status, err := h.network.GetWiFiStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// ConnectToWiFi godoc
// @Summary Connect to WiFi network
// @Description Connects to a WiFi network as a client
// @Tags Network
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "WiFi credentials" example({"ssid": "MyNetwork", "password": "secret"})
// @Success 200 {object} map[string]interface{} "Connection successful"
// @Failure 400 {object} ErrorResponse "Invalid request or missing SSID"
// @Failure 500 {object} ErrorResponse "Failed to connect"
// @Router /network/wifi/connect [post]
func (h *NetworkHandler) ConnectToWiFi(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		SSID      string `json:"ssid"`
		Password  string `json:"password"`
		Interface string `json:"interface,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SSID == "" {
		writeError(w, http.StatusBadRequest, "SSID is required")
		return
	}

	if err := h.network.ConnectToWiFi(ctx, req.SSID, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connected to WiFi network: " + req.SSID,
	})
}

// DisconnectWiFi godoc
// @Summary Disconnect from WiFi
// @Description Disconnects from the current WiFi network
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Disconnected"
// @Failure 500 {object} ErrorResponse "Failed to disconnect"
// @Router /network/wifi/disconnect [post]
func (h *NetworkHandler) DisconnectWiFi(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.network.DisconnectWiFi(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Disconnected from WiFi",
	})
}

// GetSavedNetworks godoc
// @Summary Get saved WiFi networks
// @Description Returns list of saved WiFi network configurations
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Saved networks"
// @Router /network/wifi/saved [get]
func (h *NetworkHandler) GetSavedNetworks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	networks, err := h.network.GetSavedNetworks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"networks": networks,
		"count":    len(networks),
	})
}

// ForgetNetwork godoc
// @Summary Forget saved WiFi network
// @Description Removes a saved WiFi network configuration
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Param ssid path string true "Network SSID"
// @Success 200 {object} map[string]interface{} "Network forgotten"
// @Failure 500 {object} ErrorResponse "Failed to forget network"
// @Router /network/wifi/saved/{ssid} [delete]
func (h *NetworkHandler) ForgetNetwork(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ssid := chi.URLParam(r, "ssid")
	if err := h.network.ForgetNetwork(ctx, ssid); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Network forgotten: " + ssid,
	})
}

// =============================================================================
// Access Point Management
// =============================================================================

// GetAPStatus godoc
// @Summary Get AP status
// @Description Returns detailed WiFi access point status
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "AP status"
// @Failure 500 {object} ErrorResponse "Failed to get AP status"
// @Router /network/wifi/ap/status [get]
func (h *NetworkHandler) GetAPStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get live AP status from HAL first (real SSID/channel from hostapd)
	var ssid string
	var channel int
	var hidden bool
	var hostapdRunning bool

	if h.halClient != nil {
		halStatus, err := h.halClient.GetAPStatus(ctx)
		if err == nil && halStatus != nil {
			ssid = halStatus.SSID
			channel = halStatus.Channel
			hostapdRunning = halStatus.Active
		}
	}

	// Fill gaps from config if HAL didn't provide complete data
	if ssid == "" {
		config, err := h.network.GetAPConfig(ctx)
		if err == nil && config != nil {
			ssid = config.SSID
			channel = config.Channel
			hidden = config.Hidden
		}
	}

	// Check hostapd service status if HAL AP status didn't report it
	if !hostapdRunning && h.halClient != nil {
		status, err := h.halClient.GetServiceStatus(ctx, "hostapd")
		if err == nil && status != nil {
			hostapdRunning = status.Active
		}
	}

	clients, _ := h.network.GetConnectedClients(ctx)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":   true,
		"running":   hostapdRunning,
		"ssid":      ssid,
		"channel":   channel,
		"interface": "wlan0",
		"hidden":    hidden,
		"clients":   len(clients),
	})
}

// StartAP godoc
// @Summary Start access point
// @Description Starts the WiFi access point
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "AP started"
// @Failure 500 {object} ErrorResponse "Failed to start AP"
// @Router /network/ap/start [post]
func (h *NetworkHandler) StartAP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	if err := h.halClient.StartService(ctx, "hostapd"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to start AP: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Access point started",
	})
}

// StopAP godoc
// @Summary Stop access point
// @Description Stops the WiFi access point
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "AP stopped"
// @Failure 500 {object} ErrorResponse "Failed to stop AP"
// @Router /network/ap/stop [post]
func (h *NetworkHandler) StopAP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	if err := h.halClient.StopService(ctx, "hostapd"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to stop AP: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Access point stopped",
	})
}

// RestartAP godoc
// @Summary Restart access point
// @Description Restarts the WiFi access point (hostapd service)
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "AP restarted"
// @Failure 500 {object} ErrorResponse "Failed to restart AP"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /network/wifi/ap/restart [post]
func (h *NetworkHandler) RestartAP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	if err := h.halClient.RestartService(ctx, "hostapd"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to restart AP: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Access point restarted",
	})
}

// GetAPClients godoc
// @Summary List AP clients
// @Description Returns list of clients connected to the access point
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Connected clients"
// @Failure 500 {object} ErrorResponse "Failed to get clients"
// @Router /network/wifi/ap/clients [get]
func (h *NetworkHandler) GetAPClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clients, err := h.network.GetConnectedClients(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

// KickAPClient godoc
// @Summary Kick AP client
// @Description Disconnects a client from the access point
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Param mac path string true "Client MAC address"
// @Success 200 {object} map[string]interface{} "Client disconnected"
// @Failure 400 {object} ErrorResponse "Invalid MAC address"
// @Failure 500 {object} ErrorResponse "Failed to kick client"
// @Router /network/wifi/ap/clients/{mac}/kick [post]
func (h *NetworkHandler) KickAPClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mac := chi.URLParam(r, "mac")
	if mac == "" || !isValidMAC(mac) {
		writeError(w, http.StatusBadRequest, "Invalid MAC address")
		return
	}
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	if err := h.halClient.KickAPClient(ctx, mac); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to kick client: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Client " + mac + " disconnected",
	})
}

// BlockAPClient godoc
// @Summary Block AP client
// @Description Blocks a client from connecting to the access point
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Param mac path string true "Client MAC address"
// @Success 200 {object} map[string]interface{} "Client blocked"
// @Failure 400 {object} ErrorResponse "Invalid MAC address"
// @Failure 500 {object} ErrorResponse "Failed to block client"
// @Router /network/wifi/ap/clients/{mac}/block [post]
func (h *NetworkHandler) BlockAPClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mac := chi.URLParam(r, "mac")
	if mac == "" || !isValidMAC(mac) {
		writeError(w, http.StatusBadRequest, "Invalid MAC address")
		return
	}
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	if err := h.halClient.BlockAPClient(ctx, mac); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to block client: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Client " + mac + " blocked",
	})
}

// =============================================================================
// Legacy AP Configuration
// =============================================================================

// GetAPConfig godoc
// @Summary Get AP configuration
// @Description Returns the access point configuration
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} managers.APConfig "AP configuration"
// @Failure 500 {object} ErrorResponse "Failed to get config"
// @Router /network/ap/config [get]
func (h *NetworkHandler) GetAPConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	config, err := h.network.GetAPConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, config)
}

// UpdateAPConfig godoc
// @Summary Update AP configuration
// @Description Updates the access point configuration (SSID, password, channel, hidden)
// @Tags Network
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param config body object true "AP configuration"
// @Success 200 {object} map[string]interface{} "Configuration updated"
// @Failure 400 {object} ErrorResponse "Invalid configuration"
// @Failure 500 {object} ErrorResponse "Failed to update config"
// @Failure 501 {object} ErrorResponse "Not implemented — HAL support required"
// @Router /network/ap/config [put]
func (h *NetworkHandler) UpdateAPConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		SSID     string `json:"ssid"`
		Password string `json:"password"`
		Channel  int    `json:"channel"`
		Hidden   bool   `json:"hidden"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SSID == "" {
		writeError(w, http.StatusBadRequest, "SSID is required")
		return
	}

	if len(req.Password) > 0 && len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	if err := h.network.UpdateAPConfig(ctx, req.SSID, req.Password, req.Channel, req.Hidden); err != nil {
		// Check if this is a "not implemented" error from the manager
		if strings.Contains(err.Error(), "not yet implemented") || strings.Contains(err.Error(), "not implemented") {
			writeError(w, http.StatusNotImplemented, "AP configuration update requires HAL support which is not yet available")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "AP configuration updated",
	})
}

// =============================================================================
// Network Interfaces
// =============================================================================

// GetInterfaces godoc
// @Summary List network interfaces
// @Description Returns a list of network interfaces
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Network interfaces"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /network/interfaces [get]
func (h *NetworkHandler) GetInterfaces(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	interfaces, err := h.halClient.ListInterfaces(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list interfaces: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interfaces": interfaces,
	})
}

// GetInterfacesDetailed godoc
// @Summary Get detailed network interfaces
// @Description Returns detailed information about all network interfaces
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Detailed network interfaces"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /network/interfaces/detailed [get]
func (h *NetworkHandler) GetInterfacesDetailed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	interfaces, err := h.halClient.ListInterfaces(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list interfaces: "+err.Error())
		return
	}

	type DetailedInterface struct {
		Name          string   `json:"name"`
		IsUp          bool     `json:"is_up"`
		MACAddress    string   `json:"mac_address"`
		IPv4Addresses []string `json:"ipv4_addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
		MTU           int      `json:"mtu"`
		Type          string   `json:"type"`
		Role          string   `json:"role"`
		IsWireless    bool     `json:"is_wireless"`
	}

	var detailed []DetailedInterface
	for _, iface := range interfaces {
		di := DetailedInterface{
			Name:          iface.Name,
			IsUp:          iface.IsUp,
			MACAddress:    iface.MACAddress,
			IPv4Addresses: iface.IPv4Addresses,
			IPv6Addresses: iface.IPv6Addresses,
			MTU:           iface.MTU,
		}

		switch {
		case iface.Name == "lo":
			di.Type = "loopback"
			di.Role = "system"
		case strings.HasPrefix(iface.Name, "eth"):
			di.Type = "ethernet"
			di.Role = "wan"
		case iface.Name == "wlan0":
			di.Type = "wifi"
			di.Role = "ap"
			di.IsWireless = true
		case strings.HasPrefix(iface.Name, "wlan") || strings.HasPrefix(iface.Name, "wlx"):
			di.Type = "wifi"
			di.Role = "client"
			di.IsWireless = true
		case strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "br-"):
			di.Type = "bridge"
			di.Role = "container"
		case strings.HasPrefix(iface.Name, "veth"):
			di.Type = "virtual"
			di.Role = "container"
		default:
			di.Type = "unknown"
			di.Role = "unused"
		}

		detailed = append(detailed, di)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interfaces": detailed,
		"count":      len(detailed),
	})
}

// =============================================================================
// Internet Connectivity
// =============================================================================

// GetInternetStatus godoc
// @Summary Check internet connectivity
// @Description Tests internet connectivity and returns status
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Connectivity status"
// @Router /network/internet [get]
func (h *NetworkHandler) GetInternetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.halClient != nil {
		status, err := h.halClient.GetNetworkStatus(ctx)
		if err == nil {
			resp := map[string]interface{}{
				"connected":    status["internet"],
				"check_target": "1.1.1.1",
				"target_name":  "1.1.1.1",
				"method":       "hal",
			}
			// Pass through RTT if HAL returned it
			if rtt, ok := status["rtt_ms"]; ok {
				resp["rtt_ms"] = rtt
			}
			if target, ok := status["check_target"]; ok {
				targetStr := fmt.Sprintf("%v", target)
				resp["check_target"] = targetStr
				resp["target_name"] = targetStr
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	netStatus, err := h.network.GetStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"connected":    netStatus.Internet,
		"check_target": "1.1.1.1",
		"target_name":  "1.1.1.1",
		"method":       "manager",
	})
}

// CheckConnectivity godoc
// @Summary Check connectivity
// @Description Tests network connectivity to various endpoints
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Connectivity status"
// @Router /network/connectivity [get]
func (h *NetworkHandler) CheckConnectivity(w http.ResponseWriter, r *http.Request) {
	h.GetInternetStatus(w, r)
}

// =============================================================================
// Traffic Statistics
// =============================================================================

// GetTrafficStats godoc
// @Summary Get traffic statistics
// @Description Returns current traffic statistics for all interfaces as an array
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Traffic statistics array"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /network/traffic [get]
func (h *NetworkHandler) GetTrafficStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	stats, err := h.halClient.GetTrafficStats(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get traffic stats: "+err.Error())
		return
	}

	// Transform HAL's map format {interfaces: {eth0: {...}}} into an array
	// that the frontend expects: [{interface: "eth0", rx_bytes: ..., ...}]
	var statsArray []map[string]interface{}
	if stats != nil && stats.Interfaces != nil {
		for name, iface := range stats.Interfaces {
			statsArray = append(statsArray, map[string]interface{}{
				"interface":  name,
				"rx_bytes":   iface.RXBytes,
				"tx_bytes":   iface.TXBytes,
				"rx_packets": iface.RXPackets,
				"tx_packets": iface.TXPackets,
				"rx_errors":  iface.RXErrors,
				"tx_errors":  iface.TXErrors,
				"rx_dropped": iface.RXDropped,
				"tx_dropped": iface.TXDropped,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"stats":  statsArray,
		"source": stats.Source,
	})
}

// GetTrafficHistory godoc
// @Summary Get traffic history
// @Description Returns historical traffic data for a specific interface
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Param iface path string true "Interface name"
// @Param duration query string false "History duration" default(1h)
// @Success 200 {object} map[string]interface{} "Traffic history"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /network/traffic/{iface}/history [get]
func (h *NetworkHandler) GetTrafficHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		writeError(w, http.StatusBadRequest, "Interface name is required")
		return
	}
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}
	duration := r.URL.Query().Get("duration")
	if duration == "" {
		duration = "1h"
	}
	history, err := h.halClient.GetTrafficHistory(ctx, iface, duration)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get traffic history: "+err.Error())
		return
	}

	// Normalize field names for frontend (rx_rate → rx_rate_bps)
	var normalizedHistory []map[string]interface{}
	for _, point := range history {
		normalizedHistory = append(normalizedHistory, map[string]interface{}{
			"timestamp":   point.Timestamp,
			"rx_bytes":    point.RxBytes,
			"tx_bytes":    point.TxBytes,
			"rx_rate_bps": point.RxRate,
			"tx_rate_bps": point.TxRate,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interface": iface,
		"duration":  duration,
		"history":   normalizedHistory,
	})
}

// =============================================================================
// Network Settings and VPN
// =============================================================================

// GetNetworkSettings godoc
// @Summary Get network settings
// @Description Returns current network configuration
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.NetworkConfig "Network configuration"
// @Router /network/settings [get]
func (h *NetworkHandler) GetNetworkSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	config, err := h.network.GetNetworkConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, config)
}

// UpdateNetworkSettings godoc
// @Summary Update network settings
// @Description Updates network configuration
// @Tags Network
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param settings body object true "Network settings"
// @Success 200 {object} models.NetworkConfig "Updated configuration"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to update settings"
// @Router /network/settings [put]
func (h *NetworkHandler) UpdateNetworkSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		GatewayIP        string `json:"gateway_ip"`
		Subnet           string `json:"subnet"`
		DHCPRangeStart   string `json:"dhcp_range_start"`
		DHCPRangeEnd     string `json:"dhcp_range_end"`
		FallbackStaticIP string `json:"fallback_static_ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	config, err := h.network.GetNetworkConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if req.GatewayIP != "" {
		config.GatewayIP = req.GatewayIP
	}
	if req.Subnet != "" {
		config.Subnet = req.Subnet
	}
	if req.DHCPRangeStart != "" {
		config.DHCPRangeStart = req.DHCPRangeStart
	}
	if req.DHCPRangeEnd != "" {
		config.DHCPRangeEnd = req.DHCPRangeEnd
	}
	if req.FallbackStaticIP != "" {
		config.FallbackStaticIP = req.FallbackStaticIP
	}

	if err := h.network.UpdateNetworkConfig(ctx, config); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, config)
}

// GetVPNMode godoc
// @Summary Get VPN mode
// @Description Returns current VPN overlay mode
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Current VPN mode"
// @Router /network/vpn/mode [get]
func (h *NetworkHandler) GetVPNMode(w http.ResponseWriter, r *http.Request) {
	mode := h.network.GetCurrentVPNMode()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"vpn_mode": mode,
	})
}

// SetVPNMode godoc
// @Summary Set VPN mode
// @Description Sets VPN overlay mode for network traffic
// @Tags Network
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "VPN mode configuration"
// @Success 200 {object} map[string]interface{} "VPN mode updated"
// @Failure 400 {object} ErrorResponse "Invalid mode"
// @Failure 500 {object} ErrorResponse "Failed to set VPN mode"
// @Router /network/vpn/mode [post]
func (h *NetworkHandler) SetVPNMode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Mode     string `json:"mode"`
		ConfigID *int64 `json:"config_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	validModes := map[string]bool{"none": true, "wireguard": true, "openvpn": true, "tor": true}
	if !validModes[req.Mode] {
		writeError(w, http.StatusBadRequest, "invalid VPN mode: must be none, wireguard, openvpn, or tor")
		return
	}

	if (req.Mode == "wireguard" || req.Mode == "openvpn") && req.ConfigID == nil {
		writeError(w, http.StatusBadRequest, "config_id required for wireguard/openvpn modes")
		return
	}

	var configID int64
	if req.ConfigID != nil {
		configID = *req.ConfigID
	}

	if err := h.network.SetVPNMode(ctx, models.VPNMode(req.Mode), req.ConfigID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"vpn_mode":  req.Mode,
		"config_id": configID,
		"message":   "VPN mode updated",
	})
}

// DismissServerModeWarning godoc
// @Summary Dismiss server mode warning
// @Description Dismisses the warning shown when using server network modes
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Warning dismissed"
// @Router /network/warning/dismiss [post]
func (h *NetworkHandler) DismissServerModeWarning(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.network.DismissServerModeWarning(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Server mode warning dismissed",
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

func isValidMAC(mac string) bool {
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		for _, c := range part {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func getModeDescription(mode string) string {
	descriptions := map[string]string{
		"offline":     "Air-gapped access point mode",
		"online_eth":  "AP + NAT via Ethernet uplink",
		"online_wifi": "AP + NAT via USB WiFi dongle",
		"server_eth":  "No AP, direct Ethernet connection",
		"server_wifi": "No AP, direct WiFi connection",
	}
	if desc, ok := descriptions[mode]; ok {
		return desc
	}
	return "Unknown mode"
}

// =============================================================================
// DNS Configuration
// =============================================================================

// GetDNSConfig godoc
// @Summary Get DNS configuration
// @Description Returns current DNS server configuration
// @Tags Network
// @Produce json
// @Security BearerAuth
// @Success 200 {object} managers.DNSConfig "DNS configuration"
// @Failure 500 {object} ErrorResponse "Failed to get DNS config"
// @Router /network/dns [get]
func (h *NetworkHandler) GetDNSConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	config, err := h.network.GetDNSConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get DNS config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, config)
}

// SetDNSConfig godoc
// @Summary Set DNS configuration
// @Description Updates DNS server configuration
// @Tags Network
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body managers.DNSConfig true "DNS configuration"
// @Success 200 {object} map[string]interface{} "success, config"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to set DNS config"
// @Router /network/dns [post]
func (h *NetworkHandler) SetDNSConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req managers.DNSConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.PrimaryDNS == "" && len(req.DNSServers) == 0 {
		writeError(w, http.StatusBadRequest, "At least one DNS server is required (primary_dns or dns_servers)")
		return
	}

	// If only dns_servers provided, use first as primary
	if req.PrimaryDNS == "" && len(req.DNSServers) > 0 {
		req.PrimaryDNS = req.DNSServers[0]
		if len(req.DNSServers) > 1 {
			req.SecondaryDNS = req.DNSServers[1]
		}
	}

	if err := h.network.SetDNSConfig(ctx, &req); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set DNS config: "+err.Error())
		return
	}

	// Read back current config to confirm
	current, err := h.network.GetDNSConfig(ctx)
	if err != nil {
		// Write succeeded but read-back failed — still report success
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"config":  req,
			"message": "DNS configuration updated",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"config":  current,
		"message": "DNS configuration updated",
	})
}
