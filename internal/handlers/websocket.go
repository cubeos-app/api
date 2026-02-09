package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"

	"cubeos-api/internal/managers"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins
	},
}

// WSManager manages WebSocket connections
type WSManager struct {
	connections map[*websocket.Conn]bool
	lock        sync.RWMutex
	system      *managers.SystemManager
	network     *managers.NetworkManager
	monitoring  *managers.MonitoringManager
	docker      *managers.DockerManager
}

// NewWSManager creates a new WebSocket manager
func NewWSManager(system *managers.SystemManager, network *managers.NetworkManager, monitoring *managers.MonitoringManager, docker *managers.DockerManager) *WSManager {
	return &WSManager{
		connections: make(map[*websocket.Conn]bool),
		system:      system,
		network:     network,
		monitoring:  monitoring,
		docker:      docker,
	}
}

// Connect adds a new connection
func (m *WSManager) Connect(conn *websocket.Conn) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.connections[conn] = true
	log.Info().Int("connections", len(m.connections)).Msg("WebSocket connected")
}

// Disconnect removes a connection
func (m *WSManager) Disconnect(conn *websocket.Conn) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.connections, conn)
	conn.Close()
	log.Info().Int("connections", len(m.connections)).Msg("WebSocket disconnected")
}

// Count returns the number of active connections
func (m *WSManager) Count() int {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return len(m.connections)
}

// Broadcast sends data to all connections
func (m *WSManager) Broadcast(data interface{}) {
	m.lock.RLock()
	connections := make([]*websocket.Conn, 0, len(m.connections))
	for conn := range m.connections {
		connections = append(connections, conn)
	}
	m.lock.RUnlock()

	message, err := json.Marshal(data)
	if err != nil {
		return
	}

	var disconnected []*websocket.Conn
	for _, conn := range connections {
		err := conn.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			disconnected = append(disconnected, conn)
		}
	}

	for _, conn := range disconnected {
		m.Disconnect(conn)
	}
}

// StartBroadcasting starts the background broadcasting loop
func (m *WSManager) StartBroadcasting(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if m.Count() == 0 {
				continue
			}

			// Get current stats
			stats := m.buildStatsMessage()
			m.Broadcast(stats)

			// Also record to monitoring history
			m.monitoring.RecordStats()
		}
	}
}

func (m *WSManager) buildStatsMessage() map[string]interface{} {
	sysStats := m.system.GetStats()
	interfaces := m.system.GetNetworkInterfaces()
	clients, _ := m.network.GetConnectedClients(context.Background())

	// Build network traffic summary
	networkTraffic := make(map[string]map[string]interface{})
	for _, iface := range interfaces {
		if iface.IsLoopback {
			continue
		}
		networkTraffic[iface.Name] = map[string]interface{}{
			"rx_bytes": iface.RxBytes,
			"tx_bytes": iface.TxBytes,
			"is_up":    iface.IsUp,
		}
	}

	// Get Docker container summary
	var runningContainers int
	var totalContainers int
	containerStats := make([]map[string]interface{}, 0)

	if m.docker != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		containers, err := m.docker.ListContainers(ctx)
		if err == nil {
			totalContainers = len(containers)
			for _, c := range containers {
				if c.State == "running" {
					runningContainers++
					// Get stats for running containers (lightweight)
					containerStats = append(containerStats, map[string]interface{}{
						"id":     c.ID[:12],
						"name":   c.Name,
						"state":  c.State,
						"health": c.Health,
					})
				}
			}
		}
	}

	return map[string]interface{}{
		"type":      "stats",
		"timestamp": time.Now().Format(time.RFC3339),
		"system": map[string]interface{}{
			"cpu": map[string]interface{}{
				"percent": sysStats.CPUPercent,
			},
			"memory": map[string]interface{}{
				"percent": sysStats.MemoryPercent,
				"used":    sysStats.MemoryUsed,
				"total":   sysStats.MemoryTotal,
			},
			"disk": map[string]interface{}{
				"percent": sysStats.DiskPercent,
				"used":    sysStats.DiskUsed,
				"total":   sysStats.DiskTotal,
			},
			"temperature": map[string]interface{}{
				"cpu_temp_c":    sysStats.TemperatureCPU,
				"throttled":     sysStats.Throttled,
				"under_voltage": sysStats.UnderVoltage,
			},
		},
		"network": map[string]interface{}{
			"interfaces":        networkTraffic,
			"clients_connected": len(clients),
		},
		"docker": map[string]interface{}{
			"running":    runningContainers,
			"total":      totalContainers,
			"containers": containerStats,
		},
	}
}

// WSHandlers handles WebSocket endpoints
type WSHandlers struct {
	manager *WSManager
}

// NewWSHandlers creates WebSocket handlers
func NewWSHandlers(manager *WSManager) *WSHandlers {
	return &WSHandlers{manager: manager}
}

// Routes returns the WebSocket routes
func (h *WSHandlers) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/stats", h.StatsWebSocket)
	r.Get("/monitoring", h.MonitoringWebSocket)
	r.Get("/connections", h.GetConnectionCount)

	return r
}

// StatsWebSocket godoc
// @Summary Real-time system stats WebSocket
// @Description WebSocket endpoint for real-time system statistics. Sends JSON messages containing CPU, memory, disk, temperature, network traffic, and Docker container stats at the specified interval.
// @Tags WebSocket
// @Produce json
// @Param interval query integer false "Update interval in seconds (1-60, default: 2)"
// @Success 101 {string} string "Switching Protocols - WebSocket connection established"
// @Router /ws/stats [get]
func (h *WSHandlers) StatsWebSocket(w http.ResponseWriter, r *http.Request) {
	// Get interval from query param
	intervalStr := r.URL.Query().Get("interval")
	interval, _ := strconv.Atoi(intervalStr)
	if interval < 1 || interval > 60 {
		interval = 2
	}

	// Upgrade connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("WebSocket upgrade error")
		return
	}

	h.manager.Connect(conn)
	defer h.manager.Disconnect(conn)

	// Send initial stats immediately
	stats := h.manager.buildStatsMessage()
	if err := conn.WriteJSON(stats); err != nil {
		return
	}

	// Create ticker for this connection's interval
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// Handle incoming messages (for ping/pong)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}()

	// Send stats at interval
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			stats := h.manager.buildStatsMessage()
			if err := conn.WriteJSON(stats); err != nil {
				return
			}
		}
	}
}

// MonitoringWebSocket godoc
// @Summary Real-time monitoring WebSocket
// @Description Alias for /ws/stats - WebSocket endpoint for real-time system monitoring. Sends periodic JSON messages with system, network, and Docker statistics.
// @Tags WebSocket
// @Produce json
// @Param interval query integer false "Update interval in seconds (1-60, default: 2)"
// @Success 101 {string} string "Switching Protocols - WebSocket connection established"
// @Router /ws/monitoring [get]
func (h *WSHandlers) MonitoringWebSocket(w http.ResponseWriter, r *http.Request) {
	h.StatsWebSocket(w, r)
}

// GetConnectionCount godoc
// @Summary Get WebSocket connection count
// @Description Returns the number of active WebSocket connections
// @Tags WebSocket
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "active_connections: number of connected clients"
// @Router /ws/connections [get]
func (h *WSHandlers) GetConnectionCount(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_connections": h.manager.Count(),
	})
}
