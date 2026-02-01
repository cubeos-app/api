package managers

import (
	"sync"
	"time"

	"cubeos-api/internal/models"
)

// MonitoringManager handles stats history and alerts
type MonitoringManager struct {
	system  *SystemManager
	network *NetworkManager

	history     []models.StatsSnapshot
	historyLock sync.RWMutex
	maxHistory  int

	thresholds     map[string]float64
	thresholdsLock sync.RWMutex
}

// NewMonitoringManager creates a new MonitoringManager
func NewMonitoringManager(system *SystemManager, network *NetworkManager) *MonitoringManager {
	return &MonitoringManager{
		system:     system,
		network:    network,
		history:    make([]models.StatsSnapshot, 0, 3600),
		maxHistory: 3600, // 1 hour at 1 sample/second, or 2 hours at 2s interval
		thresholds: map[string]float64{
			"cpu_percent":    90,
			"memory_percent": 90,
			"temperature_c":  80,
			"disk_percent":   95,
		},
	}
}

// RecordStats records current stats to history
func (m *MonitoringManager) RecordStats() {
	stats := m.system.GetStats()

	snapshot := models.StatsSnapshot{
		Timestamp:     time.Now(),
		CPUPercent:    stats.CPUPercent,
		MemoryPercent: stats.MemoryPercent,
		Temperature:   stats.TemperatureCPU,
	}

	m.historyLock.Lock()
	defer m.historyLock.Unlock()

	m.history = append(m.history, snapshot)
	if len(m.history) > m.maxHistory {
		m.history = m.history[len(m.history)-m.maxHistory:]
	}
}

// GetHistory returns stats history for last N minutes
func (m *MonitoringManager) GetHistory(minutes int) []models.StatsSnapshot {
	m.historyLock.RLock()
	defer m.historyLock.RUnlock()

	// At 2s interval, ~30 samples per minute
	samples := minutes * 30
	if samples > len(m.history) {
		samples = len(m.history)
	}

	return m.history[len(m.history)-samples:]
}

// GetCurrentStats returns current stats snapshot
func (m *MonitoringManager) GetCurrentStats() map[string]interface{} {
	stats := m.system.GetStats()
	interfaces := m.system.GetNetworkInterfaces()
	clients, _ := m.network.GetConnectedClients()

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

	return map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"system": map[string]interface{}{
			"cpu": map[string]interface{}{
				"percent": stats.CPUPercent,
				"cores":   stats.CPUCores,
			},
			"memory": map[string]interface{}{
				"percent": stats.MemoryPercent,
				"used":    stats.MemoryUsed,
				"total":   stats.MemoryTotal,
			},
			"temperature": map[string]interface{}{
				"cpu_temp_c":    stats.TemperatureCPU,
				"throttled":     stats.Throttled,
				"under_voltage": stats.UnderVoltage,
			},
		},
		"network": map[string]interface{}{
			"interfaces":        networkTraffic,
			"clients_connected": len(clients),
		},
	}
}

// GetThresholds returns current alert thresholds
func (m *MonitoringManager) GetThresholds() map[string]float64 {
	m.thresholdsLock.RLock()
	defer m.thresholdsLock.RUnlock()

	result := make(map[string]float64)
	for k, v := range m.thresholds {
		result[k] = v
	}
	return result
}

// SetThresholds updates alert thresholds
func (m *MonitoringManager) SetThresholds(thresholds map[string]float64) map[string]float64 {
	m.thresholdsLock.Lock()
	defer m.thresholdsLock.Unlock()

	for key, value := range thresholds {
		if _, ok := m.thresholds[key]; ok {
			m.thresholds[key] = value
		}
	}

	return m.thresholds
}

// GetCurrentAlerts checks current values against thresholds
func (m *MonitoringManager) GetCurrentAlerts() models.AlertsResponse {
	stats := m.system.GetStats()
	thresholds := m.GetThresholds()

	var alerts []models.Alert

	if stats.CPUPercent >= thresholds["cpu_percent"] {
		alerts = append(alerts, models.Alert{
			Type:     "cpu",
			Message:  "CPU usage high",
			Severity: "warning",
			Value:    stats.CPUPercent,
		})
	}

	if stats.MemoryPercent >= thresholds["memory_percent"] {
		alerts = append(alerts, models.Alert{
			Type:     "memory",
			Message:  "Memory usage high",
			Severity: "warning",
			Value:    stats.MemoryPercent,
		})
	}

	if stats.TemperatureCPU >= thresholds["temperature_c"] {
		alerts = append(alerts, models.Alert{
			Type:     "temperature",
			Message:  "CPU temperature high",
			Severity: "critical",
			Value:    stats.TemperatureCPU,
		})
	}

	if stats.Throttled {
		alerts = append(alerts, models.Alert{
			Type:     "throttling",
			Message:  "CPU throttled",
			Severity: "warning",
		})
	}

	if stats.UnderVoltage {
		alerts = append(alerts, models.Alert{
			Type:     "power",
			Message:  "Under-voltage detected",
			Severity: "critical",
		})
	}

	return models.AlertsResponse{
		Alerts:     alerts,
		AlertCount: len(alerts),
		Timestamp:  time.Now().Format(time.RFC3339),
	}
}

// StartRecording starts background stats recording
func (m *MonitoringManager) StartRecording(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			m.RecordStats()
		}
	}
}
