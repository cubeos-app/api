// Package system provides system information and monitoring.
//
// This package will be fully implemented in Sprint 1.1 to support:
// - System info (hostname, OS, architecture, uptime)
// - Raspberry Pi info (model, serial, revision)
// - CPU stats (usage, temperature)
// - Memory stats (total, used, available)
// - Disk stats (per mount point)
// - Network interfaces
//
// See CUBEOS_PROJECT_PLAN.md tasks BE-006 and BE-007.
package system

// Info represents static system information.
type Info struct {
	Hostname     string            `json:"hostname"`
	OSName       string            `json:"os_name"`
	OSVersion    string            `json:"os_version"`
	Kernel       string            `json:"kernel"`
	Architecture string            `json:"architecture"`
	PiModel      string            `json:"pi_model,omitempty"`
	PiSerial     string            `json:"pi_serial,omitempty"`
	PiRevision   string            `json:"pi_revision,omitempty"`
	UptimeSecs   int64             `json:"uptime_seconds"`
	UptimeHuman  string            `json:"uptime_human"`
	MACAddresses map[string]string `json:"mac_addresses"`
	IPAddresses  map[string]string `json:"ip_addresses"`
}

// Stats represents real-time system statistics.
type Stats struct {
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryTotal    uint64  `json:"memory_total"`
	MemoryUsed     uint64  `json:"memory_used"`
	MemoryPercent  float64 `json:"memory_percent"`
	DiskTotal      uint64  `json:"disk_total"`
	DiskUsed       uint64  `json:"disk_used"`
	DiskPercent    float64 `json:"disk_percent"`
	TemperatureCPU float64 `json:"temperature_cpu"`
	LoadAvg1       float64 `json:"load_avg_1"`
	LoadAvg5       float64 `json:"load_avg_5"`
	LoadAvg15      float64 `json:"load_avg_15"`
}

// TODO: Implement in Sprint 1.1:
// - GetInfo() (*Info, error)
// - GetStats() (*Stats, error)
// - Reboot() error
// - Shutdown() error
