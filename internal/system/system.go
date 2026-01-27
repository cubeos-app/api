// Package system provides system information and monitoring for CubeOS.
//
// This package provides functionality equivalent to Python's psutil,
// reading system stats from /proc, /sys, and other Linux interfaces.
package system

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

// Info represents static system information.
// This matches the Python SystemManager.get_system_info() response.
type Info struct {
	Hostname      string            `json:"hostname"`
	OSName        string            `json:"os_name"`
	OSVersion     string            `json:"os_version"`
	Kernel        string            `json:"kernel"`
	Architecture  string            `json:"architecture"`
	PiModel       string            `json:"pi_model,omitempty"`
	PiSerial      string            `json:"pi_serial,omitempty"`
	PiRevision    string            `json:"pi_revision,omitempty"`
	UptimeSecs    uint64            `json:"uptime_seconds"`
	UptimeHuman   string            `json:"uptime_human"`
	BootTime      time.Time         `json:"boot_time"`
	CPUModel      string            `json:"cpu_model"`
	CPUCores      int               `json:"cpu_cores"`
	MACAddresses  map[string]string `json:"mac_addresses"`
	IPAddresses   map[string]string `json:"ip_addresses"`
}

// Stats represents real-time system statistics.
// This matches the Python SystemManager stats response.
type Stats struct {
	CPUPercent      float64 `json:"cpu_percent"`
	CPUPerCore      []float64 `json:"cpu_per_core,omitempty"`
	MemoryTotal     uint64  `json:"memory_total"`
	MemoryUsed      uint64  `json:"memory_used"`
	MemoryAvailable uint64  `json:"memory_available"`
	MemoryPercent   float64 `json:"memory_percent"`
	SwapTotal       uint64  `json:"swap_total"`
	SwapUsed        uint64  `json:"swap_used"`
	SwapPercent     float64 `json:"swap_percent"`
	DiskTotal       uint64  `json:"disk_total"`
	DiskUsed        uint64  `json:"disk_used"`
	DiskFree        uint64  `json:"disk_free"`
	DiskPercent     float64 `json:"disk_percent"`
	Temperature     float64 `json:"temperature_cpu"`
	LoadAvg1        float64 `json:"load_avg_1"`
	LoadAvg5        float64 `json:"load_avg_5"`
	LoadAvg15       float64 `json:"load_avg_15"`
}

// GetInfo returns static system information.
func GetInfo() (*Info, error) {
	info := &Info{
		Architecture: runtime.GOARCH,
		CPUCores:     runtime.NumCPU(),
		MACAddresses: make(map[string]string),
		IPAddresses:  make(map[string]string),
	}

	// Hostname
	hostname, err := os.Hostname()
	if err == nil {
		info.Hostname = hostname
	}

	// Host info (OS, kernel, uptime)
	hostInfo, err := host.Info()
	if err == nil {
		info.OSName = hostInfo.Platform
		info.OSVersion = hostInfo.PlatformVersion
		info.Kernel = hostInfo.KernelVersion
		info.UptimeSecs = hostInfo.Uptime
		info.UptimeHuman = formatUptime(hostInfo.Uptime)
		info.BootTime = time.Unix(int64(hostInfo.BootTime), 0)
	}

	// CPU model
	cpuInfo, err := cpu.Info()
	if err == nil && len(cpuInfo) > 0 {
		info.CPUModel = cpuInfo[0].ModelName
	}

	// Raspberry Pi specific info
	info.PiModel = readFileString("/sys/firmware/devicetree/base/model")
	info.PiSerial, info.PiRevision = getPiInfo()

	// Network addresses
	info.MACAddresses, info.IPAddresses = getNetworkAddresses()

	return info, nil
}

// GetStats returns real-time system statistics.
func GetStats() (*Stats, error) {
	stats := &Stats{}

	// CPU usage (with 500ms sample time for accuracy)
	cpuPercent, err := cpu.Percent(500*time.Millisecond, false)
	if err == nil && len(cpuPercent) > 0 {
		stats.CPUPercent = cpuPercent[0]
	}

	// Per-core CPU (optional, for detailed view)
	cpuPerCore, err := cpu.Percent(0, true)
	if err == nil {
		stats.CPUPerCore = cpuPerCore
	}

	// Memory
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		stats.MemoryTotal = memInfo.Total
		stats.MemoryUsed = memInfo.Used
		stats.MemoryAvailable = memInfo.Available
		stats.MemoryPercent = memInfo.UsedPercent
	}

	// Swap
	swapInfo, err := mem.SwapMemory()
	if err == nil {
		stats.SwapTotal = swapInfo.Total
		stats.SwapUsed = swapInfo.Used
		stats.SwapPercent = swapInfo.UsedPercent
	}

	// Disk (root partition)
	diskInfo, err := disk.Usage("/")
	if err == nil {
		stats.DiskTotal = diskInfo.Total
		stats.DiskUsed = diskInfo.Used
		stats.DiskFree = diskInfo.Free
		stats.DiskPercent = diskInfo.UsedPercent
	}

	// CPU Temperature (Raspberry Pi / Linux thermal zone)
	stats.Temperature = getCPUTemperature()

	// Load average
	loadInfo, err := load.Avg()
	if err == nil {
		stats.LoadAvg1 = loadInfo.Load1
		stats.LoadAvg5 = loadInfo.Load5
		stats.LoadAvg15 = loadInfo.Load15
	}

	return stats, nil
}

// formatUptime converts seconds to human-readable format (e.g., "2d 5h 30m 15s")
func formatUptime(seconds uint64) string {
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	parts = append(parts, fmt.Sprintf("%ds", secs))

	return strings.Join(parts, " ")
}

// readFileString reads a file and returns its contents as a trimmed string.
// Returns empty string on error (non-fatal, e.g., file doesn't exist on non-Pi).
func readFileString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Remove null bytes and trim whitespace
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", ""))
}

// getPiInfo reads Raspberry Pi serial and revision from /proc/cpuinfo.
func getPiInfo() (serial, revision string) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Serial") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				serial = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "Revision") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				revision = strings.TrimSpace(parts[1])
			}
		}
	}
	return serial, revision
}

// getCPUTemperature reads CPU temperature from Linux thermal zone.
// Returns 0 if unavailable (non-fatal).
func getCPUTemperature() float64 {
	// Try Raspberry Pi thermal zone first
	paths := []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/devices/virtual/thermal/thermal_zone0/temp",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			var temp int
			if _, err := fmt.Sscanf(string(data), "%d", &temp); err == nil {
				// Temperature is in millidegrees, convert to degrees
				return float64(temp) / 1000.0
			}
		}
	}
	return 0
}

// getNetworkAddresses returns MAC and IP addresses for all interfaces.
func getNetworkAddresses() (macs, ips map[string]string) {
	macs = make(map[string]string)
	ips = make(map[string]string)

	interfaces, err := net.Interfaces()
	if err != nil {
		return macs, ips
	}

	for _, iface := range interfaces {
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// MAC address
		if len(iface.HardwareAddr) > 0 {
			macs[iface.Name] = iface.HardwareAddr.String()
		}

		// IP addresses (first IPv4)
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipv4 := ipnet.IP.To4(); ipv4 != nil {
					ips[iface.Name] = ipv4.String()
					break // Only first IPv4 per interface
				}
			}
		}
	}

	return macs, ips
}
