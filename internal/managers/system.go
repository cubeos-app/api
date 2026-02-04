package managers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"

	"cubeos-api/internal/models"
)

// SystemManager handles system-level operations
type SystemManager struct{}

// NewSystemManager creates a new SystemManager
func NewSystemManager() *SystemManager {
	return &SystemManager{}
}

// GetHostname returns the system hostname
// Tries to get the actual host hostname when running in a container
func (m *SystemManager) GetHostname() string {
	// First try to read from /host/etc/hostname (mounted from host)
	if data, err := os.ReadFile("/host/etc/hostname"); err == nil {
		return strings.TrimSpace(string(data))
	}

	// Try /etc/hostname
	if data, err := os.ReadFile("/etc/hostname"); err == nil {
		return strings.TrimSpace(string(data))
	}

	// Fall back to os.Hostname()
	hostname, _ := os.Hostname()
	return hostname
}

// GetOSInfo returns OS name and version
func (m *SystemManager) GetOSInfo() (name string, version string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS, ""
	}

	info := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "="); idx > 0 {
			key := line[:idx]
			value := strings.Trim(line[idx+1:], `"`)
			info[key] = value
		}
	}

	return info["NAME"], info["VERSION_ID"]
}

// GetKernelVersion returns the kernel version
func (m *SystemManager) GetKernelVersion() string {
	info, err := host.Info()
	if err != nil {
		return ""
	}
	return info.KernelVersion
}

// GetArchitecture returns the system architecture
func (m *SystemManager) GetArchitecture() string {
	return runtime.GOARCH
}

// GetPiInfo returns Raspberry Pi specific information
func (m *SystemManager) GetPiInfo() (model, serial, revision string) {
	// Read model from device tree
	if data, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		model = strings.TrimRight(string(data), "\x00\n")
	}

	// Read serial and revision from cpuinfo
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Serial") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				serial = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Revision") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				revision = strings.TrimSpace(parts[1])
			}
		}
	}
	return
}

// GetCPUModel returns the CPU model name
func (m *SystemManager) GetCPUModel() string {
	info, err := cpu.Info()
	if err != nil || len(info) == 0 {
		return ""
	}
	return info[0].ModelName
}

// GetUptime returns uptime in seconds and human-readable format
func (m *SystemManager) GetUptime() (int64, string) {
	info, err := host.Info()
	if err != nil {
		return 0, ""
	}

	uptime := int64(info.Uptime)
	return uptime, formatDuration(time.Duration(uptime) * time.Second)
}

// GetBootTime returns the system boot time
func (m *SystemManager) GetBootTime() time.Time {
	info, err := host.Info()
	if err != nil {
		return time.Time{}
	}
	return time.Unix(int64(info.BootTime), 0)
}

// GetMACAddresses returns MAC addresses for all interfaces
func (m *SystemManager) GetMACAddresses() map[string]string {
	macs := make(map[string]string)

	interfaces, err := net.Interfaces()
	if err != nil {
		return macs
	}

	for _, iface := range interfaces {
		if iface.HardwareAddr != nil && len(iface.HardwareAddr) > 0 {
			macs[iface.Name] = iface.HardwareAddr.String()
		}
	}
	return macs
}

// GetIPAddresses returns IP addresses for all interfaces
func (m *SystemManager) GetIPAddresses() map[string]string {
	ips := make(map[string]string)

	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ips[iface.Name] = ipnet.IP.String()
				break
			}
		}
	}
	return ips
}

// GetSystemInfo returns comprehensive system information
func (m *SystemManager) GetSystemInfo() *models.SystemInfo {
	osName, osVersion := m.GetOSInfo()
	uptimeSecs, uptimeHuman := m.GetUptime()
	piModel, piSerial, piRevision := m.GetPiInfo()

	cpuCount, _ := cpu.Counts(false)

	return &models.SystemInfo{
		Hostname:      m.GetHostname(),
		OSName:        osName,
		OSVersion:     osVersion,
		Kernel:        m.GetKernelVersion(),
		Architecture:  m.GetArchitecture(),
		PiModel:       piModel,
		PiSerial:      piSerial,
		PiRevision:    piRevision,
		CPUModel:      m.GetCPUModel(),
		CPUCores:      cpuCount,
		UptimeSeconds: uptimeSecs,
		UptimeHuman:   uptimeHuman,
		BootTime:      m.GetBootTime(),
		MACAddresses:  m.GetMACAddresses(),
		IPAddresses:   m.GetIPAddresses(),
	}
}

// GetCPUPercent returns current CPU usage percentage
func (m *SystemManager) GetCPUPercent() float64 {
	percentages, err := cpu.Percent(100*time.Millisecond, false)
	if err != nil || len(percentages) == 0 {
		return 0
	}
	return percentages[0]
}

// GetMemoryStats returns memory statistics
func (m *SystemManager) GetMemoryStats() (total, used, available uint64, percent float64) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return
	}
	return v.Total, v.Used, v.Available, v.UsedPercent
}

// GetDiskStats returns disk statistics for root partition
func (m *SystemManager) GetDiskStats() (total, used, free uint64, percent float64) {
	// Try host filesystem first (when running in container)
	usage, err := disk.Usage("/hostfs")
	if err != nil {
		// Fall back to container root
		usage, err = disk.Usage("/")
		if err != nil {
			return
		}
	}
	return usage.Total, usage.Used, usage.Free, usage.UsedPercent
}

// GetTemperature returns CPU temperature and throttling status
func (m *SystemManager) GetTemperature() *models.Temperature {
	result := &models.Temperature{
		Status: "unknown",
	}

	// Try to read CPU temperature from thermal zone
	thermalPaths := []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/host/sys/class/thermal/thermal_zone0/temp",
	}

	for _, path := range thermalPaths {
		if data, err := os.ReadFile(path); err == nil {
			if temp, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				result.CPUTempC = float64(temp) / 1000.0
				result.Temperature = result.CPUTempC // Alias for API compatibility
				break
			}
		}
	}

	// Try vcgencmd for GPU temp (Raspberry Pi)
	if output, err := exec.Command("vcgencmd", "measure_temp").Output(); err == nil {
		re := regexp.MustCompile(`temp=(\d+\.?\d*)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) > 1 {
			if temp, err := strconv.ParseFloat(matches[1], 64); err == nil {
				result.GPUTempC = temp
			}
		}
	}

	// Get throttling status
	throttlePaths := []string{
		"/sys/devices/platform/soc/soc:firmware/get_throttled",
		"/host/sys/devices/platform/soc/soc:firmware/get_throttled",
	}

	var throttleValue int64
	for _, path := range throttlePaths {
		if data, err := os.ReadFile(path); err == nil {
			throttleValue, _ = strconv.ParseInt(strings.TrimPrefix(strings.TrimSpace(string(data)), "0x"), 16, 64)
			break
		}
	}

	// Fall back to vcgencmd
	if throttleValue == 0 {
		if output, err := exec.Command("vcgencmd", "get_throttled").Output(); err == nil {
			parts := strings.Split(strings.TrimSpace(string(output)), "=")
			if len(parts) == 2 {
				throttleValue, _ = strconv.ParseInt(strings.TrimPrefix(parts[1], "0x"), 16, 64)
			}
		}
	}

	result.ThrottleFlags = fmt.Sprintf("0x%x", throttleValue)
	result.UnderVoltage = throttleValue&0x1 != 0
	result.FrequencyCapped = throttleValue&0x2 != 0
	result.Throttled = throttleValue&0x4 != 0
	result.SoftTempLimit = throttleValue&0x8 != 0

	// Determine status
	switch {
	case result.Throttled:
		result.Status = "throttled"
	case result.SoftTempLimit:
		result.Status = "warm"
	case result.CPUTempC >= 80:
		result.Status = "hot"
	case result.CPUTempC >= 70:
		result.Status = "warm"
	case result.CPUTempC > 0:
		result.Status = "normal"
	}

	return result
}

// GetSystemStats returns current system statistics
func (m *SystemManager) GetSystemStats() *models.SystemStats {
	memTotal, memUsed, memAvail, memPercent := m.GetMemoryStats()
	diskTotal, diskUsed, diskFree, diskPercent := m.GetDiskStats()
	temp := m.GetTemperature()

	return &models.SystemStats{
		CPUPercent:      m.GetCPUPercent(),
		MemoryPercent:   memPercent,
		MemoryTotal:     memTotal,
		MemoryUsed:      memUsed,
		MemoryAvailable: memAvail,
		DiskPercent:     diskPercent,
		DiskTotal:       diskTotal,
		DiskUsed:        diskUsed,
		DiskFree:        diskFree,
		TemperatureCPU:  temp.CPUTempC,
		Timestamp:       time.Now(),
	}
}

// GetStats returns extended stats for monitoring
func (m *SystemManager) GetStats() models.ExtendedStats {
	memTotal, memUsed, _, memPercent := m.GetMemoryStats()
	diskTotal, diskUsed, _, diskPercent := m.GetDiskStats()
	temp := m.GetTemperature()

	return models.ExtendedStats{
		CPUPercent:     m.GetCPUPercent(),
		CPUCores:       runtime.NumCPU(),
		MemoryPercent:  memPercent,
		MemoryTotal:    memTotal,
		MemoryUsed:     memUsed,
		DiskPercent:    diskPercent,
		DiskTotal:      diskTotal,
		DiskUsed:       diskUsed,
		TemperatureCPU: temp.CPUTempC,
		Throttled:      temp.Throttled,
		UnderVoltage:   temp.UnderVoltage,
	}
}

// GetLoadAverage returns system load averages
func (m *SystemManager) GetLoadAverage() (load1, load5, load15 float64) {
	avg, err := load.Avg()
	if err != nil {
		return
	}
	return avg.Load1, avg.Load5, avg.Load15
}

// Reboot initiates a system reboot
func (m *SystemManager) Reboot(delayMinutes int) (*models.PowerAction, error) {
	if delayMinutes > 0 {
		cmd := exec.Command("shutdown", "-r", fmt.Sprintf("+%d", delayMinutes))
		if err := cmd.Run(); err != nil {
			return nil, err
		}
		scheduledTime := time.Now().Add(time.Duration(delayMinutes) * time.Minute)
		return &models.PowerAction{
			Status:        "scheduled",
			Action:        "reboot",
			ScheduledTime: &scheduledTime,
			Message:       fmt.Sprintf("Reboot scheduled in %d minute(s)", delayMinutes),
		}, nil
	}

	// Immediate reboot - use goroutine to allow response to be sent
	go func() {
		time.Sleep(2 * time.Second)
		exec.Command("reboot").Run()
	}()

	return &models.PowerAction{
		Status:  "initiated",
		Action:  "reboot",
		Message: "System rebooting now",
	}, nil
}

// Shutdown initiates a system shutdown
func (m *SystemManager) Shutdown(delayMinutes int) (*models.PowerAction, error) {
	if delayMinutes > 0 {
		cmd := exec.Command("shutdown", "-h", fmt.Sprintf("+%d", delayMinutes))
		if err := cmd.Run(); err != nil {
			return nil, err
		}
		scheduledTime := time.Now().Add(time.Duration(delayMinutes) * time.Minute)
		return &models.PowerAction{
			Status:        "scheduled",
			Action:        "shutdown",
			ScheduledTime: &scheduledTime,
			Message:       fmt.Sprintf("Shutdown scheduled in %d minute(s)", delayMinutes),
		}, nil
	}

	go func() {
		time.Sleep(2 * time.Second)
		exec.Command("shutdown", "-h", "now").Run()
	}()

	return &models.PowerAction{
		Status:  "initiated",
		Action:  "shutdown",
		Message: "System shutting down now",
	}, nil
}

// CancelShutdown cancels a scheduled shutdown/reboot
func (m *SystemManager) CancelShutdown() (*models.PowerAction, error) {
	cmd := exec.Command("shutdown", "-c")
	if err := cmd.Run(); err != nil {
		return &models.PowerAction{
			Status:  "error",
			Message: "No shutdown scheduled or cancel failed",
		}, nil
	}
	return &models.PowerAction{
		Status:  "cancelled",
		Message: "Scheduled shutdown cancelled",
	}, nil
}

// GetServiceStatus returns the status of a systemd service
func (m *SystemManager) GetServiceStatus(serviceName string) *models.ServiceStatus {
	status := &models.ServiceStatus{
		Service: serviceName,
		State:   "unknown",
	}

	// Check if service is active
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, _ := cmd.Output()
	status.Active = strings.TrimSpace(string(output)) == "active"

	// Get detailed status
	cmd = exec.Command("systemctl", "show", serviceName, "--property=ActiveState,SubState,MainPID")
	output, err := cmd.Output()
	if err != nil {
		return status
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "ActiveState":
			status.State = parts[1]
		case "SubState":
			status.SubState = parts[1]
		case "MainPID":
			if pid, err := strconv.Atoi(parts[1]); err == nil && pid > 0 {
				status.PID = &pid
			}
		}
	}

	return status
}

// RestartService restarts a systemd service
func (m *SystemManager) RestartService(serviceName string) error {
	cmd := exec.Command("systemctl", "restart", serviceName)
	return cmd.Run()
}

// GetDateTime returns current date/time and timezone
func (m *SystemManager) GetDateTime() (datetime time.Time, timezone string) {
	datetime = time.Now()

	cmd := exec.Command("timedatectl", "show", "--property=Timezone", "--value")
	if output, err := cmd.Output(); err == nil {
		timezone = strings.TrimSpace(string(output))
	} else {
		timezone = "Unknown"
	}

	return
}

// formatDuration formats a duration as human readable string
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

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
	parts = append(parts, fmt.Sprintf("%ds", seconds))

	return strings.Join(parts, " ")
}

// GetNetworkInterfaces returns all network interfaces with statistics
func (m *SystemManager) GetNetworkInterfaces() []models.NetworkInterface {
	var result []models.NetworkInterface

	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}

	ioCounters, _ := psnet.IOCounters(true)
	ioMap := make(map[string]psnet.IOCountersStat)
	for _, io := range ioCounters {
		ioMap[io.Name] = io
	}

	for _, iface := range interfaces {
		ni := models.NetworkInterface{
			Name:       iface.Name,
			MTU:        iface.MTU,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}

		if iface.HardwareAddr != nil {
			ni.MACAddress = iface.HardwareAddr.String()
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ni.IPv4Addresses = append(ni.IPv4Addresses, ipnet.IP.String())
				} else {
					ni.IPv6Addresses = append(ni.IPv6Addresses, ipnet.IP.String())
				}
			}
		}

		if io, ok := ioMap[iface.Name]; ok {
			ni.RxBytes = io.BytesRecv
			ni.TxBytes = io.BytesSent
			ni.RxPackets = io.PacketsRecv
			ni.TxPackets = io.PacketsSent
			ni.RxErrors = io.Errin
			ni.TxErrors = io.Errout
		}

		result = append(result, ni)
	}

	return result
}

// GetDisks returns all mounted disks with usage statistics
func (m *SystemManager) GetDisks() []models.DiskInfo {
	var result []models.DiskInfo

	// Try host filesystem first (when running in container), fall back to /
	rootPath := "/hostfs"
	usage, err := disk.Usage(rootPath)
	if err != nil {
		rootPath = "/"
		usage, err = disk.Usage(rootPath)
	}

	if err == nil {
		result = append(result, models.DiskInfo{
			Device:      "/dev/mmcblk0p2",
			Mountpoint:  "/",
			FSType:      "ext4",
			TotalBytes:  usage.Total,
			UsedBytes:   usage.Used,
			FreeBytes:   usage.Free,
			PercentUsed: usage.UsedPercent,
			TotalHuman:  humanSize(usage.Total),
			UsedHuman:   humanSize(usage.Used),
			FreeHuman:   humanSize(usage.Free),
		})
	}

	// Add other partitions (skip virtual and container filesystems)
	partitions, err := disk.Partitions(false)
	if err != nil {
		return result
	}

	seen := map[string]bool{"/": true, rootPath: true, "/hostfs": true}
	for _, p := range partitions {
		if seen[p.Mountpoint] {
			continue
		}
		// Skip virtual filesystems and container mounts
		if strings.HasPrefix(p.Mountpoint, "/host") ||
			strings.HasPrefix(p.Mountpoint, "/sys") ||
			strings.HasPrefix(p.Mountpoint, "/proc") ||
			strings.HasPrefix(p.Mountpoint, "/dev") ||
			strings.HasPrefix(p.Mountpoint, "/run") ||
			p.Fstype == "overlay" ||
			p.Fstype == "tmpfs" ||
			p.Fstype == "devtmpfs" {
			continue
		}
		seen[p.Mountpoint] = true

		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}

		result = append(result, models.DiskInfo{
			Device:      p.Device,
			Mountpoint:  p.Mountpoint,
			FSType:      p.Fstype,
			TotalBytes:  usage.Total,
			UsedBytes:   usage.Used,
			FreeBytes:   usage.Free,
			PercentUsed: usage.UsedPercent,
			TotalHuman:  humanSize(usage.Total),
			UsedHuman:   humanSize(usage.Used),
			FreeHuman:   humanSize(usage.Free),
		})
	}

	return result
}

func humanSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GetStorageOverview returns complete storage information
func (m *SystemManager) GetStorageOverview() *models.StorageOverview {
	disks := m.GetDisks()

	var totalCapacity, totalUsed, totalFree uint64
	for _, d := range disks {
		totalCapacity += d.TotalBytes
		totalUsed += d.UsedBytes
		totalFree += d.FreeBytes
	}

	return &models.StorageOverview{
		Disks:         disks,
		TotalCapacity: totalCapacity,
		TotalUsed:     totalUsed,
		TotalFree:     totalFree,
	}
}

// ListDataDirectories returns directories under a path with sizes
func (m *SystemManager) ListDataDirectories(basePath string) ([]map[string]interface{}, error) {
	var dirs []map[string]interface{}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		path := filepath.Join(basePath, entry.Name())
		size := getDirSize(path)

		dirs = append(dirs, map[string]interface{}{
			"name":       entry.Name(),
			"path":       path,
			"size_bytes": size,
			"size_human": humanSize(uint64(size)),
		})
	}

	return dirs, nil
}

func getDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

// ServiceDataInfo represents a service's data directory info
type ServiceDataInfo struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Size      int64  `json:"size_bytes"`
	SizeHuman string `json:"size_human"`
	Exists    bool   `json:"exists"`
}

// GetServiceDataSizes returns sizes of service data directories
func (m *SystemManager) GetServiceDataSizes(basePath string) []ServiceDataInfo {
	var services []ServiceDataInfo

	// Try multiple paths (container vs host)
	paths := []string{
		basePath,
		"/hostfs" + basePath,
		"/host" + basePath,
		"/cubeos/apps",
		"/hostfs/cubeos/apps",
		"/var/lib/docker/volumes",
		"/hostfs/var/lib/docker/volumes",
	}

	var appsDir string
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			appsDir = p
			break
		}
	}

	if appsDir == "" {
		return services
	}

	// Read app directories
	entries, err := os.ReadDir(appsDir)
	if err != nil {
		return services
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()

		// Check for data directory
		dataPath := filepath.Join(appsDir, name, "data")

		info := ServiceDataInfo{
			Name:   name,
			Path:   dataPath,
			Exists: false,
		}

		if stat, err := os.Stat(dataPath); err == nil && stat.IsDir() {
			info.Exists = true
			info.Size = getDirSize(dataPath)
			info.SizeHuman = formatByteSize(info.Size)
		} else {
			// Check if app has any other data (like volumes mapped)
			appPath := filepath.Join(appsDir, name)
			info.Path = appPath
			info.Exists = true
			info.Size = getDirSize(appPath)
			info.SizeHuman = formatByteSize(info.Size)
		}

		services = append(services, info)
	}

	return services
}

// formatByteSize converts bytes to human readable format
func formatByteSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// =============================================================================
// NEW METHODS: Hostname and Timezone Management
// =============================================================================

// SetHostname sets the system hostname
func (m *SystemManager) SetHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	// Validate hostname (basic check)
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}

	// Use hostnamectl if available (systemd)
	cmd := exec.Command("hostnamectl", "set-hostname", hostname)
	if err := cmd.Run(); err != nil {
		// Fall back to writing directly to /etc/hostname
		hostPaths := []string{"/host/etc/hostname", "/etc/hostname"}
		var lastErr error
		for _, path := range hostPaths {
			if err := os.WriteFile(path, []byte(hostname+"\n"), 0644); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		return fmt.Errorf("failed to set hostname: %w", lastErr)
	}

	return nil
}

// GetTimezone returns the current system timezone
func (m *SystemManager) GetTimezone() string {
	// Try timedatectl first (systemd)
	cmd := exec.Command("timedatectl", "show", "--property=Timezone", "--value")
	if output, err := cmd.Output(); err == nil {
		tz := strings.TrimSpace(string(output))
		if tz != "" {
			return tz
		}
	}

	// Fall back to reading /etc/timezone
	tzPaths := []string{"/host/etc/timezone", "/etc/timezone"}
	for _, path := range tzPaths {
		if data, err := os.ReadFile(path); err == nil {
			tz := strings.TrimSpace(string(data))
			if tz != "" {
				return tz
			}
		}
	}

	// Try reading the localtime symlink
	localtimePaths := []string{"/host/etc/localtime", "/etc/localtime"}
	for _, path := range localtimePaths {
		if target, err := os.Readlink(path); err == nil {
			// Extract timezone from path like /usr/share/zoneinfo/America/New_York
			if idx := strings.Index(target, "/zoneinfo/"); idx >= 0 {
				return target[idx+len("/zoneinfo/"):]
			}
		}
	}

	return "UTC"
}

// SetTimezone sets the system timezone
func (m *SystemManager) SetTimezone(timezone string) error {
	if timezone == "" {
		return fmt.Errorf("timezone cannot be empty")
	}

	// Validate timezone exists
	zonePaths := []string{
		filepath.Join("/usr/share/zoneinfo", timezone),
		filepath.Join("/host/usr/share/zoneinfo", timezone),
	}

	var zonePath string
	for _, p := range zonePaths {
		if _, err := os.Stat(p); err == nil {
			zonePath = p
			break
		}
	}

	if zonePath == "" {
		return fmt.Errorf("invalid timezone: %s", timezone)
	}

	// Use timedatectl if available (systemd)
	cmd := exec.Command("timedatectl", "set-timezone", timezone)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Fall back to manual method
	// Write to /etc/timezone
	tzPaths := []string{"/host/etc/timezone", "/etc/timezone"}
	for _, path := range tzPaths {
		if err := os.WriteFile(path, []byte(timezone+"\n"), 0644); err == nil {
			break
		}
	}

	// Update /etc/localtime symlink
	localTimePaths := []string{"/host/etc/localtime", "/etc/localtime"}
	for _, path := range localTimePaths {
		os.Remove(path)
		// Use the appropriate zoneinfo path
		zoneFile := filepath.Join("/usr/share/zoneinfo", timezone)
		if err := os.Symlink(zoneFile, path); err == nil {
			return nil
		}
	}

	return nil
}

// GetTimezones returns a list of available timezones
func (m *SystemManager) GetTimezones() []string {
	var timezones []string

	// Try to read all timezones from the system
	zoneinfoDir := "/usr/share/zoneinfo"
	if _, err := os.Stat(zoneinfoDir); os.IsNotExist(err) {
		zoneinfoDir = "/host/usr/share/zoneinfo"
	}

	if _, err := os.Stat(zoneinfoDir); err == nil {
		_ = filepath.Walk(zoneinfoDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Skip directories we don't want
			if info.IsDir() {
				name := info.Name()
				if name == "posix" || name == "right" || name == "Etc" {
					return filepath.SkipDir
				}
				return nil
			}

			// Get relative path from zoneinfo
			relPath, err := filepath.Rel(zoneinfoDir, path)
			if err != nil {
				return nil
			}

			// Skip files that aren't timezones
			if strings.Contains(relPath, ".") ||
				relPath == "localtime" ||
				relPath == "posixrules" ||
				relPath == "leap-seconds.list" ||
				relPath == "leapseconds" ||
				relPath == "tzdata.zi" ||
				relPath == "zone.tab" ||
				relPath == "zone1970.tab" ||
				relPath == "iso3166.tab" {
				return nil
			}

			// Validate it looks like a timezone (contains a /)
			if strings.Contains(relPath, "/") {
				timezones = append(timezones, relPath)
			}

			return nil
		})
	}

	// If we found some timezones, return them
	if len(timezones) > 0 {
		return timezones
	}

	// Fall back to common timezones
	return []string{
		"UTC",
		"America/New_York",
		"America/Chicago",
		"America/Denver",
		"America/Los_Angeles",
		"America/Toronto",
		"America/Vancouver",
		"America/Sao_Paulo",
		"Europe/London",
		"Europe/Paris",
		"Europe/Berlin",
		"Europe/Amsterdam",
		"Europe/Rome",
		"Europe/Madrid",
		"Europe/Moscow",
		"Asia/Tokyo",
		"Asia/Shanghai",
		"Asia/Hong_Kong",
		"Asia/Singapore",
		"Asia/Dubai",
		"Asia/Kolkata",
		"Asia/Seoul",
		"Australia/Sydney",
		"Australia/Melbourne",
		"Pacific/Auckland",
		"Pacific/Honolulu",
	}
}
