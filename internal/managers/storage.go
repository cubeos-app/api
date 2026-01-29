package managers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StorageManager handles SMB shares and disk health monitoring
type StorageManager struct {
	smbConfPath string
	mu          sync.RWMutex
}

// NewStorageManager creates a new StorageManager
func NewStorageManager() *StorageManager {
	return &StorageManager{
		smbConfPath: "/etc/samba/smb.conf",
	}
}

// =============================================================================
// SMB Shares
// =============================================================================

// SMBShare represents a Samba share configuration
type SMBShare struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Comment    string   `json:"comment,omitempty"`
	Browseable bool     `json:"browseable"`
	ReadOnly   bool     `json:"read_only"`
	GuestOK    bool     `json:"guest_ok"`
	ValidUsers []string `json:"valid_users,omitempty"`
	CreateMask string   `json:"create_mask,omitempty"`
	DirMask    string   `json:"dir_mask,omitempty"`
	ForceUser  string   `json:"force_user,omitempty"`
	ForceGroup string   `json:"force_group,omitempty"`
}

// SMBConfig represents the global Samba configuration
type SMBConfig struct {
	Workgroup   string     `json:"workgroup"`
	ServerName  string     `json:"server_name"`
	Description string     `json:"description"`
	Shares      []SMBShare `json:"shares"`
}

// GetSMBConfig reads the current Samba configuration
func (m *StorageManager) GetSMBConfig() (*SMBConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	config := &SMBConfig{
		Workgroup:   "WORKGROUP",
		ServerName:  "CUBEOS",
		Description: "CubeOS File Server",
		Shares:      []SMBShare{},
	}

	// Try multiple paths
	paths := []string{
		m.smbConfPath,
		"/hostfs" + m.smbConfPath,
		"/host" + m.smbConfPath,
	}

	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		return config, nil // Return defaults if no config exists
	}

	// Parse smb.conf
	var currentSection string
	var currentShare *SMBShare

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// Save previous share
			if currentShare != nil {
				config.Shares = append(config.Shares, *currentShare)
			}

			currentSection = line[1 : len(line)-1]

			// Skip global section for shares
			if currentSection != "global" {
				currentShare = &SMBShare{
					Name:       currentSection,
					Browseable: true,
					ReadOnly:   false,
					GuestOK:    false,
					CreateMask: "0644",
					DirMask:    "0755",
				}
			} else {
				currentShare = nil
			}
			continue
		}

		// Parse key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		// Global settings
		if currentSection == "global" {
			switch key {
			case "workgroup":
				config.Workgroup = value
			case "server string":
				config.Description = value
			case "netbios name":
				config.ServerName = value
			}
			continue
		}

		// Share settings
		if currentShare != nil {
			switch key {
			case "path":
				currentShare.Path = value
			case "comment":
				currentShare.Comment = value
			case "browseable", "browsable":
				currentShare.Browseable = parseBool(value)
			case "read only":
				currentShare.ReadOnly = parseBool(value)
			case "guest ok":
				currentShare.GuestOK = parseBool(value)
			case "valid users":
				currentShare.ValidUsers = strings.Fields(value)
			case "create mask":
				currentShare.CreateMask = value
			case "directory mask":
				currentShare.DirMask = value
			case "force user":
				currentShare.ForceUser = value
			case "force group":
				currentShare.ForceGroup = value
			}
		}
	}

	// Don't forget the last share
	if currentShare != nil {
		config.Shares = append(config.Shares, *currentShare)
	}

	return config, nil
}

// GetSMBShares returns all configured SMB shares
func (m *StorageManager) GetSMBShares() ([]SMBShare, error) {
	config, err := m.GetSMBConfig()
	if err != nil {
		return nil, err
	}
	return config.Shares, nil
}

// CreateSMBShare creates a new SMB share
func (m *StorageManager) CreateSMBShare(share SMBShare) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate
	if share.Name == "" {
		return fmt.Errorf("share name is required")
	}
	if share.Path == "" {
		return fmt.Errorf("share path is required")
	}

	// Clean name (no special chars)
	share.Name = regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(share.Name, "_")

	// Ensure path exists
	if _, err := os.Stat(share.Path); os.IsNotExist(err) {
		if err := os.MkdirAll(share.Path, 0755); err != nil {
			return fmt.Errorf("failed to create share path: %w", err)
		}
	}

	// Generate share config block
	shareConfig := m.generateShareConfig(share)

	// Append to smb.conf
	f, err := os.OpenFile(m.smbConfPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// Try creating a new file if it doesn't exist
		return m.createDefaultSMBConfig(share)
	}
	defer f.Close()

	if _, err := f.WriteString("\n" + shareConfig); err != nil {
		return fmt.Errorf("failed to write share config: %w", err)
	}

	// Reload Samba
	return m.reloadSamba()
}

// UpdateSMBShare updates an existing SMB share
func (m *StorageManager) UpdateSMBShare(name string, share SMBShare) error {
	// Get current config
	config, err := m.GetSMBConfig()
	if err != nil {
		return err
	}

	// Find and update the share
	found := false
	for i, s := range config.Shares {
		if s.Name == name {
			share.Name = name // Preserve original name
			config.Shares[i] = share
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("share '%s' not found", name)
	}

	// Rewrite entire config
	return m.writeSMBConfig(config)
}

// DeleteSMBShare removes an SMB share
func (m *StorageManager) DeleteSMBShare(name string) error {
	// Get current config
	config, err := m.GetSMBConfig()
	if err != nil {
		return err
	}

	// Remove the share
	newShares := []SMBShare{}
	found := false
	for _, s := range config.Shares {
		if s.Name != name {
			newShares = append(newShares, s)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("share '%s' not found", name)
	}

	config.Shares = newShares
	return m.writeSMBConfig(config)
}

// GetSMBStatus returns Samba service status
func (m *StorageManager) GetSMBStatus() map[string]interface{} {
	status := map[string]interface{}{
		"installed": false,
		"running":   false,
		"enabled":   false,
		"version":   "",
	}

	// Check if samba is installed - try multiple methods
	// Method 1: Direct lookup
	if _, err := exec.LookPath("smbd"); err == nil {
		status["installed"] = true
	}
	// Method 2: Check host binary paths
	hostPaths := []string{"/host/usr/sbin/smbd", "/hostfs/usr/sbin/smbd", "/usr/sbin/smbd"}
	for _, p := range hostPaths {
		if _, err := os.Stat(p); err == nil {
			status["installed"] = true
			break
		}
	}
	// Method 3: Check if smb.conf exists (indicates samba was configured)
	smbConfPaths := []string{m.smbConfPath, "/host" + m.smbConfPath, "/hostfs" + m.smbConfPath}
	for _, p := range smbConfPaths {
		if _, err := os.Stat(p); err == nil {
			status["installed"] = true
			break
		}
	}

	// Check service status via nsenter (runs on host)
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "is-active", "smbd")
	if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) == "active" {
		status["running"] = true
	} else {
		// Fallback: check if process is running via /proc
		cmd = exec.Command("sh", "-c", "pgrep -x smbd > /dev/null 2>&1 || nsenter -t 1 -m -p -- pgrep -x smbd > /dev/null 2>&1")
		if cmd.Run() == nil {
			status["running"] = true
		}
	}

	// Check if enabled
	cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "is-enabled", "smbd")
	if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) == "enabled" {
		status["enabled"] = true
	}

	// Get version via nsenter
	cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "smbd", "--version")
	if output, err := cmd.Output(); err == nil {
		status["version"] = strings.TrimSpace(string(output))
	}

	// Get connected clients
	cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "smbstatus", "-b", "--json")
	if output, err := cmd.Output(); err == nil {
		var smbStatus map[string]interface{}
		if json.Unmarshal(output, &smbStatus) == nil {
			if sessions, ok := smbStatus["sessions"].(map[string]interface{}); ok {
				status["clients"] = len(sessions)
			}
		}
	}

	return status
}

func (m *StorageManager) generateShareConfig(share SMBShare) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("[%s]", share.Name))
	lines = append(lines, fmt.Sprintf("   path = %s", share.Path))

	if share.Comment != "" {
		lines = append(lines, fmt.Sprintf("   comment = %s", share.Comment))
	}

	lines = append(lines, fmt.Sprintf("   browseable = %s", boolToYesNo(share.Browseable)))
	lines = append(lines, fmt.Sprintf("   read only = %s", boolToYesNo(share.ReadOnly)))
	lines = append(lines, fmt.Sprintf("   guest ok = %s", boolToYesNo(share.GuestOK)))

	if len(share.ValidUsers) > 0 {
		lines = append(lines, fmt.Sprintf("   valid users = %s", strings.Join(share.ValidUsers, " ")))
	}

	if share.CreateMask != "" {
		lines = append(lines, fmt.Sprintf("   create mask = %s", share.CreateMask))
	}
	if share.DirMask != "" {
		lines = append(lines, fmt.Sprintf("   directory mask = %s", share.DirMask))
	}
	if share.ForceUser != "" {
		lines = append(lines, fmt.Sprintf("   force user = %s", share.ForceUser))
	}
	if share.ForceGroup != "" {
		lines = append(lines, fmt.Sprintf("   force group = %s", share.ForceGroup))
	}

	return strings.Join(lines, "\n")
}

func (m *StorageManager) createDefaultSMBConfig(share SMBShare) error {
	config := `[global]
   workgroup = WORKGROUP
   server string = CubeOS File Server
   netbios name = CUBEOS
   security = user
   map to guest = Bad User
   dns proxy = no
   log file = /var/log/samba/log.%m
   max log size = 1000

`
	config += m.generateShareConfig(share) + "\n"

	// Write config
	if err := os.MkdirAll(filepath.Dir(m.smbConfPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(m.smbConfPath, []byte(config), 0644); err != nil {
		return err
	}

	return m.reloadSamba()
}

func (m *StorageManager) writeSMBConfig(config *SMBConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lines []string

	// Global section
	lines = append(lines, "[global]")
	lines = append(lines, fmt.Sprintf("   workgroup = %s", config.Workgroup))
	lines = append(lines, fmt.Sprintf("   server string = %s", config.Description))
	lines = append(lines, fmt.Sprintf("   netbios name = %s", config.ServerName))
	lines = append(lines, "   security = user")
	lines = append(lines, "   map to guest = Bad User")
	lines = append(lines, "   dns proxy = no")
	lines = append(lines, "   log file = /var/log/samba/log.%m")
	lines = append(lines, "   max log size = 1000")
	lines = append(lines, "")

	// Shares
	for _, share := range config.Shares {
		lines = append(lines, m.generateShareConfig(share))
		lines = append(lines, "")
	}

	content := strings.Join(lines, "\n")
	if err := os.WriteFile(m.smbConfPath, []byte(content), 0644); err != nil {
		return err
	}

	return m.reloadSamba()
}

func (m *StorageManager) reloadSamba() error {
	// Try to reload
	cmd := exec.Command("systemctl", "reload", "smbd")
	if err := cmd.Run(); err != nil {
		// Try restart if reload fails
		cmd = exec.Command("systemctl", "restart", "smbd")
		return cmd.Run()
	}
	return nil
}

// =============================================================================
// Disk Health (S.M.A.R.T.)
// =============================================================================

// DiskHealth represents S.M.A.R.T. health data for a disk
type DiskHealth struct {
	Device        string                 `json:"device"`
	Model         string                 `json:"model"`
	Serial        string                 `json:"serial"`
	Firmware      string                 `json:"firmware"`
	Capacity      string                 `json:"capacity"`
	CapacityBytes int64                  `json:"capacity_bytes"`
	Type          string                 `json:"type"`   // HDD, SSD, NVMe
	Health        string                 `json:"health"` // PASSED, FAILED, UNKNOWN
	Temperature   int                    `json:"temperature"`
	PowerOnHours  int                    `json:"power_on_hours"`
	PowerCycles   int                    `json:"power_cycles"`
	Attributes    []SMARTAttribute       `json:"attributes,omitempty"`
	SmartEnabled  bool                   `json:"smart_enabled"`
	LastChecked   time.Time              `json:"last_checked"`
	Warnings      []string               `json:"warnings,omitempty"`
	Raw           map[string]interface{} `json:"raw,omitempty"`
}

// SMARTAttribute represents a single S.M.A.R.T. attribute
type SMARTAttribute struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Value     int    `json:"value"`
	Worst     int    `json:"worst"`
	Threshold int    `json:"threshold"`
	RawValue  string `json:"raw_value"`
	Failing   bool   `json:"failing"`
	Type      string `json:"type"` // pre-fail, old-age
}

// GetDiskHealth returns S.M.A.R.T. health data for all disks
func (m *StorageManager) GetDiskHealth() ([]DiskHealth, error) {
	var disks []DiskHealth

	// Find block devices
	devices, err := m.listBlockDevices()
	if err != nil {
		return nil, err
	}

	for _, dev := range devices {
		health, err := m.getDiskHealthInfo(dev)
		if err != nil {
			continue // Skip devices that can't be queried
		}
		disks = append(disks, *health)
	}

	return disks, nil
}

// GetDiskHealthByDevice returns S.M.A.R.T. data for a specific device
func (m *StorageManager) GetDiskHealthByDevice(device string) (*DiskHealth, error) {
	return m.getDiskHealthInfo(device)
}

func (m *StorageManager) listBlockDevices() ([]string, error) {
	var devices []string

	// Try nsenter to run lsblk on host
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "lsblk", "-d", "-n", "-o", "NAME,TYPE", "-J")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try direct lsblk
		cmd = exec.Command("lsblk", "-d", "-n", "-o", "NAME,TYPE", "-J")
		output, err = cmd.Output()
	}

	if err != nil {
		// Fallback: scan /dev and /host/dev directly
		devPaths := []string{"/dev", "/host/dev", "/hostfs/dev"}
		for _, devPath := range devPaths {
			entries, err := os.ReadDir(devPath)
			if err != nil {
				continue
			}
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "nvme") || strings.HasPrefix(name, "mmcblk") {
					// Skip partitions
					if strings.HasPrefix(name, "sd") && len(name) == 3 {
						devices = append(devices, devPath+"/"+name)
					} else if strings.HasPrefix(name, "nvme") && strings.Contains(name, "n") && !strings.Contains(name, "p") {
						devices = append(devices, devPath+"/"+name)
					} else if strings.HasPrefix(name, "mmcblk") && !strings.Contains(name, "p") {
						devices = append(devices, devPath+"/"+name)
					}
				}
			}
			if len(devices) > 0 {
				break
			}
		}
		return devices, nil
	}

	var lsblkOutput struct {
		Blockdevices []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"blockdevices"`
	}

	if err := json.Unmarshal(output, &lsblkOutput); err != nil {
		return nil, err
	}

	for _, dev := range lsblkOutput.Blockdevices {
		if dev.Type == "disk" {
			devices = append(devices, "/dev/"+dev.Name)
		}
	}

	return devices, nil
}

func (m *StorageManager) getDiskHealthInfo(device string) (*DiskHealth, error) {
	health := &DiskHealth{
		Device:      device,
		Health:      "UNKNOWN",
		LastChecked: time.Now(),
	}

	// SD/eMMC cards don't support SMART - handle gracefully
	if strings.Contains(device, "mmcblk") {
		health.Type = "SD/eMMC"
		health.Health = "N/A"
		health.Model = "SD/eMMC Card"

		// Try to get capacity from lsblk
		cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "lsblk", "-b", "-d", "-n", "-o", "SIZE", device)
		if output, err := cmd.Output(); err == nil {
			if size, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
				health.CapacityBytes = size
				health.Capacity = formatBytes(size)
			}
		}

		health.Warnings = append(health.Warnings, "SD/eMMC cards do not support S.M.A.R.T. monitoring")
		return health, nil
	}

	// Try to run smartctl via nsenter (on host)
	// First check if smartctl exists on host
	checkCmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "which", "smartctl")
	if _, err := checkCmd.Output(); err != nil {
		// Fallback: check direct path
		if _, err := exec.LookPath("smartctl"); err != nil {
			return health, fmt.Errorf("smartctl not found on host")
		}
	}

	// Get SMART info in JSON format via nsenter
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "smartctl", "-a", "-j", device)
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try direct smartctl
		cmd = exec.Command("smartctl", "-a", "-j", device)
		output, err = cmd.Output()
		if err != nil {
			// Try without JSON (older smartctl)
			return m.getDiskHealthLegacy(device)
		}
	}

	var smartData map[string]interface{}
	if err := json.Unmarshal(output, &smartData); err != nil {
		return m.getDiskHealthLegacy(device)
	}

	// Store raw data
	health.Raw = smartData

	// Parse device info
	if deviceInfo, ok := smartData["device"].(map[string]interface{}); ok {
		if name, ok := deviceInfo["name"].(string); ok {
			health.Device = name
		}
		if devType, ok := deviceInfo["type"].(string); ok {
			health.Type = strings.ToUpper(devType)
		}
	}

	// Parse model info
	if modelName, ok := smartData["model_name"].(string); ok {
		health.Model = modelName
	}
	if serial, ok := smartData["serial_number"].(string); ok {
		health.Serial = serial
	}
	if firmware, ok := smartData["firmware_version"].(string); ok {
		health.Firmware = firmware
	}

	// Parse capacity
	if userCap, ok := smartData["user_capacity"].(map[string]interface{}); ok {
		if bytes, ok := userCap["bytes"].(float64); ok {
			health.CapacityBytes = int64(bytes)
			health.Capacity = formatBytes(int64(bytes))
		}
	}

	// Determine disk type
	if rotationRate, ok := smartData["rotation_rate"].(float64); ok {
		if rotationRate == 0 {
			health.Type = "SSD"
		} else {
			health.Type = "HDD"
		}
	}
	if strings.Contains(device, "nvme") {
		health.Type = "NVMe"
	}

	// Parse SMART status
	if smartStatus, ok := smartData["smart_status"].(map[string]interface{}); ok {
		if passed, ok := smartStatus["passed"].(bool); ok {
			if passed {
				health.Health = "PASSED"
			} else {
				health.Health = "FAILED"
				health.Warnings = append(health.Warnings, "SMART overall-health self-assessment: FAILED")
			}
		}
	}

	// Check if SMART is enabled
	if smartSupport, ok := smartData["smart_support"].(map[string]interface{}); ok {
		if enabled, ok := smartSupport["enabled"].(bool); ok {
			health.SmartEnabled = enabled
		}
	}

	// Parse temperature
	if temp, ok := smartData["temperature"].(map[string]interface{}); ok {
		if current, ok := temp["current"].(float64); ok {
			health.Temperature = int(current)
		}
	}

	// Parse power on time
	if powerOn, ok := smartData["power_on_time"].(map[string]interface{}); ok {
		if hours, ok := powerOn["hours"].(float64); ok {
			health.PowerOnHours = int(hours)
		}
	}

	// Parse power cycles
	if powerCycle, ok := smartData["power_cycle_count"].(float64); ok {
		health.PowerCycles = int(powerCycle)
	}

	// Parse SMART attributes (for SATA drives)
	if ataAttrs, ok := smartData["ata_smart_attributes"].(map[string]interface{}); ok {
		if table, ok := ataAttrs["table"].([]interface{}); ok {
			for _, attrRaw := range table {
				if attr, ok := attrRaw.(map[string]interface{}); ok {
					smartAttr := SMARTAttribute{}
					if id, ok := attr["id"].(float64); ok {
						smartAttr.ID = int(id)
					}
					if name, ok := attr["name"].(string); ok {
						smartAttr.Name = name
					}
					if value, ok := attr["value"].(float64); ok {
						smartAttr.Value = int(value)
					}
					if worst, ok := attr["worst"].(float64); ok {
						smartAttr.Worst = int(worst)
					}
					if thresh, ok := attr["thresh"].(float64); ok {
						smartAttr.Threshold = int(thresh)
					}
					if raw, ok := attr["raw"].(map[string]interface{}); ok {
						if rawStr, ok := raw["string"].(string); ok {
							smartAttr.RawValue = rawStr
						}
					}
					if flags, ok := attr["flags"].(map[string]interface{}); ok {
						if prefail, ok := flags["prefailure"].(bool); ok && prefail {
							smartAttr.Type = "pre-fail"
						} else {
							smartAttr.Type = "old-age"
						}
					}
					if whenFailed, ok := attr["when_failed"].(string); ok && whenFailed != "" {
						smartAttr.Failing = true
						health.Warnings = append(health.Warnings, fmt.Sprintf("Attribute %s is failing", smartAttr.Name))
					}
					health.Attributes = append(health.Attributes, smartAttr)
				}
			}
		}
	}

	// Check for critical attributes
	m.checkCriticalAttributes(health)

	return health, nil
}

func (m *StorageManager) getDiskHealthLegacy(device string) (*DiskHealth, error) {
	health := &DiskHealth{
		Device:      device,
		Health:      "UNKNOWN",
		LastChecked: time.Now(),
	}

	// Run smartctl without JSON via nsenter
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "smartctl", "-H", "-i", device)
	output, _ := cmd.CombinedOutput()
	if len(output) == 0 {
		// Fallback to direct
		cmd = exec.Command("smartctl", "-H", "-i", device)
		output, _ = cmd.CombinedOutput()
	}
	outputStr := string(output)

	// Parse health status
	if strings.Contains(outputStr, "PASSED") {
		health.Health = "PASSED"
	} else if strings.Contains(outputStr, "FAILED") {
		health.Health = "FAILED"
	}

	// Parse model
	if match := regexp.MustCompile(`Device Model:\s+(.+)`).FindStringSubmatch(outputStr); len(match) > 1 {
		health.Model = strings.TrimSpace(match[1])
	} else if match := regexp.MustCompile(`Model Number:\s+(.+)`).FindStringSubmatch(outputStr); len(match) > 1 {
		health.Model = strings.TrimSpace(match[1])
	}

	// Parse serial
	if match := regexp.MustCompile(`Serial Number:\s+(.+)`).FindStringSubmatch(outputStr); len(match) > 1 {
		health.Serial = strings.TrimSpace(match[1])
	}

	// Determine type
	if strings.Contains(device, "nvme") {
		health.Type = "NVMe"
	} else if strings.Contains(outputStr, "Solid State") {
		health.Type = "SSD"
	} else if strings.Contains(outputStr, "Rotation Rate") {
		health.Type = "HDD"
	}

	return health, nil
}

func (m *StorageManager) checkCriticalAttributes(health *DiskHealth) {
	criticalIDs := map[int]string{
		5:   "Reallocated_Sector_Ct",
		10:  "Spin_Retry_Count",
		196: "Reallocated_Event_Count",
		197: "Current_Pending_Sector",
		198: "Offline_Uncorrectable",
	}

	for _, attr := range health.Attributes {
		if name, ok := criticalIDs[attr.ID]; ok {
			if rawVal, _ := strconv.ParseInt(strings.Fields(attr.RawValue)[0], 10, 64); rawVal > 0 {
				health.Warnings = append(health.Warnings, fmt.Sprintf("%s: %s (non-zero)", name, attr.RawValue))
			}
		}
	}
}

// =============================================================================
// Helpers
// =============================================================================

func parseBool(s string) bool {
	s = strings.ToLower(s)
	return s == "yes" || s == "true" || s == "1"
}

func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func formatBytes(bytes int64) string {
	const unit = 1000
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
