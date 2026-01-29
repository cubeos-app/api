package managers

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cubeos-api/internal/models"
)

// LogManager handles system and container logs
type LogManager struct{}

// NewLogManager creates a new LogManager
func NewLogManager() *LogManager {
	return &LogManager{}
}

// GetJournalLogs retrieves logs from systemd journal or falls back to syslog
func (m *LogManager) GetJournalLogs(unit string, lines int, since, until, priority, grep string) []models.LogEntry {
	var entries []models.LogEntry

	// First try journalctl (may not be available in Alpine)
	entries = m.tryJournalctl(unit, lines, since, until, priority, grep)
	if len(entries) > 0 {
		return entries
	}

	// Fallback: read traditional syslog files
	return m.readSyslogFiles(unit, lines, grep)
}

// tryJournalctl attempts to use journalctl command
func (m *LogManager) tryJournalctl(unit string, lines int, since, until, priority, grep string) []models.LogEntry {
	var entries []models.LogEntry

	// Check if journalctl exists
	if _, err := exec.LookPath("journalctl"); err != nil {
		return entries
	}

	// Try multiple journal directories (container vs host-mounted)
	journalDirs := []string{
		"/var/log/journal", // Standard persistent journal location
		"/run/log/journal", // Runtime journal location
	}

	var journalDir string
	for _, dir := range journalDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			// Check if directory has content
			dirEntries, _ := os.ReadDir(dir)
			if len(dirEntries) > 0 {
				journalDir = dir
				break
			}
		}
	}

	if journalDir == "" {
		return entries
	}

	args := []string{
		"-D", journalDir,
		"--no-pager",
		"--output=json",
	}

	if lines > 0 {
		args = append(args, fmt.Sprintf("-n%d", lines))
	}

	if unit != "" {
		args = append(args, "-u", unit)
	}

	if since != "" {
		args = append(args, "--since", since)
	}

	if until != "" {
		args = append(args, "--until", until)
	}

	if priority != "" {
		args = append(args, "-p", priority)
	}

	if grep != "" {
		args = append(args, "-g", grep)
	}

	cmd := exec.Command("journalctl", args...)
	output, err := cmd.Output()
	if err != nil {
		return entries
	}

	// Parse JSON lines
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		entry := m.parseJournalLine(line)
		if entry.Message != "" {
			entries = append(entries, entry)
		}
	}

	return entries
}

// readSyslogFiles reads traditional /var/log files as fallback
func (m *LogManager) readSyslogFiles(unit string, lines int, grep string) []models.LogEntry {
	var entries []models.LogEntry

	// Try common syslog locations (both host-mounted and container paths)
	logFiles := []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/daemon.log",
		"/host/var/log/syslog",
		"/host/var/log/messages",
	}

	var logFile string
	for _, f := range logFiles {
		if info, err := os.Stat(f); err == nil && !info.IsDir() {
			logFile = f
			break
		}
	}

	if logFile == "" {
		// No syslog files found, return empty
		return entries
	}

	file, err := os.Open(logFile)
	if err != nil {
		return entries
	}
	defer file.Close()

	var allLines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Filter by unit if specified
		if unit != "" && !strings.Contains(line, unit) {
			continue
		}

		// Filter by grep pattern
		if grep != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(grep)) {
			continue
		}

		allLines = append(allLines, line)
	}

	// Get last N lines
	if lines > 0 && len(allLines) > lines {
		allLines = allLines[len(allLines)-lines:]
	}

	// Convert to LogEntry format
	for _, line := range allLines {
		entry := m.parseSyslogLine(line)
		entries = append(entries, entry)
	}

	return entries
}

// parseSyslogLine parses a traditional syslog line
func (m *LogManager) parseSyslogLine(line string) models.LogEntry {
	entry := models.LogEntry{
		Priority: "info",
		Message:  line,
	}

	// Try to parse standard syslog format: "Mon DD HH:MM:SS hostname service[pid]: message"
	// Example: "Jan 28 03:45:12 nllei01mule01 dockerd[1234]: Starting container"
	// Or kernel: "Jan 28 03:45:12 nllei01mule01 kernel: [12345.678] docker0: port 1..."

	// Match timestamp pattern at start
	timestampRegex := regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)

	if matches := timestampRegex.FindStringSubmatch(line); len(matches) >= 5 {
		// Parse timestamp
		if t, err := time.Parse("Jan 2 15:04:05", matches[1]); err == nil {
			t = t.AddDate(time.Now().Year(), 0, 0)
			entry.Timestamp = &t
		}

		// Hostname
		entry.Hostname = matches[2]

		// Unit/service
		entry.Unit = matches[3]

		// PID (optional)
		if len(matches) > 4 && matches[4] != "" {
			if pid, err := strconv.Atoi(matches[4]); err == nil {
				entry.PID = &pid
			}
		}

		// Message
		if len(matches) > 5 {
			entry.Message = matches[5]
		}
	}

	// Detect priority from message content
	msgLower := strings.ToLower(entry.Message)
	if strings.Contains(msgLower, "error") || strings.Contains(msgLower, "fail") {
		entry.Priority = "err"
	} else if strings.Contains(msgLower, "warn") {
		entry.Priority = "warning"
	} else if strings.Contains(msgLower, "debug") {
		entry.Priority = "debug"
	}

	return entry
}

func (m *LogManager) parseJournalLine(line string) models.LogEntry {
	entry := models.LogEntry{
		Priority: "info",
	}

	// Simple JSON parsing for common fields
	// __REALTIME_TIMESTAMP, MESSAGE, _SYSTEMD_UNIT, PRIORITY, _HOSTNAME, _PID

	if match := regexp.MustCompile(`"MESSAGE"\s*:\s*"([^"]*)"?`).FindStringSubmatch(line); len(match) > 1 {
		entry.Message = match[1]
	}

	if match := regexp.MustCompile(`"_SYSTEMD_UNIT"\s*:\s*"([^"]*)"?`).FindStringSubmatch(line); len(match) > 1 {
		entry.Unit = match[1]
	}

	if match := regexp.MustCompile(`"_HOSTNAME"\s*:\s*"([^"]*)"?`).FindStringSubmatch(line); len(match) > 1 {
		entry.Hostname = match[1]
	}

	if match := regexp.MustCompile(`"_PID"\s*:\s*"?(\d+)"?`).FindStringSubmatch(line); len(match) > 1 {
		if pid, err := strconv.Atoi(match[1]); err == nil {
			entry.PID = &pid
		}
	}

	if match := regexp.MustCompile(`"PRIORITY"\s*:\s*"?(\d+)"?`).FindStringSubmatch(line); len(match) > 1 {
		priorities := map[string]string{
			"0": "emerg", "1": "alert", "2": "crit", "3": "err",
			"4": "warning", "5": "notice", "6": "info", "7": "debug",
		}
		if p, ok := priorities[match[1]]; ok {
			entry.Priority = p
		}
	}

	if match := regexp.MustCompile(`"__REALTIME_TIMESTAMP"\s*:\s*"?(\d+)"?`).FindStringSubmatch(line); len(match) > 1 {
		if ts, err := strconv.ParseInt(match[1], 10, 64); err == nil {
			t := time.Unix(ts/1000000, (ts%1000000)*1000)
			entry.Timestamp = &t
		}
	}

	return entry
}

// GetAvailableUnits returns list of systemd units with logs
func (m *LogManager) GetAvailableUnits() []string {
	var units []string

	// Check if journalctl exists
	if _, err := exec.LookPath("journalctl"); err != nil {
		// Fallback: return common service names
		return []string{"docker.service", "hostapd.service", "dnsmasq.service", "nginx.service", "ssh.service"}
	}

	// Find journal directory
	journalDirs := []string{"/var/log/journal", "/run/log/journal"}
	var journalDir string
	for _, dir := range journalDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			entries, _ := os.ReadDir(dir)
			if len(entries) > 0 {
				journalDir = dir
				break
			}
		}
	}

	if journalDir == "" {
		return []string{"docker.service", "hostapd.service", "dnsmasq.service", "nginx.service", "ssh.service"}
	}

	args := []string{"-D", journalDir, "--no-pager", "-F", "_SYSTEMD_UNIT"}

	cmd := exec.Command("journalctl", args...)
	output, err := cmd.Output()
	if err != nil {
		return units
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		unit := strings.TrimSpace(scanner.Text())
		if unit != "" {
			units = append(units, unit)
		}
	}

	return units
}

// GetContainerLogs retrieves logs from a Docker container
func (m *LogManager) GetContainerLogs(ctx context.Context, container string, lines int, since string, timestamps bool) []string {
	var entries []string

	// Try to resolve the container name - Docker might need different formats
	containerNames := []string{
		container,                      // exact name: "syncthing"
		"mulecube-" + container + "-1", // compose format: "mulecube-syncthing-1"
		"mulecube-" + container,        // short compose: "mulecube-syncthing"
		container + "-1",               // simple suffix: "syncthing-1"
	}

	// Try each name format until one works
	for _, name := range containerNames {
		args := []string{"logs"}

		if lines > 0 {
			args = append(args, "--tail", fmt.Sprintf("%d", lines))
		}

		if since != "" {
			args = append(args, "--since", since)
		}

		if timestamps {
			args = append(args, "--timestamps")
		}

		args = append(args, name)

		cmd := exec.CommandContext(ctx, "docker", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue // Try next name format
		}

		// If we got output, parse it
		if len(output) > 0 {
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				entries = append(entries, scanner.Text())
			}
			if len(entries) > 0 {
				return entries
			}
		}
	}

	// Fallback: try to find container by partial name match
	listCmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--format", "{{.Names}}")
	listOutput, err := listCmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(listOutput)))
		for scanner.Scan() {
			name := scanner.Text()
			// Check if this container name contains our search term
			if strings.Contains(strings.ToLower(name), strings.ToLower(container)) {
				args := []string{"logs"}
				if lines > 0 {
					args = append(args, "--tail", fmt.Sprintf("%d", lines))
				}
				if since != "" {
					args = append(args, "--since", since)
				}
				if timestamps {
					args = append(args, "--timestamps")
				}
				args = append(args, name)

				cmd := exec.CommandContext(ctx, "docker", args...)
				output, err := cmd.CombinedOutput()
				if err == nil && len(output) > 0 {
					logScanner := bufio.NewScanner(strings.NewReader(string(output)))
					for logScanner.Scan() {
						entries = append(entries, logScanner.Text())
					}
					return entries
				}
			}
		}
	}

	return entries
}

// GetKernelLogs retrieves kernel messages (dmesg)
func (m *LogManager) GetKernelLogs(lines int) []string {
	var entries []string

	// Try dmesg first
	args := []string{"-T"}
	cmd := exec.Command("dmesg", args...)
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			entries = append(entries, scanner.Text())
		}

		// Return last N lines
		if lines > 0 && len(entries) > lines {
			entries = entries[len(entries)-lines:]
		}
		return entries
	}

	// Fallback: read kernel log files
	kernLogPaths := []string{
		"/var/log/kern.log",
		"/host/var/log/kern.log",
		"/var/log/dmesg",
		"/host/var/log/dmesg",
		"/var/log/messages",
		"/host/var/log/messages",
	}

	for _, path := range kernLogPaths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		var allLines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			// Filter for kernel messages
			if strings.Contains(line, "kernel:") || strings.Contains(line, "kernel[") {
				allLines = append(allLines, line)
			}
		}

		if len(allLines) > 0 {
			// Return last N lines
			if lines > 0 && len(allLines) > lines {
				allLines = allLines[len(allLines)-lines:]
			}
			return allLines
		}
	}

	// Last resort: try reading syslog and filter kernel messages
	syslogPaths := []string{"/var/log/syslog", "/host/var/log/syslog"}
	for _, path := range syslogPaths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		var kernelLines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "kernel:") || strings.Contains(line, "kernel[") {
				kernelLines = append(kernelLines, line)
			}
		}

		if len(kernelLines) > 0 {
			if lines > 0 && len(kernelLines) > lines {
				kernelLines = kernelLines[len(kernelLines)-lines:]
			}
			return kernelLines
		}
	}

	return entries
}

// GetBootLogs retrieves logs from a specific boot
func (m *LogManager) GetBootLogs(bootID int, lines int) []models.LogEntry {
	// Find journal directory
	journalDirs := []string{"/var/log/journal", "/run/log/journal"}
	var journalDir string
	for _, dir := range journalDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			entries, _ := os.ReadDir(dir)
			if len(entries) > 0 {
				journalDir = dir
				break
			}
		}
	}

	args := []string{
		"--no-pager",
		"--output=json",
		fmt.Sprintf("-b%d", bootID),
	}

	if journalDir != "" {
		args = append([]string{"-D", journalDir}, args...)
	}

	if lines > 0 {
		args = append(args, fmt.Sprintf("-n%d", lines))
	}

	cmd := exec.Command("journalctl", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var entries []models.LogEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		entry := m.parseJournalLine(scanner.Text())
		if entry.Message != "" {
			entries = append(entries, entry)
		}
	}

	return entries
}

// ReadLogFile reads from a traditional log file
func (m *LogManager) ReadLogFile(path string, lines int, grep string) ([]string, error) {
	// Security check - only allow /var/log
	if !strings.HasPrefix(path, "/var/log/") && !strings.HasPrefix(path, "/host/var/log/") {
		return nil, fmt.Errorf("only /var/log/ access allowed")
	}

	// Try host-mounted path first
	actualPath := path
	if _, err := os.Stat(path); os.IsNotExist(err) {
		actualPath = "/host" + path
	}

	file, err := os.Open(actualPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var allLines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if grep == "" || strings.Contains(strings.ToLower(line), strings.ToLower(grep)) {
			allLines = append(allLines, line)
		}
	}

	// Return last N lines
	if lines > 0 && len(allLines) > lines {
		allLines = allLines[len(allLines)-lines:]
	}

	return allLines, nil
}

// GetRecentErrors retrieves recent error-level logs
func (m *LogManager) GetRecentErrors(lines int, hours int) []models.LogEntry {
	since := fmt.Sprintf("%d hours ago", hours)
	return m.GetJournalLogs("", lines, since, "", "err", "")
}
