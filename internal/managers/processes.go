package managers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"cubeos-api/internal/models"
)

// ProcessManager handles system process operations
type ProcessManager struct{}

// NewProcessManager creates a new ProcessManager
func NewProcessManager() *ProcessManager {
	return &ProcessManager{}
}

// ListProcesses returns running processes
func (m *ProcessManager) ListProcesses(sortBy string, limit int, filterName string) []models.ProcessInfo {
	var processes []models.ProcessInfo
	
	// Read /proc for process info
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return processes
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}
		
		proc := m.getProcessInfo(pid)
		if proc == nil {
			continue
		}
		
		// Apply filter
		if filterName != "" && !strings.Contains(strings.ToLower(proc.Name), strings.ToLower(filterName)) {
			continue
		}
		
		processes = append(processes, *proc)
	}
	
	// Sort
	switch sortBy {
	case "cpu":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].CPUPercent > processes[j].CPUPercent
		})
	case "memory":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].MemoryPercent > processes[j].MemoryPercent
		})
	case "name":
		sort.Slice(processes, func(i, j int) bool {
			return strings.ToLower(processes[i].Name) < strings.ToLower(processes[j].Name)
		})
	case "pid":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].PID < processes[j].PID
		})
	}
	
	// Apply limit
	if limit > 0 && len(processes) > limit {
		processes = processes[:limit]
	}
	
	return processes
}

func (m *ProcessManager) getProcessInfo(pid int) *models.ProcessInfo {
	procPath := fmt.Sprintf("/proc/%d", pid)
	
	// Read stat
	statPath := filepath.Join(procPath, "stat")
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return nil
	}
	
	// Parse stat - format: pid (name) state ppid ...
	statStr := string(statData)
	
	// Find process name between parentheses
	nameStart := strings.Index(statStr, "(")
	nameEnd := strings.LastIndex(statStr, ")")
	if nameStart == -1 || nameEnd == -1 {
		return nil
	}
	
	name := statStr[nameStart+1 : nameEnd]
	fields := strings.Fields(statStr[nameEnd+2:])
	
	if len(fields) < 20 {
		return nil
	}
	
	status := fields[0]
	
	// Read status file for memory info
	statusPath := filepath.Join(procPath, "status")
	statusData, _ := os.ReadFile(statusPath)
	
	var memRSS int64
	var username string
	var numThreads int
	
	scanner := bufio.NewScanner(strings.NewReader(string(statusData)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memRSS, _ = strconv.ParseInt(parts[1], 10, 64)
				memRSS *= 1024 // Convert KB to bytes
			}
		} else if strings.HasPrefix(line, "Uid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				uid, _ := strconv.Atoi(parts[1])
				username = m.getUsername(uid)
			}
		} else if strings.HasPrefix(line, "Threads:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				numThreads, _ = strconv.Atoi(parts[1])
			}
		}
	}
	
	// Read cmdline
	cmdlinePath := filepath.Join(procPath, "cmdline")
	cmdlineData, _ := os.ReadFile(cmdlinePath)
	cmdline := strings.ReplaceAll(string(cmdlineData), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)
	
	// Get total memory for percentage calculation
	totalMem := m.getTotalMemory()
	memPercent := float64(0)
	if totalMem > 0 {
		memPercent = float64(memRSS) / float64(totalMem) * 100
	}
	
	// Map status letter to string
	statusMap := map[string]string{
		"R": "running",
		"S": "sleeping",
		"D": "disk-sleep",
		"Z": "zombie",
		"T": "stopped",
		"t": "tracing-stop",
		"X": "dead",
	}
	statusStr := statusMap[status]
	if statusStr == "" {
		statusStr = status
	}
	
	return &models.ProcessInfo{
		PID:           pid,
		Name:          name,
		Username:      username,
		CPUPercent:    0, // Would need multiple samples to calculate
		MemoryPercent: memPercent,
		MemoryRSS:     memRSS,
		Status:        statusStr,
		Cmdline:       cmdline,
		NumThreads:    numThreads,
	}
}

func (m *ProcessManager) getUsername(uid int) string {
	// Try to read /etc/passwd
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return fmt.Sprintf("%d", uid)
	}
	
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 3 {
			if u, _ := strconv.Atoi(parts[2]); u == uid {
				return parts[0]
			}
		}
	}
	
	return fmt.Sprintf("%d", uid)
}

func (m *ProcessManager) getTotalMemory() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				total, _ := strconv.ParseInt(parts[1], 10, 64)
				return total * 1024 // Convert KB to bytes
			}
		}
	}
	
	return 0
}

// GetProcess returns details about a specific process
func (m *ProcessManager) GetProcess(pid int) *models.ProcessInfo {
	return m.getProcessInfo(pid)
}

// KillProcess sends a signal to a process
func (m *ProcessManager) KillProcess(pid int, signal string) *models.SuccessResponse {
	// Protected PIDs
	protectedPIDs := []int{1, 2}
	for _, p := range protectedPIDs {
		if pid == p {
			return &models.SuccessResponse{Status: "error", Message: "Cannot kill protected system process"}
		}
	}
	
	// Get process info to check name
	proc := m.getProcessInfo(pid)
	if proc == nil {
		return &models.SuccessResponse{Status: "error", Message: "Process not found"}
	}
	
	protectedNames := []string{"systemd", "init", "kernel", "kthreadd"}
	for _, name := range protectedNames {
		if strings.ToLower(proc.Name) == name {
			return &models.SuccessResponse{Status: "error", Message: "Cannot kill protected system process"}
		}
	}
	
	// Map signal name to syscall
	signalMap := map[string]syscall.Signal{
		"SIGTERM": syscall.SIGTERM,
		"SIGKILL": syscall.SIGKILL,
		"SIGHUP":  syscall.SIGHUP,
		"SIGINT":  syscall.SIGINT,
	}
	
	sig, ok := signalMap[signal]
	if !ok {
		sig = syscall.SIGTERM
	}
	
	// Find process and send signal
	process, err := os.FindProcess(pid)
	if err != nil {
		return &models.SuccessResponse{Status: "error", Message: "Process not found"}
	}
	
	if err := process.Signal(sig); err != nil {
		return &models.SuccessResponse{Status: "error", Message: err.Error()}
	}
	
	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("Signal %s sent to process %d", signal, pid),
	}
}

// GetProcessStats returns process statistics summary
func (m *ProcessManager) GetProcessStats() map[string]interface{} {
	processes := m.ListProcesses("", 0, "")
	
	byStatus := make(map[string]int)
	for _, proc := range processes {
		byStatus[proc.Status]++
	}
	
	return map[string]interface{}{
		"total_processes": len(processes),
		"by_status":       byStatus,
	}
}

// TopCPU returns processes with highest CPU usage
func (m *ProcessManager) TopCPU(limit int) []models.ProcessInfo {
	return m.ListProcesses("cpu", limit, "")
}

// TopMemory returns processes with highest memory usage
func (m *ProcessManager) TopMemory(limit int) []models.ProcessInfo {
	return m.ListProcesses("memory", limit, "")
}

// SearchProcesses searches for processes by name
func (m *ProcessManager) SearchProcesses(name string, exact bool) []models.ProcessInfo {
	var results []models.ProcessInfo
	
	processes := m.ListProcesses("", 0, "")
	for _, proc := range processes {
		if exact {
			if proc.Name == name {
				results = append(results, proc)
			}
		} else {
			if strings.Contains(strings.ToLower(proc.Name), strings.ToLower(name)) {
				results = append(results, proc)
			}
		}
	}
	
	return results
}

// GetProcessTree returns process with its children
func (m *ProcessManager) GetProcessTree(pid int) map[string]interface{} {
	proc := m.getProcessInfo(pid)
	if proc == nil {
		return nil
	}
	
	// Find children by reading all processes and checking ppid
	var children []int
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		childPID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		
		statPath := fmt.Sprintf("/proc/%d/stat", childPID)
		statData, err := os.ReadFile(statPath)
		if err != nil {
			continue
		}
		
		// Parse ppid from stat
		statStr := string(statData)
		nameEnd := strings.LastIndex(statStr, ")")
		if nameEnd == -1 {
			continue
		}
		
		fields := strings.Fields(statStr[nameEnd+2:])
		if len(fields) >= 2 {
			ppid, _ := strconv.Atoi(fields[1])
			if ppid == pid {
				children = append(children, childPID)
			}
		}
	}
	
	return map[string]interface{}{
		"process":  proc,
		"children": children,
	}
}

// Pgrep finds processes by pattern (like pgrep command)
func (m *ProcessManager) Pgrep(pattern string) []int {
	var pids []int
	
	cmd := exec.Command("pgrep", "-f", pattern)
	output, err := cmd.Output()
	if err != nil {
		return pids
	}
	
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		if pid, err := strconv.Atoi(strings.TrimSpace(scanner.Text())); err == nil {
			pids = append(pids, pid)
		}
	}
	
	return pids
}
