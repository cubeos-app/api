package managers

import (
	"database/sql"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Note: Port range constants (SystemPortMin, SystemPortMax, UserPortMin, UserPortMax)
// are defined in appmanager.go and available here since we're in the same package.

// ReservedPorts that cannot be allocated
var ReservedPorts = map[int]bool{
	22:    true, // SSH
	53:    true, // DNS
	67:    true, // DHCP
	68:    true, // DHCP
	80:    true, // HTTP
	81:    true, // NPM admin
	443:   true, // HTTPS
	5000:  true, // Registry
	5001:  true, // Registry
	8000:  true, // Common dev
	8080:  true, // Common dev
	9009:  true, // CubeOS API
	11434: true, // Ollama
}

// PortManager handles port allocation and tracking
type PortManager struct {
	db *sql.DB
	mu sync.RWMutex
}

// PortAllocation represents an allocated port
type PortAllocation struct {
	ID          int64  `json:"id"`
	AppID       int64  `json:"app_id"`
	AppName     string `json:"app_name"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	InUse       bool   `json:"in_use"` // From ss -tulnp check
	CreatedAt   string `json:"created_at"`
}

// ListeningPort represents a port from ss -tulnp
type ListeningPort struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Process   string `json:"process"`
	LocalAddr string `json:"local_addr"`
}

// NewPortManager creates a new port manager
func NewPortManager(db *sql.DB) *PortManager {
	return &PortManager{db: db}
}

// InitSchema creates the port_allocations table
func (m *PortManager) InitSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS port_allocations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		app_id INTEGER NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp',
		description TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(port, protocol)
	);
	CREATE INDEX IF NOT EXISTS idx_ports_port ON port_allocations(port);
	CREATE INDEX IF NOT EXISTS idx_ports_app ON port_allocations(app_id);
	`
	_, err := m.db.Exec(schema)
	return err
}

// GetListeningPorts returns all ports currently listening (from ss -tulnp)
func (m *PortManager) GetListeningPorts() ([]ListeningPort, error) {
	var ports []ListeningPort

	// Run ss -tulnp
	cmd := exec.Command("ss", "-tulnp")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		cmd = exec.Command("netstat", "-tulnp")
		output, err = cmd.Output()
		if err != nil {
			return ports, nil // Return empty if neither works
		}
	}

	// Parse output
	lines := strings.Split(string(output), "\n")
	portRe := regexp.MustCompile(`(?::|\s)(\d+)\s`)
	processRe := regexp.MustCompile(`users:\(\("([^"]+)"`)

	for _, line := range lines[1:] { // Skip header
		if line == "" {
			continue
		}

		// Determine protocol
		protocol := "tcp"
		if strings.HasPrefix(line, "udp") {
			protocol = "udp"
		}

		// Extract port
		portMatches := portRe.FindAllStringSubmatch(line, -1)
		if len(portMatches) == 0 {
			continue
		}

		// Get the first port match (local port)
		port, err := strconv.Atoi(portMatches[0][1])
		if err != nil {
			continue
		}

		// Extract process name
		process := ""
		processMatches := processRe.FindStringSubmatch(line)
		if len(processMatches) > 1 {
			process = processMatches[1]
		}

		// Get local address
		fields := strings.Fields(line)
		localAddr := ""
		if len(fields) >= 5 {
			localAddr = fields[4]
		}

		ports = append(ports, ListeningPort{
			Port:      port,
			Protocol:  protocol,
			Process:   process,
			LocalAddr: localAddr,
		})
	}

	return ports, nil
}

// GetListeningPortsMap returns listening ports as a map for quick lookup
func (m *PortManager) GetListeningPortsMap() map[int]bool {
	ports, _ := m.GetListeningPorts()
	portMap := make(map[int]bool)
	for _, p := range ports {
		portMap[p.Port] = true
	}
	return portMap
}

// IsPortInUse checks if a port is in use (database + ss -tulnp + reserved)
func (m *PortManager) IsPortInUse(port int) bool {
	// Check reserved
	if ReservedPorts[port] {
		return true
	}

	// Check database
	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM port_allocations WHERE port = ?", port).Scan(&count)
	if count > 0 {
		return true
	}

	// Check ss -tulnp
	listeningPorts := m.GetListeningPortsMap()
	return listeningPorts[port]
}

// GetAvailablePort finds the next available port in a range
func (m *PortManager) GetAvailablePort(portType string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Use constants from appmanager.go (same package)
	minPort, maxPort := UserPortMin, UserPortMax
	if portType == "system" {
		minPort, maxPort = SystemPortMin, SystemPortMax
	}

	listeningPorts := m.GetListeningPortsMap()

	for port := minPort; port <= maxPort; port++ {
		// Skip reserved
		if ReservedPorts[port] {
			continue
		}

		// Skip if listening
		if listeningPorts[port] {
			continue
		}

		// Check database
		var count int
		m.db.QueryRow("SELECT COUNT(*) FROM port_allocations WHERE port = ?", port).Scan(&count)
		if count == 0 {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports in range %d-%d", minPort, maxPort)
}

// ListAllocations returns all port allocations with app names
func (m *PortManager) ListAllocations() ([]PortAllocation, error) {
	rows, err := m.db.Query(`
		SELECT pa.id, pa.app_id, COALESCE(a.name, 'unknown'), pa.port, pa.protocol, pa.description, pa.created_at
		FROM port_allocations pa
		LEFT JOIN apps a ON pa.app_id = a.id
		ORDER BY pa.port
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query port allocations: %w", err)
	}
	defer rows.Close()

	listeningPorts := m.GetListeningPortsMap()

	var allocations []PortAllocation
	for rows.Next() {
		var pa PortAllocation
		if err := rows.Scan(&pa.ID, &pa.AppID, &pa.AppName, &pa.Port, &pa.Protocol, &pa.Description, &pa.CreatedAt); err != nil {
			continue
		}
		pa.InUse = listeningPorts[pa.Port]
		allocations = append(allocations, pa)
	}

	return allocations, nil
}

// Allocate allocates a port to an app
func (m *PortManager) Allocate(appID int64, port int, protocol, description string) (*PortAllocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if protocol == "" {
		protocol = "tcp"
	}

	// Validate port
	if port > 0 {
		if m.IsPortInUse(port) {
			return nil, fmt.Errorf("port %d is already in use", port)
		}
	} else {
		// Auto-assign
		var err error
		port, err = m.GetAvailablePort("user")
		if err != nil {
			return nil, err
		}
	}

	// Insert allocation
	result, err := m.db.Exec(`
		INSERT INTO port_allocations (app_id, port, protocol, description)
		VALUES (?, ?, ?, ?)
	`, appID, port, protocol, description)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	id, _ := result.LastInsertId()

	// Get app name
	var appName string
	m.db.QueryRow("SELECT name FROM apps WHERE id = ?", appID).Scan(&appName)

	return &PortAllocation{
		ID:          id,
		AppID:       appID,
		AppName:     appName,
		Port:        port,
		Protocol:    protocol,
		Description: description,
		InUse:       false,
	}, nil
}

// Release releases a port allocation
func (m *PortManager) Release(port int, protocol string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if protocol == "" {
		protocol = "tcp"
	}

	result, err := m.db.Exec("DELETE FROM port_allocations WHERE port = ? AND protocol = ?", port, protocol)
	if err != nil {
		return fmt.Errorf("failed to release port: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("port %d/%s not found in allocations", port, protocol)
	}

	return nil
}

// GetAppPorts returns all ports allocated to an app
func (m *PortManager) GetAppPorts(appID int64) ([]PortAllocation, error) {
	rows, err := m.db.Query(`
		SELECT id, app_id, port, protocol, description, created_at
		FROM port_allocations WHERE app_id = ?
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	listeningPorts := m.GetListeningPortsMap()

	var allocations []PortAllocation
	for rows.Next() {
		var pa PortAllocation
		if err := rows.Scan(&pa.ID, &pa.AppID, &pa.Port, &pa.Protocol, &pa.Description, &pa.CreatedAt); err != nil {
			continue
		}
		pa.InUse = listeningPorts[pa.Port]
		allocations = append(allocations, pa)
	}

	return allocations, nil
}

// SyncFromSystem scans running containers and creates allocations for their ports
func (m *PortManager) SyncFromSystem(composeManager *ComposeManager) error {
	apps, err := composeManager.ListApps()
	if err != nil {
		return err
	}

	for _, appName := range apps {
		// Get app ID
		var appID int64
		err := m.db.QueryRow("SELECT id FROM apps WHERE name = ?", appName).Scan(&appID)
		if err != nil {
			continue // App not in database
		}

		// Get compose config
		config, err := composeManager.GetConfig(appName)
		if err != nil {
			continue
		}

		// Extract ports from compose
		ports := composeManager.ExtractPorts(config.ComposeFile)

		for _, p := range ports {
			// Check if already allocated
			var count int
			m.db.QueryRow("SELECT COUNT(*) FROM port_allocations WHERE port = ?", p.HostPort).Scan(&count)
			if count > 0 {
				continue
			}

			// Allocate
			m.db.Exec(`
				INSERT OR IGNORE INTO port_allocations (app_id, port, protocol, description)
				VALUES (?, ?, ?, ?)
			`, appID, p.HostPort, p.Protocol, fmt.Sprintf("Auto-synced from %s", appName))
		}
	}

	return nil
}

// SyncFromDockerPS scans running containers via docker ps and creates allocations
// This complements SyncFromSystem (compose files) by detecting actual runtime ports
func (m *PortManager) SyncFromDockerPS(db *sql.DB) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Run docker ps to get running containers with their ports
	cmd := exec.Command("docker", "ps", "--format", "{{.Names}}:{{.Ports}}")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run docker ps: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	// Enhanced regex to handle various port formats:
	// - 0.0.0.0:6004->8080/tcp
	// - :::6004->8080/tcp (IPv6)
	// - 192.168.42.1:80->80/tcp
	// - 80/tcp (exposed but not mapped)
	portRe := regexp.MustCompile(`(?:[\d.:[\]]+:)?(\d+)->(\d+)/(tcp|udp)`)

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}

		containerName := parts[0]
		portsStr := parts[1]

		// Extract app name from container name
		appName := containerName
		if strings.HasPrefix(containerName, "cubeos-") {
			appName = strings.TrimPrefix(containerName, "cubeos-")
		} else if strings.HasPrefix(containerName, "mulecube-") {
			appName = strings.TrimPrefix(containerName, "mulecube-")
		}

		// Get app ID from database - try multiple strategies
		var appID int64
		err := db.QueryRow("SELECT id FROM apps WHERE name = ?", appName).Scan(&appID)
		if err != nil {
			// Try with container name
			err = db.QueryRow("SELECT id FROM apps WHERE name = ?", containerName).Scan(&appID)
			if err != nil {
				// Try partial match (e.g., "logs" for container "cubeos-logs")
				err = db.QueryRow("SELECT id FROM apps WHERE ? LIKE '%' || name || '%'", containerName).Scan(&appID)
				if err != nil {
					// App not found - create it on the fly if it's a cubeos container
					if strings.HasPrefix(containerName, "cubeos-") || strings.HasPrefix(containerName, "mulecube-") {
						displayName := strings.ReplaceAll(appName, "-", " ")
						displayName = strings.Title(displayName)
						result, err := db.Exec(`
							INSERT OR IGNORE INTO apps (name, display_name, description, type, source, enabled)
							VALUES (?, ?, '', 'system', 'cubeos', TRUE)
						`, appName, displayName)
						if err == nil {
							appID, _ = result.LastInsertId()
							if appID == 0 {
								// INSERT OR IGNORE didn't insert, get existing ID
								db.QueryRow("SELECT id FROM apps WHERE name = ?", appName).Scan(&appID)
							}
						}
					}
					if appID == 0 {
						continue // Skip if we still can't match
					}
				}
			}
		}

		// Extract all port mappings
		matches := portRe.FindAllStringSubmatch(portsStr, -1)
		for _, match := range matches {
			if len(match) < 4 {
				continue
			}

			hostPort, _ := strconv.Atoi(match[1])
			protocol := match[3]

			if hostPort == 0 {
				continue
			}

			// Note: We now include reserved ports in tracking, just mark them differently
			description := fmt.Sprintf("Auto-synced from container %s", containerName)
			if ReservedPorts[hostPort] {
				description = fmt.Sprintf("System port from container %s", containerName)
			}

			var count int
			db.QueryRow("SELECT COUNT(*) FROM port_allocations WHERE port = ?", hostPort).Scan(&count)
			if count > 0 {
				continue
			}

			db.Exec(`
				INSERT OR IGNORE INTO port_allocations (app_id, port, protocol, description)
				VALUES (?, ?, ?, ?)
			`, appID, hostPort, protocol, description)
		}
	}

	return nil
}

// SyncFromSystemEnhanced combines compose file scanning AND docker ps scanning
func (m *PortManager) SyncFromSystemEnhanced(composeManager *ComposeManager, db *sql.DB) error {
	// First, sync from compose files
	if err := m.SyncFromSystem(composeManager); err != nil {
		// Log but continue
	}

	// Then, sync from running containers
	if err := m.SyncFromDockerPS(db); err != nil {
		// Log but continue
	}

	return nil
}

// GetPortStats returns statistics about port usage
func (m *PortManager) GetPortStats() map[string]interface{} {
	var totalAllocated, systemAllocated, userAllocated int

	m.db.QueryRow("SELECT COUNT(*) FROM port_allocations").Scan(&totalAllocated)
	m.db.QueryRow("SELECT COUNT(*) FROM port_allocations WHERE port >= ? AND port <= ?", SystemPortMin, SystemPortMax).Scan(&systemAllocated)
	m.db.QueryRow("SELECT COUNT(*) FROM port_allocations WHERE port >= ? AND port <= ?", UserPortMin, UserPortMax).Scan(&userAllocated)

	listeningPorts := m.GetListeningPortsMap()

	return map[string]interface{}{
		"total_allocated":        totalAllocated,
		"system_allocated":       systemAllocated,
		"user_allocated":         userAllocated,
		"system_range":           fmt.Sprintf("%d-%d", SystemPortMin, SystemPortMax),
		"user_range":             fmt.Sprintf("%d-%d", UserPortMin, UserPortMax),
		"reserved_count":         len(ReservedPorts),
		"currently_listening":    len(listeningPorts),
		"system_ports_available": (SystemPortMax - SystemPortMin + 1) - systemAllocated,
		"user_ports_available":   (UserPortMax - UserPortMin + 1) - userAllocated,
	}
}
