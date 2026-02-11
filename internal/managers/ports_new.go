// Package managers provides service management functionality for CubeOS.
package managers

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"cubeos-api/internal/hal"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// Port allocation scheme constants.
// This is the strict 6xxx scheme - NO EXCEPTIONS.
const (
	// System reserved (host mode services)
	PortSSH   = 22
	PortDNS   = 53
	PortDHCP  = 67
	PortHTTP  = 80
	PortHTTPS = 443

	// Infrastructure range (6000-6009)
	PortNPM      = 6000
	PortPihole   = 6001
	PortRegistry = 5000 // Exception: Registry uses standard port

	// Platform range (6010-6019)
	PortAPI       = 6010
	PortDashboard = 6011
	PortDozzle    = 6012

	// Network range (6020-6029)
	PortWireGuard = 6020
	PortOpenVPN   = 6021
	PortTor       = 6022
	PortTorCtrl   = 6023

	// AI/ML range (6030-6039)
	PortOllama    = 6030
	PortChromaDB  = 6031
	PortDocsIndex = 6032

	// User apps range (6100-6999)
	UserPortMin = 6100
	UserPortMax = 6999

	// Total available user ports
	UserPortCount = UserPortMax - UserPortMin + 1
)

// ReservedSystemPorts that cannot be allocated to user apps.
var ReservedSystemPorts = map[int]string{
	22:   "SSH",
	53:   "DNS (Pi-hole)",
	67:   "DHCP (Pi-hole)",
	68:   "DHCP Client",
	80:   "HTTP (NPM)",
	443:  "HTTPS (NPM)",
	81:   "NPM Admin",
	5000: "Registry",
	6000: "NPM Admin",
	6001: "Pi-hole Admin",
	6010: "CubeOS API",
	6011: "CubeOS Dashboard",
	6012: "Dozzle",
	6020: "WireGuard",
	6021: "OpenVPN",
	6022: "Tor SOCKS",
	6023: "Tor Control",
	6030: "Ollama",
	6031: "ChromaDB",
	6032: "Docs Indexer",
}

// PortManager handles port allocation and tracking with triple-source validation.
// It enforces the strict 6xxx port scheme and checks three sources before allocating:
//   - Database (port_allocations table) — what CubeOS thinks is allocated
//   - Swarm API (published ports) — what Docker Swarm has claimed
//   - Host OS (HAL /proc/net scan) — what's actually listening on the host
//
// A port is considered FREE only when ALL three sources agree it's available.
type PortManager struct {
	db    *sql.DB
	swarm *SwarmManager
	hal   *hal.Client
	mu    sync.RWMutex
}

// NewPortManager creates a new PortManager with triple-source validation.
// Both swarm and hal may be nil for graceful degradation — the manager
// will fall back to DB-only validation (same as pre-Group 2 behavior).
func NewPortManager(db *sql.DB, swarm *SwarmManager, hal *hal.Client) *PortManager {
	return &PortManager{
		db:    db,
		swarm: swarm,
		hal:   hal,
	}
}

// AllocateUserPort allocates the next available port in the user range (6100-6999).
// This is the backward-compatible wrapper that uses a background context.
// Prefer AllocateUserPortWithContext for new code.
func (p *PortManager) AllocateUserPort() (int, error) {
	return p.AllocateUserPortWithContext(context.Background())
}

// AllocateUserPortWithContext allocates the next available port using triple-source
// validation. It acquires the mutex and is safe to call from external code.
func (p *PortManager) AllocateUserPortWithContext(ctx context.Context) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allocateNextUserPort(ctx)
}

// allocateNextUserPort is the internal, lock-free triple-source implementation.
// MUST be called with p.mu already held.
//
// Validation order:
//  1. Query port_allocations table → dbUsed set
//  2. Query Swarm published ports → swarmUsed set (graceful degradation if unavailable)
//  3. Query HAL host listening ports → hostUsed set (graceful degradation if unavailable)
//  4. Merge all three sets + reserved system ports
//  5. Iterate 6100→6999, return first port NOT in merged set
func (p *PortManager) allocateNextUserPort(ctx context.Context) (int, error) {
	// Build merged set of all occupied ports
	occupied := make(map[int]bool)

	// Source 1: Database — port_allocations table
	dbPorts, err := p.getDBAllocatedPorts()
	if err != nil {
		return 0, fmt.Errorf("failed to query port allocations: %w", err)
	}
	for _, port := range dbPorts {
		occupied[port] = true
	}
	log.Debug().Int("db_ports", len(dbPorts)).Msg("Port validation: DB ports loaded")

	// Source 2: Swarm published ports (graceful degradation)
	swarmPorts := p.getSwarmPorts(ctx)
	for port, svcName := range swarmPorts {
		if port >= UserPortMin && port <= UserPortMax {
			if !occupied[port] {
				log.Warn().Int("port", port).Str("service", svcName).
					Msg("Port claimed by Swarm but missing from DB — blocking allocation")
			}
			occupied[port] = true
		}
	}
	log.Debug().Int("swarm_ports", len(swarmPorts)).Msg("Port validation: Swarm ports loaded")

	// Source 3: Host listening ports via HAL (graceful degradation)
	hostPorts := p.getHostPorts(ctx)
	for _, port := range hostPorts {
		if port >= UserPortMin && port <= UserPortMax {
			if !occupied[port] {
				log.Warn().Int("port", port).
					Msg("Port in use on host but missing from DB and Swarm — blocking allocation")
			}
			occupied[port] = true
		}
	}
	log.Debug().Int("host_ports", len(hostPorts)).Msg("Port validation: Host ports loaded")

	// Also block reserved system ports (belt-and-suspenders)
	for port := range ReservedSystemPorts {
		occupied[port] = true
	}

	// Find first free port in user range
	for port := UserPortMin; port <= UserPortMax; port++ {
		if !occupied[port] {
			log.Debug().Int("port", port).Msg("Port validation: allocated port")
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports in user range (%d-%d): all %d ports occupied",
		UserPortMin, UserPortMax, UserPortCount)
}

// getDBAllocatedPorts returns all ports from the port_allocations table in the user range.
func (p *PortManager) getDBAllocatedPorts() ([]int, error) {
	rows, err := p.db.Query(`
		SELECT port FROM port_allocations 
		WHERE port >= ? AND port <= ?
		ORDER BY port
	`, UserPortMin, UserPortMax)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, fmt.Errorf("failed to scan port allocation: %w", err)
		}
		ports = append(ports, port)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate port allocations: %w", err)
	}
	return ports, nil
}

// getSwarmPorts queries Swarm for all published ports.
// Returns empty map if SwarmManager is nil or Swarm is unreachable.
func (p *PortManager) getSwarmPorts(ctx context.Context) map[int]string {
	if p.swarm == nil {
		return make(map[int]string)
	}

	ports, err := p.swarm.GetAllPublishedPorts(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Port validation: Swarm query failed, proceeding without Swarm data")
		return make(map[int]string)
	}
	return ports
}

// getHostPorts queries HAL for all listening ports on the host.
// Returns empty slice if HAL client is nil or HAL is unreachable.
func (p *PortManager) getHostPorts(ctx context.Context) []int {
	if p.hal == nil {
		return nil
	}

	// Use a shorter timeout for HAL — don't block installs for too long
	halCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	listeningPorts, err := p.hal.GetListeningPorts(halCtx)
	if err != nil {
		// GetListeningPorts already does graceful degradation internally,
		// but handle any unexpected errors here too
		log.Warn().Err(err).Msg("Port validation: HAL query failed, proceeding without host data")
		return nil
	}

	ports := make([]int, 0, len(listeningPorts))
	for _, lp := range listeningPorts {
		ports = append(ports, lp.Port)
	}
	return ports
}

// AllocatePort allocates a specific port or auto-allocates if port is 0.
func (p *PortManager) AllocatePort(appID int64, port int, protocol, description string, isPrimary bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if protocol == "" {
		protocol = "tcp"
	}

	// If port is 0, auto-allocate (use lock-free variant since we already hold mu)
	if port == 0 {
		var err error
		port, err = p.allocateNextUserPort(context.Background())
		if err != nil {
			return err
		}
	}

	// Validate port is not reserved (unless it's a system app)
	if _, reserved := ReservedSystemPorts[port]; reserved {
		// Check if this is a system app by looking at the app type
		var appType string
		err := p.db.QueryRow("SELECT type FROM apps WHERE id = ?", appID).Scan(&appType)
		if err != nil {
			return fmt.Errorf("failed to look up app type for app_id %d: %w", appID, err)
		}
		if appType != "system" && appType != "platform" {
			return fmt.Errorf("port %d is reserved for system use", port)
		}
	}

	// Check if port is already allocated in DB
	var count int
	if err := p.db.QueryRow("SELECT COUNT(*) FROM port_allocations WHERE port = ? AND protocol = ?", port, protocol).Scan(&count); err != nil {
		return fmt.Errorf("failed to check port allocation: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("port %d/%s is already allocated", port, protocol)
	}

	// Insert allocation
	_, err := p.db.Exec(`
		INSERT INTO port_allocations (app_id, port, protocol, description, is_primary)
		VALUES (?, ?, ?, ?, ?)
	`, appID, port, protocol, description, isPrimary)
	return err
}

// DeallocatePort removes a port allocation.
func (p *PortManager) DeallocatePort(port int, protocol string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if protocol == "" {
		protocol = "tcp"
	}

	_, err := p.db.Exec("DELETE FROM port_allocations WHERE port = ? AND protocol = ?", port, protocol)
	return err
}

// DeallocateAppPorts removes all port allocations for an app.
func (p *PortManager) DeallocateAppPorts(appID int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec("DELETE FROM port_allocations WHERE app_id = ?", appID)
	return err
}

// IsPortAllocated checks if a port is already allocated.
func (p *PortManager) IsPortAllocated(port int, protocol string) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if protocol == "" {
		protocol = "tcp"
	}

	var count int
	err := p.db.QueryRow("SELECT COUNT(*) FROM port_allocations WHERE port = ? AND protocol = ?", port, protocol).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// IsPortReserved checks if a port is in the reserved system ports list.
func (p *PortManager) IsPortReserved(port int) bool {
	_, reserved := ReservedSystemPorts[port]
	return reserved
}

// GetPortOwner returns the app name that owns a port.
func (p *PortManager) GetPortOwner(port int, protocol string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if protocol == "" {
		protocol = "tcp"
	}

	var appName string
	err := p.db.QueryRow(`
		SELECT a.name FROM apps a
		JOIN port_allocations pa ON a.id = pa.app_id
		WHERE pa.port = ? AND pa.protocol = ?
	`, port, protocol).Scan(&appName)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return appName, err
}

// GetAppPorts returns all ports allocated to an app.
func (p *PortManager) GetAppPorts(appID int64) ([]int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	rows, err := p.db.Query("SELECT port FROM port_allocations WHERE app_id = ?", appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, fmt.Errorf("failed to scan port: %w", err)
		}
		ports = append(ports, port)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate ports: %w", err)
	}
	return ports, nil
}

// GetAllAllocations returns all port allocations.
func (p *PortManager) GetAllAllocations() ([]models.PortAllocation, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	rows, err := p.db.Query(`
		SELECT pa.id, pa.app_id, a.name, pa.port, pa.protocol, pa.description, pa.is_primary, pa.created_at
		FROM port_allocations pa
		JOIN apps a ON pa.app_id = a.id
		ORDER BY pa.port
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var allocations []models.PortAllocation
	for rows.Next() {
		var alloc models.PortAllocation
		err := rows.Scan(&alloc.ID, &alloc.AppID, &alloc.AppName, &alloc.Port,
			&alloc.Protocol, &alloc.Description, &alloc.IsPrimary, &alloc.CreatedAt)
		if err != nil {
			continue
		}
		allocations = append(allocations, alloc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate allocations: %w", err)
	}
	return allocations, nil
}

// GetPortStats returns statistics about port allocation.
func (p *PortManager) GetPortStats() (*PortStats, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := &PortStats{
		SystemRange:   "6000-6099",
		UserRange:     "6100-6999",
		ReservedCount: len(ReservedSystemPorts),
	}

	// Count allocations by type
	if err := p.db.QueryRow(`
		SELECT COUNT(*) FROM port_allocations pa
		JOIN apps a ON pa.app_id = a.id
		WHERE a.type IN ('system', 'platform')
	`).Scan(&stats.SystemAllocated); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to count system port allocations: %w", err)
	}

	if err := p.db.QueryRow(`
		SELECT COUNT(*) FROM port_allocations pa
		JOIN apps a ON pa.app_id = a.id
		WHERE a.type = 'user'
	`).Scan(&stats.UserAllocated); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to count user port allocations: %w", err)
	}

	stats.TotalAllocated = stats.SystemAllocated + stats.UserAllocated
	stats.UserPortsAvailable = UserPortCount - stats.UserAllocated

	return stats, nil
}

// PortStats holds port allocation statistics.
type PortStats struct {
	TotalAllocated     int    `json:"total_allocated"`
	SystemAllocated    int    `json:"system_allocated"`
	UserAllocated      int    `json:"user_allocated"`
	SystemRange        string `json:"system_range"`
	UserRange          string `json:"user_range"`
	ReservedCount      int    `json:"reserved_count"`
	UserPortsAvailable int    `json:"user_ports_available"`
}

// ValidatePortScheme checks if a port is valid for the given app type.
func ValidatePortScheme(port int, appType string) error {
	switch appType {
	case "system":
		// System apps can use any reserved port or 6000-6009
		if port >= 6000 && port <= 6009 {
			return nil
		}
		if _, ok := ReservedSystemPorts[port]; ok {
			return nil
		}
		return fmt.Errorf("system apps must use ports 6000-6009 or reserved system ports")

	case "platform":
		// Platform apps use 6010-6019
		if port < 6010 || port > 6019 {
			return fmt.Errorf("platform apps must use ports 6010-6019")
		}
		return nil

	case "network":
		// Network apps use 6020-6029
		if port < 6020 || port > 6029 {
			return fmt.Errorf("network apps must use ports 6020-6029")
		}
		return nil

	case "ai":
		// AI apps use 6030-6039
		if port < 6030 || port > 6039 {
			return fmt.Errorf("AI apps must use ports 6030-6039")
		}
		return nil

	case "user":
		// User apps use 6100-6999
		if port < UserPortMin || port > UserPortMax {
			return fmt.Errorf("user apps must use ports %d-%d", UserPortMin, UserPortMax)
		}
		return nil

	default:
		return fmt.Errorf("unknown app type: %s", appType)
	}
}
