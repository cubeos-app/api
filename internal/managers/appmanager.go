package managers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"cubeos-api/internal/models"
)

// Port ranges
const (
	SystemPortMin = 6000
	SystemPortMax = 6999
	UserPortMin   = 7000
	UserPortMax   = 7999
)

// Reserved ports that cannot be allocated
var reservedPorts = map[int]bool{
	22: true, 53: true, 80: true, 81: true, 443: true,
	5000: true, 5001: true, 8000: true, 8080: true, 9009: true, 11434: true,
}

// AppManager manages applications, ports, FQDNs, and profiles
type AppManager struct {
	db             *sql.DB
	dataDir        string
	registryURL    string
	npmManager     *NPMManager
	piholeManager  *PiholeManager
	composeManager *ComposeManager
	portManager    *PortManager
	mu             sync.RWMutex
}

// NewAppManager creates a new AppManager
func NewAppManager(db *sql.DB, dataDir string) *AppManager {
	mgr := &AppManager{
		db:             db,
		dataDir:        dataDir,
		registryURL:    "localhost:5000",
		npmManager:     NewNPMManager(filepath.Join(dataDir, "config")),
		piholeManager:  NewPiholeManager(filepath.Dir(dataDir)),
		composeManager: NewComposeManager(filepath.Dir(dataDir)),
		portManager:    NewPortManager(db),
	}
	// Initialize NPM token in background
	go mgr.npmManager.Init()
	return mgr
}

// InitSchema creates the required database tables
func (m *AppManager) InitSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS apps (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		display_name TEXT NOT NULL,
		description TEXT DEFAULT '',
		type TEXT NOT NULL DEFAULT 'user',
		source TEXT DEFAULT 'custom',
		icon_url TEXT DEFAULT '',
		github_repo TEXT DEFAULT '',
		compose_path TEXT DEFAULT '',
		enabled BOOLEAN DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_apps_name ON apps(name);
	CREATE INDEX IF NOT EXISTS idx_apps_type ON apps(type);

	CREATE TABLE IF NOT EXISTS port_allocations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		app_id INTEGER NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp',
		description TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
		UNIQUE(port, protocol)
	);
	CREATE INDEX IF NOT EXISTS idx_ports_app ON port_allocations(app_id);
	CREATE INDEX IF NOT EXISTS idx_ports_port ON port_allocations(port);

	CREATE TABLE IF NOT EXISTS fqdns (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		app_id INTEGER NOT NULL,
		fqdn TEXT UNIQUE NOT NULL,
		subdomain TEXT NOT NULL,
		backend_port INTEGER NOT NULL,
		ssl_enabled BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_fqdns_app ON fqdns(app_id);

	CREATE TABLE IF NOT EXISTS profiles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT DEFAULT '',
		is_active BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS profile_apps (
		profile_id INTEGER NOT NULL,
		app_id INTEGER NOT NULL,
		enabled BOOLEAN DEFAULT TRUE,
		PRIMARY KEY (profile_id, app_id),
		FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
		FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
	);
	`
	_, err := m.db.Exec(schema)
	return err
}

// SeedSystemApps adds default system apps if they don't exist
func (m *AppManager) SeedSystemApps() error {
	systemApps := []models.App{
		{Name: "pihole", DisplayName: "Pi-hole", Description: "Network-wide DNS and ad blocking", Type: "system", Source: "cubeos"},
		{Name: "npm", DisplayName: "Nginx Proxy Manager", Description: "Reverse proxy management", Type: "system", Source: "cubeos"},
		{Name: "dockge", DisplayName: "Dockge", Description: "Docker compose management", Type: "system", Source: "cubeos"},
		{Name: "dozzle", DisplayName: "Dozzle", Description: "Real-time container log viewer", Type: "system", Source: "cubeos"},
		{Name: "ollama", DisplayName: "Ollama", Description: "Local LLM inference server", Type: "system", Source: "cubeos"},
		{Name: "chromadb", DisplayName: "ChromaDB", Description: "Vector database for AI", Type: "system", Source: "cubeos"},
		{Name: "backup", DisplayName: "Backup Service", Description: "Automated backup management", Type: "system", Source: "cubeos"},
		{Name: "terminal", DisplayName: "Web Terminal", Description: "Browser-based terminal access", Type: "system", Source: "cubeos"},
		{Name: "watchdog", DisplayName: "Watchdog", Description: "Service health monitoring", Type: "system", Source: "cubeos"},
		{Name: "orchestrator", DisplayName: "Orchestrator", Description: "Service orchestration", Type: "system", Source: "cubeos"},
	}

	for _, app := range systemApps {
		// Get compose path - will auto-discover from /cubeos/coreapps/{name}/appconfig/docker-compose.yml
		composePath := m.composeManager.GetComposePath(app.Name)

		// Only set compose_path if the file actually exists
		if _, err := os.Stat(composePath); err != nil {
			composePath = "" // File doesn't exist, leave empty
		}

		_, err := m.db.Exec(`
			INSERT OR IGNORE INTO apps (name, display_name, description, type, source, compose_path, enabled)
			VALUES (?, ?, ?, ?, ?, ?, TRUE)
		`, app.Name, app.DisplayName, app.Description, app.Type, app.Source, composePath)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateAppComposePaths updates compose_path for existing apps by auto-discovering compose files
func (m *AppManager) UpdateAppComposePaths() error {
	rows, err := m.db.Query("SELECT id, name FROM apps WHERE compose_path = '' OR compose_path IS NULL")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			continue
		}

		// Try to find compose file
		composePath := m.composeManager.GetComposePath(name)
		if _, err := os.Stat(composePath); err == nil {
			m.db.Exec("UPDATE apps SET compose_path = ? WHERE id = ?", composePath, id)
		}
	}

	return nil
}

// SeedDefaultProfiles creates default profiles if none exist
func (m *AppManager) SeedDefaultProfiles() error {
	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM profiles").Scan(&count)
	if count > 0 {
		return nil
	}

	profiles := []struct {
		name        string
		description string
		isActive    bool
	}{
		{"Full", "All services enabled", true},
		{"Minimal", "Core services only", false},
		{"Offline", "Offline-capable services", false},
	}

	for _, p := range profiles {
		_, err := m.db.Exec(`
			INSERT INTO profiles (name, description, is_active)
			VALUES (?, ?, ?)
		`, p.name, p.description, p.isActive)
		if err != nil {
			return err
		}
	}
	return nil
}

// === Apps ===

// ListApps returns all registered apps with their ports and FQDNs
func (m *AppManager) ListApps() ([]models.App, error) {
	rows, err := m.db.Query(`
		SELECT id, name, display_name, description, type, source, icon_url, github_repo, compose_path, enabled, created_at, updated_at
		FROM apps ORDER BY type, name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []models.App
	for rows.Next() {
		var app models.App
		err := rows.Scan(&app.ID, &app.Name, &app.DisplayName, &app.Description, &app.Type, &app.Source, &app.IconURL, &app.GithubRepo, &app.ComposePath, &app.Enabled, &app.CreatedAt, &app.UpdatedAt)
		if err != nil {
			return nil, err
		}
		app.Ports, _ = m.GetAppPorts(app.ID)
		app.FQDNs, _ = m.GetAppFQDNs(app.ID)
		apps = append(apps, app)
	}
	return apps, nil
}

// GetApp returns a single app by name
func (m *AppManager) GetApp(name string) (*models.App, error) {
	var app models.App
	err := m.db.QueryRow(`
		SELECT id, name, display_name, description, type, source, icon_url, github_repo, compose_path, enabled, created_at, updated_at
		FROM apps WHERE name = ?
	`, name).Scan(&app.ID, &app.Name, &app.DisplayName, &app.Description, &app.Type, &app.Source, &app.IconURL, &app.GithubRepo, &app.ComposePath, &app.Enabled, &app.CreatedAt, &app.UpdatedAt)
	if err != nil {
		return nil, err
	}
	app.Ports, _ = m.GetAppPorts(app.ID)
	app.FQDNs, _ = m.GetAppFQDNs(app.ID)
	return &app, nil
}

// RegisterApp adds a new app to the registry
func (m *AppManager) RegisterApp(req models.RegisterAppRequest) (*models.App, error) {
	if req.Type == "" {
		req.Type = "user"
	}
	if req.Source == "" {
		req.Source = "custom"
	}

	nameRegex := regexp.MustCompile(`^[a-z0-9-]+$`)
	if !nameRegex.MatchString(req.Name) {
		return nil, fmt.Errorf("invalid app name: must be lowercase alphanumeric with hyphens")
	}

	result, err := m.db.Exec(`
		INSERT INTO apps (name, display_name, description, type, source, icon_url, github_repo, compose_path, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE)
	`, req.Name, req.DisplayName, req.Description, req.Type, req.Source, req.IconURL, req.GithubRepo, req.ComposePath)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	return m.getAppByID(id)
}

// UnregisterApp removes an app from the registry
func (m *AppManager) UnregisterApp(name string) error {
	result, err := m.db.Exec("DELETE FROM apps WHERE name = ? AND type != 'system'", name)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("app not found or is a system app")
	}
	return nil
}

// EnableApp enables an app
func (m *AppManager) EnableApp(name string) error {
	_, err := m.db.Exec("UPDATE apps SET enabled = TRUE, updated_at = CURRENT_TIMESTAMP WHERE name = ?", name)
	return err
}

// DisableApp disables an app
func (m *AppManager) DisableApp(name string) error {
	_, err := m.db.Exec("UPDATE apps SET enabled = FALSE, updated_at = CURRENT_TIMESTAMP WHERE name = ?", name)
	return err
}

func (m *AppManager) getAppByID(id int64) (*models.App, error) {
	var app models.App
	err := m.db.QueryRow(`
		SELECT id, name, display_name, description, type, source, icon_url, github_repo, compose_path, enabled, created_at, updated_at
		FROM apps WHERE id = ?
	`, id).Scan(&app.ID, &app.Name, &app.DisplayName, &app.Description, &app.Type, &app.Source, &app.IconURL, &app.GithubRepo, &app.ComposePath, &app.Enabled, &app.CreatedAt, &app.UpdatedAt)
	return &app, err
}

// === Ports ===

// ListPorts returns all allocated ports
func (m *AppManager) ListPorts() ([]models.PortAllocation, error) {
	rows, err := m.db.Query(`
		SELECT p.id, p.app_id, a.name, p.port, p.protocol, p.description, p.created_at
		FROM port_allocations p
		JOIN apps a ON p.app_id = a.id
		ORDER BY p.port
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []models.PortAllocation
	for rows.Next() {
		var port models.PortAllocation
		err := rows.Scan(&port.ID, &port.AppID, &port.AppName, &port.Port, &port.Protocol, &port.Description, &port.CreatedAt)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// GetAppPorts returns ports allocated to an app
func (m *AppManager) GetAppPorts(appID int64) ([]models.PortAllocation, error) {
	rows, err := m.db.Query(`
		SELECT id, app_id, port, protocol, description, created_at
		FROM port_allocations WHERE app_id = ? ORDER BY port
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []models.PortAllocation
	for rows.Next() {
		var port models.PortAllocation
		rows.Scan(&port.ID, &port.AppID, &port.Port, &port.Protocol, &port.Description, &port.CreatedAt)
		ports = append(ports, port)
	}
	return ports, nil
}

// AllocatePort allocates a port to an app
func (m *AppManager) AllocatePort(req models.AllocatePortRequest) (*models.PortAllocation, error) {
	app, err := m.GetApp(req.AppName)
	if err != nil {
		return nil, fmt.Errorf("app not found: %s", req.AppName)
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	port := req.Port
	if port == 0 {
		port, err = m.getNextAvailablePort(app.Type)
		if err != nil {
			return nil, err
		}
	}

	if reservedPorts[port] {
		return nil, fmt.Errorf("port %d is reserved", port)
	}

	result, err := m.db.Exec(`
		INSERT INTO port_allocations (app_id, port, protocol, description)
		VALUES (?, ?, ?, ?)
	`, app.ID, port, req.Protocol, req.Description)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	return m.getPortByID(id)
}

// ReleasePort releases a port allocation
func (m *AppManager) ReleasePort(port int, protocol string) error {
	if protocol == "" {
		protocol = "tcp"
	}
	result, err := m.db.Exec("DELETE FROM port_allocations WHERE port = ? AND protocol = ?", port, protocol)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("port allocation not found")
	}
	return nil
}

// GetAvailablePort returns the next available port for the given type
func (m *AppManager) GetAvailablePort(appType string) (int, error) {
	return m.getNextAvailablePort(appType)
}

func (m *AppManager) getNextAvailablePort(appType string) (int, error) {
	minPort, maxPort := UserPortMin, UserPortMax
	if appType == "system" {
		minPort, maxPort = SystemPortMin, SystemPortMax
	}

	rows, err := m.db.Query("SELECT port FROM port_allocations WHERE port >= ? AND port <= ? ORDER BY port", minPort, maxPort)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	usedPorts := make(map[int]bool)
	for rows.Next() {
		var port int
		rows.Scan(&port)
		usedPorts[port] = true
	}

	for port := minPort; port <= maxPort; port++ {
		if !usedPorts[port] && !reservedPorts[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available ports in range %d-%d", minPort, maxPort)
}

func (m *AppManager) getPortByID(id int64) (*models.PortAllocation, error) {
	var port models.PortAllocation
	err := m.db.QueryRow(`
		SELECT p.id, p.app_id, a.name, p.port, p.protocol, p.description, p.created_at
		FROM port_allocations p JOIN apps a ON p.app_id = a.id WHERE p.id = ?
	`, id).Scan(&port.ID, &port.AppID, &port.AppName, &port.Port, &port.Protocol, &port.Description, &port.CreatedAt)
	return &port, err
}

// === FQDNs ===

// ListFQDNs returns all registered FQDNs
func (m *AppManager) ListFQDNs() ([]models.FQDN, error) {
	rows, err := m.db.Query(`
		SELECT f.id, f.app_id, a.name, f.fqdn, f.subdomain, f.backend_port, f.ssl_enabled, f.created_at
		FROM fqdns f JOIN apps a ON f.app_id = a.id ORDER BY f.fqdn
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fqdns []models.FQDN
	for rows.Next() {
		var fqdn models.FQDN
		rows.Scan(&fqdn.ID, &fqdn.AppID, &fqdn.AppName, &fqdn.FQDN, &fqdn.Subdomain, &fqdn.BackendPort, &fqdn.SSLEnabled, &fqdn.CreatedAt)
		fqdns = append(fqdns, fqdn)
	}
	return fqdns, nil
}

// GetAppFQDNs returns FQDNs for an app
func (m *AppManager) GetAppFQDNs(appID int64) ([]models.FQDN, error) {
	rows, err := m.db.Query(`
		SELECT id, app_id, fqdn, subdomain, backend_port, ssl_enabled, created_at
		FROM fqdns WHERE app_id = ? ORDER BY fqdn
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fqdns []models.FQDN
	for rows.Next() {
		var fqdn models.FQDN
		rows.Scan(&fqdn.ID, &fqdn.AppID, &fqdn.FQDN, &fqdn.Subdomain, &fqdn.BackendPort, &fqdn.SSLEnabled, &fqdn.CreatedAt)
		fqdns = append(fqdns, fqdn)
	}
	return fqdns, nil
}

// RegisterFQDN registers a new FQDN for an app
func (m *AppManager) RegisterFQDN(req models.RegisterFQDNRequest) (*models.FQDN, error) {
	app, err := m.GetApp(req.AppName)
	if err != nil {
		return nil, fmt.Errorf("app not found: %s", req.AppName)
	}

	fqdn := fmt.Sprintf("%s.cubeos.cube", req.Subdomain)

	result, err := m.db.Exec(`
		INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port, ssl_enabled)
		VALUES (?, ?, ?, ?, ?)
	`, app.ID, fqdn, req.Subdomain, req.BackendPort, req.SSLEnabled)
	if err != nil {
		return nil, err
	}

	// Add to Pi-hole custom DNS (best effort)
	go m.addPiholeDNS(fqdn, "192.168.42.1")

	id, _ := result.LastInsertId()
	return m.getFQDNByID(id)
}

// DeregisterFQDN removes an FQDN
func (m *AppManager) DeregisterFQDN(fqdn string) error {
	result, err := m.db.Exec("DELETE FROM fqdns WHERE fqdn = ?", fqdn)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("FQDN not found")
	}

	// Remove from Pi-hole (best effort)
	go m.removePiholeDNS(fqdn)
	return nil
}

func (m *AppManager) getFQDNByID(id int64) (*models.FQDN, error) {
	var fqdn models.FQDN
	err := m.db.QueryRow(`
		SELECT f.id, f.app_id, a.name, f.fqdn, f.subdomain, f.backend_port, f.ssl_enabled, f.created_at
		FROM fqdns f JOIN apps a ON f.app_id = a.id WHERE f.id = ?
	`, id).Scan(&fqdn.ID, &fqdn.AppID, &fqdn.AppName, &fqdn.FQDN, &fqdn.Subdomain, &fqdn.BackendPort, &fqdn.SSLEnabled, &fqdn.CreatedAt)
	return &fqdn, err
}

func (m *AppManager) addPiholeDNS(fqdn, ip string) {
	customList := "/cubeos/coreapps/pihole/appdata/etc-pihole/custom.list"
	entry := fmt.Sprintf("%s %s\n", ip, fqdn)

	f, err := os.OpenFile(customList, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(entry)

	// Reload Pi-hole DNS
	exec.Command("docker", "exec", "pihole", "pihole", "restartdns").Run()
}

func (m *AppManager) removePiholeDNS(fqdn string) {
	customList := "/cubeos/coreapps/pihole/appdata/etc-pihole/custom.list"
	content, err := os.ReadFile(customList)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, fqdn) {
			newLines = append(newLines, line)
		}
	}

	os.WriteFile(customList, []byte(strings.Join(newLines, "\n")), 0644)
	exec.Command("docker", "exec", "pihole", "pihole", "restartdns").Run()
}

// === Profiles ===

// ListProfiles returns all profiles
func (m *AppManager) ListProfiles() ([]models.Profile, error) {
	rows, err := m.db.Query(`
		SELECT id, name, description, is_active, created_at, updated_at
		FROM profiles ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []models.Profile
	for rows.Next() {
		var profile models.Profile
		rows.Scan(&profile.ID, &profile.Name, &profile.Description, &profile.IsActive, &profile.CreatedAt, &profile.UpdatedAt)
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// GetProfile returns a profile with its app states
func (m *AppManager) GetProfile(id int64) (*models.Profile, error) {
	var profile models.Profile
	err := m.db.QueryRow(`
		SELECT id, name, description, is_active, created_at, updated_at FROM profiles WHERE id = ?
	`, id).Scan(&profile.ID, &profile.Name, &profile.Description, &profile.IsActive, &profile.CreatedAt, &profile.UpdatedAt)
	if err != nil {
		return nil, err
	}

	rows, err := m.db.Query(`
		SELECT pa.profile_id, pa.app_id, a.name, pa.enabled
		FROM profile_apps pa JOIN apps a ON pa.app_id = a.id WHERE pa.profile_id = ?
	`, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var pa models.ProfileApp
			rows.Scan(&pa.ProfileID, &pa.AppID, &pa.AppName, &pa.Enabled)
			profile.Apps = append(profile.Apps, pa)
		}
	}
	return &profile, nil
}

// CreateProfile creates a new profile
func (m *AppManager) CreateProfile(req models.CreateProfileRequest) (*models.Profile, error) {
	result, err := m.db.Exec(`INSERT INTO profiles (name, description) VALUES (?, ?)`, req.Name, req.Description)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()

	// Initialize profile_apps for all existing apps (enabled by default)
	m.db.Exec(`INSERT INTO profile_apps (profile_id, app_id, enabled) SELECT ?, id, TRUE FROM apps`, id)

	return m.GetProfile(id)
}

// DeleteProfile deletes a profile
func (m *AppManager) DeleteProfile(id int64) error {
	result, err := m.db.Exec("DELETE FROM profiles WHERE id = ? AND is_active = FALSE", id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("profile not found or is active")
	}
	return nil
}

// ActivateProfile activates a profile and starts/stops containers accordingly
func (m *AppManager) ActivateProfile(id int64) error {
	profile, err := m.GetProfile(id)
	if err != nil {
		return err
	}

	// Deactivate all profiles
	m.db.Exec("UPDATE profiles SET is_active = FALSE")

	// Activate this profile
	_, err = m.db.Exec("UPDATE profiles SET is_active = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	if err != nil {
		return err
	}

	// Start/stop containers in background
	go m.applyProfileContainers(profile)
	return nil
}

// SetProfileApp sets whether an app is enabled in a profile
func (m *AppManager) SetProfileApp(profileID, appID int64, enabled bool) error {
	_, err := m.db.Exec(`
		INSERT INTO profile_apps (profile_id, app_id, enabled) VALUES (?, ?, ?)
		ON CONFLICT(profile_id, app_id) DO UPDATE SET enabled = ?
	`, profileID, appID, enabled, enabled)
	return err
}

func (m *AppManager) applyProfileContainers(profile *models.Profile) {
	for _, pa := range profile.Apps {
		app, err := m.getAppByID(pa.AppID)
		if err != nil || app.ComposePath == "" {
			continue
		}
		if pa.Enabled {
			m.startAppContainers(app)
		} else {
			m.stopAppContainers(app)
		}
	}
}

// === Container Control ===

// StartApp starts an app's containers
func (m *AppManager) StartApp(name string) error {
	app, err := m.GetApp(name)
	if err != nil {
		return err
	}
	if app.ComposePath == "" {
		return fmt.Errorf("app has no compose path")
	}
	go m.startAppContainers(app)
	return nil
}

// StopApp stops an app's containers
func (m *AppManager) StopApp(name string) error {
	app, err := m.GetApp(name)
	if err != nil {
		return err
	}
	if app.ComposePath == "" {
		return fmt.Errorf("app has no compose path")
	}
	go m.stopAppContainers(app)
	return nil
}

// RestartApp restarts an app's containers
func (m *AppManager) RestartApp(name string) error {
	app, err := m.GetApp(name)
	if err != nil {
		return err
	}
	if app.ComposePath == "" {
		return fmt.Errorf("app has no compose path")
	}
	go func() {
		m.stopAppContainers(app)
		time.Sleep(2 * time.Second)
		m.startAppContainers(app)
	}()
	return nil
}

// GetAppStatus returns the running status of an app's containers
func (m *AppManager) GetAppStatus(name string) (string, error) {
	app, err := m.GetApp(name)
	if err != nil {
		return "unknown", err
	}
	if app.ComposePath == "" {
		return "unknown", nil
	}

	dir := filepath.Dir(app.ComposePath)
	cmd := exec.Command("docker", "compose", "-f", app.ComposePath, "ps", "--format", "json")
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return "unknown", nil
	}

	var containers []struct {
		State string `json:"State"`
	}
	json.Unmarshal(output, &containers)

	if len(containers) == 0 {
		return "stopped", nil
	}

	running := 0
	for _, c := range containers {
		if c.State == "running" {
			running++
		}
	}

	if running == len(containers) {
		return "running", nil
	} else if running == 0 {
		return "stopped", nil
	}
	return "partial", nil
}

func (m *AppManager) startAppContainers(app *models.App) {
	if app.ComposePath == "" {
		return
	}
	dir := filepath.Dir(app.ComposePath)
	cmd := exec.Command("docker", "compose", "-f", app.ComposePath, "up", "-d")
	cmd.Dir = dir
	cmd.Run()
}

func (m *AppManager) stopAppContainers(app *models.App) {
	if app.ComposePath == "" {
		return
	}
	dir := filepath.Dir(app.ComposePath)
	cmd := exec.Command("docker", "compose", "-f", app.ComposePath, "down")
	cmd.Dir = dir
	cmd.Run()
}

// === Registry ===

// GetRegistryStatus returns the status of the local Docker registry
func (m *AppManager) GetRegistryStatus() (*models.RegistryStatusResponse, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s/v2/", m.registryURL))
	if err != nil {
		return &models.RegistryStatusResponse{Running: false}, nil
	}
	defer resp.Body.Close()

	status := &models.RegistryStatusResponse{Running: resp.StatusCode == 200}

	if status.Running {
		images, _ := m.ListRegistryImages()
		status.ImageCount = len(images)
		for _, img := range images {
			status.TagCount += len(img.Tags)
		}
	}
	return status, nil
}

// InitRegistry starts the local Docker registry
func (m *AppManager) InitRegistry() error {
	// Check if already running
	status, _ := m.GetRegistryStatus()
	if status.Running {
		return nil
	}

	dataDir := filepath.Join(m.dataDir, "registry")
	os.MkdirAll(dataDir, 0755)

	cmd := exec.Command("docker", "run", "-d",
		"--name", "cubeos-registry",
		"--restart", "unless-stopped",
		"-p", "5000:5000",
		"-v", dataDir+":/var/lib/registry",
		"registry:2")
	return cmd.Run()
}

// ListRegistryImages returns images in the local registry
func (m *AppManager) ListRegistryImages() ([]models.RegistryImage, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s/v2/_catalog", m.registryURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	json.NewDecoder(resp.Body).Decode(&catalog)

	var images []models.RegistryImage
	for _, repo := range catalog.Repositories {
		tags, _ := m.getImageTags(repo)
		images = append(images, models.RegistryImage{Name: repo, Tags: tags})
	}
	return images, nil
}

func (m *AppManager) getImageTags(name string) ([]string, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s/v2/%s/tags/list", m.registryURL, name))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Tags []string `json:"tags"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Tags, nil
}

// CacheImage pulls an image and pushes it to the local registry
func (m *AppManager) CacheImage(imageRef string) error {
	// Pull the image
	cmd := exec.Command("docker", "pull", imageRef)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	// Tag for local registry
	localRef := fmt.Sprintf("%s/%s", m.registryURL, imageRef)
	cmd = exec.Command("docker", "tag", imageRef, localRef)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to tag image: %w", err)
	}

	// Push to local registry
	cmd = exec.Command("docker", "push", localRef)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to push image: %w", err)
	}

	return nil
}

// DeleteRegistryImage deletes an image from the local registry
func (m *AppManager) DeleteRegistryImage(name, tag string) error {
	// Get manifest digest
	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/v2/%s/manifests/%s", m.registryURL, name, tag), nil)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return fmt.Errorf("could not get digest")
	}

	// Delete manifest
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("http://%s/v2/%s/manifests/%s", m.registryURL, name, digest), nil)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 202 {
		return fmt.Errorf("failed to delete: status %d", resp.StatusCode)
	}
	return nil
}

// === CasaOS Import ===

// ParseCasaOSApp parses CasaOS JSON format
func (m *AppManager) ParseCasaOSApp(jsonData string) (*models.CasaOSApp, error) {
	var app models.CasaOSApp
	if err := json.Unmarshal([]byte(jsonData), &app); err != nil {
		return nil, err
	}
	return &app, nil
}

// ConvertCasaOSToCompose converts a CasaOS app to docker-compose.yml
func (m *AppManager) ConvertCasaOSToCompose(app *models.CasaOSApp) string {
	var sb strings.Builder
	sb.WriteString("version: '3.8'\n")
	sb.WriteString("services:\n")
	sb.WriteString(fmt.Sprintf("  %s:\n", app.Name))
	sb.WriteString(fmt.Sprintf("    image: %s\n", app.Container.Image))
	sb.WriteString(fmt.Sprintf("    container_name: %s\n", app.Name))
	sb.WriteString("    restart: unless-stopped\n")

	// Labels
	sb.WriteString("    labels:\n")
	sb.WriteString(fmt.Sprintf("      - cubeos.app.name=%s\n", app.Name))
	sb.WriteString("      - cubeos.app.source=casaos\n")
	if app.Title != "" {
		sb.WriteString(fmt.Sprintf("      - cubeos.app.title=%s\n", app.Title))
	}

	// Environment
	if len(app.Envs) > 0 {
		sb.WriteString("    environment:\n")
		for _, env := range app.Envs {
			sb.WriteString(fmt.Sprintf("      - %s=%s\n", env.Key, env.Value))
		}
	}

	// Ports
	if len(app.Ports) > 0 {
		sb.WriteString("    ports:\n")
		for _, port := range app.Ports {
			proto := port.Protocol
			if proto == "" {
				proto = "tcp"
			}
			sb.WriteString(fmt.Sprintf("      - \"%s:%s/%s\"\n", port.Host, port.Container, proto))
		}
	}

	// Volumes - convert CasaOS paths
	if len(app.Volumes) > 0 {
		sb.WriteString("    volumes:\n")
		for _, vol := range app.Volumes {
			hostPath := vol.Host
			// Convert CasaOS paths to CubeOS paths
			hostPath = strings.ReplaceAll(hostPath, "/DATA/AppData/", fmt.Sprintf("/cubeos/userapps/%s/appdata/", app.Name))
			hostPath = strings.ReplaceAll(hostPath, "/DATA/", "/cubeos/data/")
			sb.WriteString(fmt.Sprintf("      - %s:%s\n", hostPath, vol.Container))
		}
	}

	// Devices
	if len(app.Devices) > 0 {
		sb.WriteString("    devices:\n")
		for _, dev := range app.Devices {
			sb.WriteString(fmt.Sprintf("      - %s:%s\n", dev.Host, dev.Container))
		}
	}

	// Privileged
	if app.Container.Privileged {
		sb.WriteString("    privileged: true\n")
	}

	// Network mode
	if app.Container.NetworkMode != "" {
		sb.WriteString(fmt.Sprintf("    network_mode: %s\n", app.Container.NetworkMode))
	}

	// Cap add
	if len(app.Container.CapAdd) > 0 {
		sb.WriteString("    cap_add:\n")
		for _, cap := range app.Container.CapAdd {
			sb.WriteString(fmt.Sprintf("      - %s\n", cap))
		}
	}

	// Sysctls
	if len(app.Sysctls) > 0 {
		sb.WriteString("    sysctls:\n")
		for k, v := range app.Sysctls {
			sb.WriteString(fmt.Sprintf("      - %s=%s\n", k, v))
		}
	}

	// Command
	if app.Container.Command != "" {
		sb.WriteString(fmt.Sprintf("    command: %s\n", app.Container.Command))
	}

	return sb.String()
}

// ImportCasaOSApp imports a CasaOS app into CubeOS
func (m *AppManager) ImportCasaOSApp(jsonData string) (*models.App, error) {
	casaApp, err := m.ParseCasaOSApp(jsonData)
	if err != nil {
		return nil, err
	}

	// Create app directory
	appDir := filepath.Join(m.dataDir, "userapps", casaApp.Name, "appconfig")
	os.MkdirAll(appDir, 0755)
	os.MkdirAll(filepath.Join(m.dataDir, "userapps", casaApp.Name, "appdata"), 0755)

	// Generate compose file
	compose := m.ConvertCasaOSToCompose(casaApp)
	composePath := filepath.Join(appDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(compose), 0644); err != nil {
		return nil, err
	}

	// Register app
	displayName := casaApp.Title
	if displayName == "" {
		displayName = casaApp.Name
	}

	return m.RegisterApp(models.RegisterAppRequest{
		Name:        casaApp.Name,
		DisplayName: displayName,
		Description: casaApp.Tagline,
		Type:        "user",
		Source:      "casaos",
		IconURL:     casaApp.Icon,
		ComposePath: composePath,
	})
}

// FetchCasaOSStore fetches apps from a CasaOS store URL
func (m *AppManager) FetchCasaOSStore(storeURL string) ([]models.CasaOSApp, error) {
	// Try common catalog paths
	paths := []string{"index.json", "main.json", "apps.json", ""}

	for _, path := range paths {
		url := storeURL
		if path != "" {
			url = strings.TrimSuffix(storeURL, "/") + "/" + path
		}

		resp, err := http.Get(url)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		// Try parsing as array
		var apps []models.CasaOSApp
		if err := json.Unmarshal(body, &apps); err == nil && len(apps) > 0 {
			return apps, nil
		}

		// Try parsing as object with "apps" field
		var catalog struct {
			Apps []models.CasaOSApp `json:"apps"`
		}
		if err := json.Unmarshal(body, &catalog); err == nil && len(catalog.Apps) > 0 {
			return catalog.Apps, nil
		}
	}

	return nil, fmt.Errorf("could not fetch apps from store")
}

// ============================================================================
// Config Editing Methods
// ============================================================================

// GetAppConfig returns the compose and env file contents for an app
func (m *AppManager) GetAppConfig(appName string) (*models.AppConfig, error) {
	config, err := m.composeManager.GetConfig(appName)
	if err != nil {
		return nil, err
	}
	return &models.AppConfig{
		AppName:     config.AppName,
		ComposePath: config.ComposePath,
		EnvPath:     config.EnvPath,
		Compose:     config.ComposeFile,
		Env:         config.EnvFile,
		HasEnv:      config.HasEnv,
	}, nil
}

// SaveAppConfig saves compose and env files with optional container recreate
func (m *AppManager) SaveAppConfig(appName, compose, env string, recreate bool) error {
	return m.composeManager.SaveConfig(appName, compose, env, recreate)
}

// ============================================================================
// Enhanced Port Methods
// ============================================================================

// GetListeningPorts returns all ports currently listening (ss -tulnp)
func (m *AppManager) GetListeningPorts() ([]models.ListeningPort, error) {
	ports, err := m.portManager.GetListeningPorts()
	if err != nil {
		return nil, err
	}

	var result []models.ListeningPort
	for _, p := range ports {
		result = append(result, models.ListeningPort{
			Port:      p.Port,
			Protocol:  p.Protocol,
			Process:   p.Process,
			LocalAddr: p.LocalAddr,
		})
	}
	return result, nil
}

// GetPortStats returns port allocation statistics
func (m *AppManager) GetPortStats() map[string]interface{} {
	return m.portManager.GetPortStats()
}

// SyncPortsFromSystem scans running containers and syncs ports to database
func (m *AppManager) SyncPortsFromSystem() error {
	return m.portManager.SyncFromSystem(m.composeManager)
}

// ============================================================================
// Enhanced Domain Methods (Pi-hole + NPM Integration)
// ============================================================================

// ListDomainsEnhanced returns domains with Pi-hole and NPM status
func (m *AppManager) ListDomainsEnhanced() ([]models.DomainInfo, error) {
	// Get FQDNs from database
	fqdns, err := m.ListFQDNs()
	if err != nil {
		return nil, err
	}

	// Get Pi-hole entries
	piholeEntries, _ := m.piholeManager.GetCubeOSDomains()
	piholeMap := make(map[string]bool)
	for _, e := range piholeEntries {
		piholeMap[e.Domain] = true
	}

	// Get NPM hosts
	npmHosts, _ := m.npmManager.ListProxyHosts()
	npmMap := make(map[string]int) // domain -> proxy ID
	for _, h := range npmHosts {
		for _, d := range h.DomainNames {
			npmMap[d] = h.ID
		}
	}

	var domains []models.DomainInfo
	for _, f := range fqdns {
		domains = append(domains, models.DomainInfo{
			ID:            f.ID,
			AppID:         f.AppID,
			AppName:       f.AppName,
			FQDN:          f.FQDN,
			Subdomain:     f.Subdomain,
			BackendPort:   f.BackendPort,
			SSLEnabled:    f.SSLEnabled,
			NPMProxyID:    npmMap[f.FQDN],
			PiholeEnabled: piholeMap[f.FQDN],
			NPMEnabled:    npmMap[f.FQDN] > 0,
			CreatedAt:     f.CreatedAt.Format(time.RFC3339),
		})
	}

	return domains, nil
}

// SyncDomainsFromPihole imports existing Pi-hole DNS entries with improved app matching
// Uses NPM as primary source for port info and better subdomain-to-app matching
func (m *AppManager) SyncDomainsFromPihole() error {
	entries, err := m.piholeManager.GetCubeOSDomains()
	if err != nil {
		return err
	}

	// Pre-fetch NPM hosts to get accurate port mappings
	npmHosts, _ := m.npmManager.ListProxyHosts()
	npmMap := make(map[string]*NPMProxyHostExtended)
	for i := range npmHosts {
		for _, domain := range npmHosts[i].DomainNames {
			npmMap[domain] = &npmHosts[i]
		}
	}

	// Build a map of all registered apps for matching
	rows, _ := m.db.Query("SELECT id, name FROM apps")
	appMap := make(map[string]int64) // name -> id
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var name string
			rows.Scan(&id, &name)
			appMap[name] = id
		}
	}

	for _, entry := range entries {
		// Skip if already in database
		var count int
		m.db.QueryRow("SELECT COUNT(*) FROM fqdns WHERE fqdn = ?", entry.Domain).Scan(&count)
		if count > 0 {
			continue
		}

		// Extract subdomain
		subdomain := strings.TrimSuffix(entry.Domain, ".cubeos.cube")
		if subdomain == entry.Domain {
			subdomain = "" // It's cubeos.cube itself
		}

		// Determine the correct app and port using multiple strategies
		var appID int64 = 0
		backendPort := 80

		// Strategy 1: Get info from NPM (most accurate - has actual forward port)
		if npmHost, ok := npmMap[entry.Domain]; ok {
			backendPort = npmHost.ForwardPort

			// Try to match app by ForwardHost (container name pattern)
			containerName := npmHost.ForwardHost
			if strings.HasPrefix(containerName, "cubeos-") {
				appName := strings.TrimPrefix(containerName, "cubeos-")
				if id, ok := appMap[appName]; ok {
					appID = id
				}
			}
		}

		// Strategy 2: Match by subdomain name directly (if NPM didn't match)
		if appID == 0 && subdomain != "" {
			if id, ok := appMap[subdomain]; ok {
				appID = id
			}
		}

		// Strategy 3: Special cases for known domains
		if appID == 0 {
			switch subdomain {
			case "api":
				if id, ok := appMap["orchestrator"]; ok {
					appID = id
				}
			case "logs":
				if id, ok := appMap["dozzle"]; ok {
					appID = id
				}
			case "": // cubeos.cube itself - main dashboard
				if id, ok := appMap["orchestrator"]; ok {
					appID = id
				}
			}
		}

		// Strategy 4: Partial match
		if appID == 0 && subdomain != "" {
			for appName, id := range appMap {
				if strings.Contains(subdomain, appName) || strings.Contains(appName, subdomain) {
					appID = id
					break
				}
			}
		}

		// Strategy 5: Check if there's a coreapps folder for this subdomain
		if appID == 0 && subdomain != "" {
			composePath := filepath.Join(filepath.Dir(m.dataDir), "coreapps", subdomain, "appconfig", "docker-compose.yml")
			if _, err := os.Stat(composePath); err == nil {
				// Found a compose file - register the app
				result, err := m.db.Exec(`
					INSERT OR IGNORE INTO apps (name, display_name, description, type, source, enabled)
					VALUES (?, ?, '', 'system', 'cubeos', TRUE)
				`, subdomain, strings.Title(subdomain))
				if err == nil {
					if id, err := result.LastInsertId(); err == nil && id > 0 {
						appID = id
					} else {
						m.db.QueryRow("SELECT id FROM apps WHERE name = ?", subdomain).Scan(&appID)
					}
				}
			}
		}

		// Skip unmatched domains rather than wrongly attributing them
		if appID == 0 {
			continue
		}

		// Insert into database with correct app and port
		m.db.Exec(`
			INSERT OR IGNORE INTO fqdns (app_id, fqdn, subdomain, backend_port, ssl_enabled)
			VALUES (?, ?, ?, ?, FALSE)
		`, appID, entry.Domain, subdomain, backendPort)
	}

	return nil
}

// SyncDomainsFromNPM syncs domains directly from NPM proxy hosts
// This provides more accurate port information
func (m *AppManager) SyncDomainsFromNPM() error {
	hosts, err := m.npmManager.ListProxyHosts()
	if err != nil {
		return err
	}

	// Build app map
	rows, _ := m.db.Query("SELECT id, name FROM apps")
	appMap := make(map[string]int64)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var name string
			rows.Scan(&id, &name)
			appMap[name] = id
		}
	}

	for _, host := range hosts {
		for _, domain := range host.DomainNames {
			// Skip if already in database
			var count int
			m.db.QueryRow("SELECT COUNT(*) FROM fqdns WHERE fqdn = ?", domain).Scan(&count)
			if count > 0 {
				// Update the backend port if it changed
				m.db.Exec("UPDATE fqdns SET backend_port = ? WHERE fqdn = ?", host.ForwardPort, domain)
				continue
			}

			// Extract subdomain
			subdomain := strings.TrimSuffix(domain, ".cubeos.cube")
			if subdomain == domain {
				subdomain = ""
			}

			// Find matching app
			var appID int64 = 0

			// By container name pattern
			if strings.HasPrefix(host.ForwardHost, "cubeos-") {
				appName := strings.TrimPrefix(host.ForwardHost, "cubeos-")
				if id, ok := appMap[appName]; ok {
					appID = id
				}
			}

			// By subdomain
			if appID == 0 && subdomain != "" {
				if id, ok := appMap[subdomain]; ok {
					appID = id
				}
			}

			// Special cases
			if appID == 0 {
				switch subdomain {
				case "api":
					if id, ok := appMap["orchestrator"]; ok {
						appID = id
					}
				case "logs":
					if id, ok := appMap["dozzle"]; ok {
						appID = id
					}
				}
			}

			if appID == 0 {
				continue
			}

			m.db.Exec(`
				INSERT OR IGNORE INTO fqdns (app_id, fqdn, subdomain, backend_port, ssl_enabled)
				VALUES (?, ?, ?, ?, FALSE)
			`, appID, domain, subdomain, host.ForwardPort)
		}
	}

	return nil
}

// ============================================================================
// NPM (Nginx Proxy Manager) Methods
// ============================================================================

// GetNPMStatus returns NPM connection status
func (m *AppManager) GetNPMStatus() map[string]interface{} {
	healthy := m.npmManager.IsHealthy()
	return map[string]interface{}{
		"healthy":   healthy,
		"connected": m.npmManager.token != "",
		"url":       "http://192.168.42.1:6000",
	}
}

// ListNPMHosts returns all NPM proxy hosts
func (m *AppManager) ListNPMHosts() ([]models.NPMProxyHostInfo, error) {
	hosts, err := m.npmManager.ListProxyHosts()
	if err != nil {
		return nil, err
	}

	var result []models.NPMProxyHostInfo
	for _, h := range hosts {
		result = append(result, models.NPMProxyHostInfo{
			ID:            h.ID,
			DomainNames:   h.DomainNames,
			ForwardHost:   h.ForwardHost,
			ForwardPort:   h.ForwardPort,
			ForwardScheme: h.ForwardScheme,
			SSLForced:     h.SSLForced,
			Enabled:       h.Enabled == 1,
			CreatedOn:     h.CreatedOn,
		})
	}
	return result, nil
}

// InitNPM initializes the NPM connection
func (m *AppManager) InitNPM() error {
	return m.npmManager.Init()
}

// ============================================================================
// Migration Methods
// ============================================================================

// RunMigration imports existing apps, ports, and domains
func (m *AppManager) RunMigration() (*models.MigrationResult, error) {
	result := &models.MigrationResult{}

	// 1. Import apps from coreapps directory
	apps, err := m.composeManager.ListApps()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to list apps: %v", err))
	} else {
		for _, appName := range apps {
			// Check if already exists
			var count int
			m.db.QueryRow("SELECT COUNT(*) FROM apps WHERE name = ?", appName).Scan(&count)
			if count > 0 {
				continue
			}

			// Get display name
			displayName := strings.ReplaceAll(appName, "-", " ")
			displayName = strings.Title(displayName)

			// Get compose path
			composePath := m.composeManager.GetComposePath(appName)

			// Insert with compose_path
			_, err := m.db.Exec(`
				INSERT INTO apps (name, display_name, description, type, source, compose_path, enabled)
				VALUES (?, ?, '', 'system', 'cubeos', ?, TRUE)
			`, appName, displayName, composePath)
			if err == nil {
				result.AppsImported++
			}
		}
	}

	// 2. Update compose paths for existing apps that are missing them
	if err := m.UpdateAppComposePaths(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to update compose paths: %v", err))
	}

	// 3. Sync domains from NPM first (has accurate port info)
	if err := m.SyncDomainsFromNPM(); err != nil {
		// NPM might not be available, continue with Pi-hole
	}

	// 4. Sync domains from Pi-hole
	if err := m.SyncDomainsFromPihole(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to sync domains: %v", err))
	}
	// Count domains
	var domainCount int
	m.db.QueryRow("SELECT COUNT(*) FROM fqdns").Scan(&domainCount)
	result.DomainsImported = domainCount

	// 5. Sync ports from compose files
	if err := m.SyncPortsFromSystem(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to sync ports from compose: %v", err))
	}

	// 6. Sync ports from running docker containers
	if err := m.portManager.SyncFromDockerPS(m.db); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to sync ports from docker: %v", err))
	}

	// Count ports
	var portCount int
	m.db.QueryRow("SELECT COUNT(*) FROM port_allocations").Scan(&portCount)
	result.PortsImported = portCount

	return result, nil
}
