package managers

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/models"

	"gopkg.in/yaml.v3"
)

// AppStoreManager handles app store and installed app operations
type AppStoreManager struct {
	db           *DatabaseManager
	pihole       *PiholeManager
	dataPath     string
	cachePath    string
	appsPath     string // /cubeos/apps - user apps, freely removable
	coreAppsPath string // /cubeos/coreapps - system critical, protected
	appDataPath  string // deprecated - now per-app at /cubeos/apps/{app}/appdata
	baseDomain   string
	gatewayIP    string
	npmAPIURL    string // NPM API endpoint
	npmToken     string // NPM API token (cached)
	stores       map[string]*models.AppStore
	catalog      map[string]*models.StoreApp
	installed    map[string]*models.InstalledApp
	mu           sync.RWMutex
}

// NewAppStoreManager creates a new app store manager with centralized config
func NewAppStoreManager(cfg *config.Config, db *DatabaseManager, dataPath string, pihole *PiholeManager) *AppStoreManager {
	// Directory structure:
	// /cubeos/coreapps/ - NPM, Pi-hole, dashboard (system critical)
	// /cubeos/apps/{app}/appconfig/ - docker-compose.yml, .env
	// /cubeos/apps/{app}/appdata/   - persistent data
	coreAppsPath := "/cubeos/coreapps"
	appsPath := "/cubeos/apps"
	cachePath := filepath.Join(dataPath, "appstore-cache")

	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(coreAppsPath, 0755)
	os.MkdirAll(appsPath, 0755)

	m := &AppStoreManager{
		db:           db,
		pihole:       pihole,
		dataPath:     dataPath,
		cachePath:    cachePath,
		appsPath:     appsPath,
		coreAppsPath: coreAppsPath,
		appDataPath:  "", // deprecated - now per-app
		baseDomain:   cfg.Domain,
		gatewayIP:    cfg.GatewayIP,
		npmAPIURL:    fmt.Sprintf("%s/api", cfg.GetNPMURL()),
		stores:       make(map[string]*models.AppStore),
		catalog:      make(map[string]*models.StoreApp),
		installed:    make(map[string]*models.InstalledApp),
	}

	m.initDB()
	m.loadStores()
	m.loadInstalledApps()

	// Initialize NPM API token
	go m.initNPMToken()

	return m
}

// initDB ensures app store tables exist.
// Core table creation is handled by database.InitSchema().
// The apps table already has all needed columns (deploy_mode, store_app_id, etc.)
func (m *AppStoreManager) initDB() {
	// Ensure store_app_id column exists for older databases
	m.db.db.Exec(`ALTER TABLE apps ADD COLUMN store_app_id TEXT DEFAULT NULL`)
}

// loadStores loads stores from database
func (m *AppStoreManager) loadStores() {
	rows, err := m.db.db.Query(`SELECT id, name, url, description, author, app_count, 
		COALESCE(last_sync, '') as last_sync, enabled, created_at FROM app_stores`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var store models.AppStore
		var lastSync, createdAt string
		var enabled int
		rows.Scan(&store.ID, &store.Name, &store.URL, &store.Description, &store.Author,
			&store.AppCount, &lastSync, &enabled, &createdAt)
		store.Enabled = enabled == 1
		if lastSync != "" {
			store.LastSync, _ = time.Parse(time.RFC3339, lastSync)
		}
		store.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		m.stores[store.ID] = &store
	}
	if err := rows.Err(); err != nil {
		log.Printf("Warning: error iterating app stores: %v", err)
	}

	// Add default stores if none exist
	if len(m.stores) == 0 {
		for _, ds := range models.DefaultAppStores {
			m.addStore(&ds)
		}
	}
}

// loadInstalledApps loads user-installed apps from the unified apps table.
// Only loads apps with source='casaos' (installed from app store).
func (m *AppStoreManager) loadInstalledApps() {
	rows, err := m.db.db.Query(`SELECT name, store_id, COALESCE(store_app_id, '') as store_app_id,
		name, COALESCE(display_name, name) as title, COALESCE(description, '') as description,
		COALESCE(icon_url, '') as icon, COALESCE(category, '') as category,
		COALESCE(version, '') as version, COALESCE(homepage, '') as webui,
		COALESCE(compose_path, '') as compose_file, COALESCE(data_path, '') as data_path,
		created_at, updated_at
		FROM apps WHERE source = 'casaos'`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var app models.InstalledApp
		var installedAt, updatedAt string
		rows.Scan(&app.ID, &app.StoreID, &app.StoreAppID, &app.Name, &app.Title, &app.Description,
			&app.Icon, &app.Category, &app.Version, &app.WebUI, &app.ComposeFile,
			&app.DataPath, &installedAt, &updatedAt)
		app.InstalledAt, _ = time.Parse(time.RFC3339, installedAt)
		app.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		app.Status = "unknown" // Will be refreshed from Swarm at query time
		m.installed[app.ID] = &app
	}
	if err := rows.Err(); err != nil {
		log.Printf("Warning: error iterating installed apps: %v", err)
	}
}

func (m *AppStoreManager) addStore(store *models.AppStore) error {
	store.CreatedAt = time.Now()
	_, err := m.db.db.Exec(
		`INSERT INTO app_stores (id, name, url, description, author, enabled, created_at) 
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		store.ID, store.Name, store.URL, store.Description, store.Author, store.Enabled,
		store.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return err
	}
	m.stores[store.ID] = store
	return nil
}

// RegisterStore registers a new app store
func (m *AppStoreManager) RegisterStore(url, name, description string) (*models.AppStore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already exists
	for _, s := range m.stores {
		if s.URL == url {
			return s, nil
		}
	}

	hash := sha256.Sum256([]byte(url))
	store := &models.AppStore{
		ID:          hex.EncodeToString(hash[:8]),
		Name:        name,
		URL:         url,
		Description: description,
		Enabled:     true,
	}

	if err := m.addStore(store); err != nil {
		return nil, err
	}

	return store, nil
}

// RemoveStore removes an app store
func (m *AppStoreManager) RemoveStore(storeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.db.Exec(`DELETE FROM app_stores WHERE id = ?`, storeID)
	if err != nil {
		return err
	}

	delete(m.stores, storeID)

	// Remove catalog entries
	for key, app := range m.catalog {
		if app.StoreID == storeID {
			delete(m.catalog, key)
		}
	}

	return nil
}

// GetStores returns all stores
func (m *AppStoreManager) GetStores() []*models.AppStore {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stores := make([]*models.AppStore, 0, len(m.stores))
	for _, s := range m.stores {
		stores = append(stores, s)
	}
	return stores
}

// GetStore returns a specific store
func (m *AppStoreManager) GetStore(storeID string) *models.AppStore {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stores[storeID]
}

// SyncStore downloads and parses a store
func (m *AppStoreManager) SyncStore(storeID string) error {
	store := m.GetStore(storeID)
	if store == nil {
		return fmt.Errorf("store not found: %s", storeID)
	}

	zipPath := filepath.Join(m.cachePath, storeID+".zip")
	extractPath := filepath.Join(m.cachePath, storeID)

	// Download
	if err := m.downloadFile(store.URL, zipPath); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Extract
	os.RemoveAll(extractPath)
	if err := m.extractZip(zipPath, extractPath); err != nil {
		return fmt.Errorf("extract failed: %w", err)
	}

	// Find Apps directory
	appsDir := m.findAppsDir(extractPath)
	if appsDir == "" {
		return fmt.Errorf("Apps directory not found")
	}

	// Parse manifests
	entries, err := os.ReadDir(appsDir)
	if err != nil {
		return err
	}

	m.mu.Lock()
	// Clear old entries
	for key, app := range m.catalog {
		if app.StoreID == storeID {
			delete(m.catalog, key)
		}
	}

	appCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		manifestPath := filepath.Join(appsDir, entry.Name(), "docker-compose.yml")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			continue
		}

		app, err := m.parseManifest(manifestPath, storeID, entry.Name())
		if err != nil {
			continue
		}

		if !m.isArchCompatible(app.Architectures) {
			continue
		}

		// Check if installed
		for _, inst := range m.installed {
			if inst.StoreAppID == app.ID {
				app.Installed = true
				break
			}
		}

		m.catalog[app.ID] = app
		appCount++
	}
	m.mu.Unlock()

	// Update store
	store.AppCount = appCount
	store.LastSync = time.Now()
	m.db.db.Exec(`UPDATE app_stores SET app_count = ?, last_sync = ? WHERE id = ?`,
		appCount, store.LastSync.Format(time.RFC3339), storeID)

	return nil
}

// SyncAllStores syncs all enabled stores
func (m *AppStoreManager) SyncAllStores() error {
	var lastErr error
	for _, store := range m.GetStores() {
		if store.Enabled {
			if err := m.SyncStore(store.ID); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

func (m *AppStoreManager) downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func (m *AppStoreManager) extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	os.MkdirAll(dest, 0755)

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, f.Mode())
			continue
		}

		os.MkdirAll(filepath.Dir(fpath), 0755)
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			continue
		}

		rc, _ := f.Open()
		io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}

	return nil
}

func (m *AppStoreManager) findAppsDir(root string) string {
	direct := filepath.Join(root, "Apps")
	if _, err := os.Stat(direct); err == nil {
		return direct
	}

	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if entry.IsDir() {
			nested := filepath.Join(root, entry.Name(), "Apps")
			if _, err := os.Stat(nested); err == nil {
				return nested
			}
		}
	}
	return ""
}

func (m *AppStoreManager) parseManifest(path, storeID, appName string) (*models.StoreApp, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest models.CasaOSManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	if manifest.XCasaOS.Main == "" || len(manifest.XCasaOS.Architectures) == 0 {
		return nil, fmt.Errorf("missing required fields")
	}

	mainService, ok := manifest.Services[manifest.XCasaOS.Main]
	if !ok {
		return nil, fmt.Errorf("main service not found")
	}

	version := ""
	if parts := strings.Split(mainService.Image, ":"); len(parts) > 1 {
		version = parts[1]
	}

	id := appName
	if manifest.Name != "" {
		id = manifest.Name
	}

	// Icon URL
	icon := manifest.XCasaOS.Icon
	appDir := filepath.Dir(path)
	if icon == "" {
		if _, err := os.Stat(filepath.Join(appDir, "icon.png")); err == nil {
			icon = fmt.Sprintf("/api/v1/appstore/stores/%s/apps/%s/icon", storeID, id)
		}
	}

	// Screenshots
	var screenshots []string
	for i := 1; i <= 5; i++ {
		ssPath := filepath.Join(appDir, fmt.Sprintf("screenshot-%d.png", i))
		if _, err := os.Stat(ssPath); err == nil {
			screenshots = append(screenshots, fmt.Sprintf("/api/v1/appstore/stores/%s/apps/%s/screenshot/%d", storeID, id, i))
		}
	}

	return &models.StoreApp{
		ID:            fmt.Sprintf("%s/%s", storeID, id),
		StoreID:       storeID,
		Name:          id,
		Title:         manifest.XCasaOS.Title,
		Description:   manifest.XCasaOS.Description,
		Tagline:       manifest.XCasaOS.Tagline,
		Icon:          icon,
		Screenshots:   screenshots,
		Category:      manifest.XCasaOS.Category,
		Author:        manifest.XCasaOS.Author,
		Architectures: manifest.XCasaOS.Architectures,
		MainService:   manifest.XCasaOS.Main,
		PortMap:       manifest.XCasaOS.PortMap,
		Index:         manifest.XCasaOS.Index,
		Scheme:        manifest.XCasaOS.Scheme,
		Version:       version,
		Tips:          manifest.XCasaOS.Tips,
		ManifestPath:  path,
	}, nil
}

func (m *AppStoreManager) isArchCompatible(archs []string) bool {
	current := runtime.GOARCH
	archMap := map[string][]string{
		"amd64": {"amd64", "x86_64", "x86-64"},
		"arm64": {"arm64", "aarch64"},
		"arm":   {"arm", "armv7", "armhf"},
	}

	for _, arch := range archs {
		for _, alias := range archMap[current] {
			if strings.EqualFold(arch, alias) {
				return true
			}
		}
	}
	return false
}

// GetCatalog returns apps from catalog with optional filters
func (m *AppStoreManager) GetCatalog(category, search, storeID string) []*models.StoreApp {
	m.mu.RLock()
	defer m.mu.RUnlock()

	apps := make([]*models.StoreApp, 0)
	searchLower := strings.ToLower(search)

	for _, app := range m.catalog {
		if storeID != "" && app.StoreID != storeID {
			continue
		}

		if category != "" && !strings.EqualFold(app.Category, category) {
			continue
		}

		if search != "" {
			title := strings.ToLower(app.Title["en_us"])
			if title == "" {
				title = strings.ToLower(app.Name)
			}
			desc := strings.ToLower(app.Description["en_us"])
			name := strings.ToLower(app.Name)

			if !strings.Contains(title, searchLower) &&
				!strings.Contains(desc, searchLower) &&
				!strings.Contains(name, searchLower) {
				continue
			}
		}

		apps = append(apps, app)
	}

	// Sort by name
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].Name < apps[j].Name
	})

	return apps
}

// GetApp returns a specific app from catalog
func (m *AppStoreManager) GetApp(storeID, appName string) *models.StoreApp {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.catalog[fmt.Sprintf("%s/%s", storeID, appName)]
}

// GetAppManifest returns the raw manifest for an app
func (m *AppStoreManager) GetAppManifest(storeID, appName string) ([]byte, error) {
	app := m.GetApp(storeID, appName)
	if app == nil {
		return nil, fmt.Errorf("app not found")
	}

	return os.ReadFile(app.ManifestPath)
}

// GetCategories returns all unique categories
func (m *AppStoreManager) GetCategories() []*models.AppCategory {
	m.mu.RLock()
	defer m.mu.RUnlock()

	catMap := make(map[string]int)
	for _, app := range m.catalog {
		if app.Category != "" {
			catMap[app.Category]++
		}
	}

	cats := make([]*models.AppCategory, 0, len(catMap))
	for name, count := range catMap {
		cats = append(cats, &models.AppCategory{Name: name, Count: count})
	}

	sort.Slice(cats, func(i, j int) bool {
		return cats[i].Name < cats[j].Name
	})

	return cats
}

// GetIconPath returns path to app icon
func (m *AppStoreManager) GetIconPath(storeID, appName string) string {
	extractPath := filepath.Join(m.cachePath, storeID)
	appsDir := m.findAppsDir(extractPath)
	if appsDir == "" {
		return ""
	}
	return filepath.Join(appsDir, appName, "icon.png")
}

// GetScreenshotPath returns path to app screenshot
func (m *AppStoreManager) GetScreenshotPath(storeID, appName string, index int) string {
	extractPath := filepath.Join(m.cachePath, storeID)
	appsDir := m.findAppsDir(extractPath)
	if appsDir == "" {
		return ""
	}
	return filepath.Join(appsDir, appName, fmt.Sprintf("screenshot-%d.png", index))
}

// InstallApp installs an app from the store using Docker Swarm stack deploy.
// It also creates an NPM proxy host and Pi-hole DNS entry for FQDN access.
func (m *AppStoreManager) InstallApp(req *models.AppInstallRequest) (*models.InstalledApp, error) {
	storeApp := m.GetApp(req.StoreID, req.AppName)
	if storeApp == nil {
		return nil, fmt.Errorf("app not found: %s/%s", req.StoreID, req.AppName)
	}

	// Check if already installed
	for _, inst := range m.installed {
		if inst.Name == req.AppName {
			return nil, fmt.Errorf("app already installed: %s", req.AppName)
		}
	}

	// Read manifest
	manifestData, err := os.ReadFile(storeApp.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// Create app directories: /cubeos/apps/{app}/appconfig and /cubeos/apps/{app}/appdata
	appBase := filepath.Join(m.appsPath, req.AppName)
	appConfig := filepath.Join(appBase, "appconfig")
	appData := filepath.Join(appBase, "appdata")
	os.MkdirAll(appConfig, 0755)
	os.MkdirAll(appData, 0755)

	// Allocate a port in the user app range (6100-6999)
	allocatedPort := m.findAvailablePort(6100)

	// Process manifest with variable substitution
	processedManifest := m.processManifest(string(manifestData), req.AppName, appData, req)

	// Write docker-compose.yml to appconfig
	composePath := filepath.Join(appConfig, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(processedManifest), 0644); err != nil {
		return nil, fmt.Errorf("failed to write compose file: %w", err)
	}

	// Deploy as Swarm stack instead of docker compose
	// --resolve-image=never is critical for ARM64 compatibility
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	deployCmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
		"-c", composePath,
		"--resolve-image=never",
		req.AppName,
	)
	deployCmd.Dir = appConfig
	if output, err := deployCmd.CombinedOutput(); err != nil {
		// Cleanup on failure
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("stack deploy failed: %s", string(output))
	}

	// Build WebUI URL using configured gateway IP (not hardcoded)
	webUI := ""
	appPort := 0
	if storeApp.PortMap != "" {
		scheme := storeApp.Scheme
		if scheme == "" {
			scheme = "http"
		}
		index := storeApp.Index
		if index == "" {
			index = "/"
		}
		webUI = fmt.Sprintf("%s://%s:%s%s", scheme, m.gatewayIP, storeApp.PortMap, index)
		fmt.Sscanf(storeApp.PortMap, "%d", &appPort)
	}
	if appPort == 0 {
		appPort = allocatedPort
	}

	// Build FQDN for this app
	appFQDN := fmt.Sprintf("%s.%s", req.AppName, m.baseDomain)

	// Create NPM proxy host for FQDN access (non-fatal)
	var npmProxyID int
	if proxyID, err := m.addNPMProxyHost(req.AppName, appFQDN, appPort, "http", true); err != nil {
		log.Printf("Warning: Failed to create NPM proxy for %s: %v", appFQDN, err)
	} else {
		npmProxyID = proxyID
	}

	// Create Pi-hole DNS entry for FQDN (non-fatal)
	if m.pihole != nil {
		if err := m.pihole.AddEntry(appFQDN, m.gatewayIP); err != nil {
			log.Printf("Warning: Failed to add DNS entry for %s: %v", appFQDN, err)
		}
	}

	// Get title
	title := req.Title
	if title == "" {
		title = storeApp.Title["en_us"]
		if title == "" {
			title = storeApp.Name
		}
	}

	// If we have a FQDN, prefer it as the WebUI URL
	if appFQDN != "" && webUI != "" {
		webUI = fmt.Sprintf("http://%s", appFQDN)
	}

	// Create installed app record
	installed := &models.InstalledApp{
		ID:          req.AppName,
		StoreID:     req.StoreID,
		StoreAppID:  storeApp.ID,
		Name:        req.AppName,
		Title:       title,
		Description: storeApp.Description["en_us"],
		Icon:        storeApp.Icon,
		Category:    storeApp.Category,
		Version:     storeApp.Version,
		Status:      "running",
		WebUI:       webUI,
		ComposeFile: composePath,
		DataPath:    appData,
		InstalledAt: time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Save to database (unified apps table, source='casaos', deploy_mode='stack' for new Swarm installs)
	_, err = m.db.db.Exec(`INSERT INTO apps 
		(name, display_name, description, type, category, source,
		 store_id, store_app_id, compose_path, data_path,
		 enabled, deploy_mode, icon_url, version, homepage,
		 created_at, updated_at)
		VALUES (?, ?, ?, 'user', ?, 'casaos', ?, ?, ?, ?, TRUE, 'stack', ?, ?, ?, ?, ?)`,
		installed.Name, installed.Title, installed.Description,
		installed.Category, installed.StoreID, installed.StoreAppID,
		installed.ComposeFile, installed.DataPath,
		installed.Icon, installed.Version, installed.WebUI,
		installed.InstalledAt.Format(time.RFC3339), installed.UpdatedAt.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("failed to save app record: %w", err)
	}

	// Store NPM proxy ID and FQDN in the fqdns table (replaces old installed_apps.npm_proxy_id)
	if npmProxyID > 0 && appFQDN != "" {
		var appID int64
		if err := m.db.db.QueryRow("SELECT id FROM apps WHERE name = ?", installed.Name).Scan(&appID); err == nil {
			m.db.db.Exec(`INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port, npm_proxy_id)
				VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
				appID, appFQDN, installed.Name, appPort, npmProxyID)
		}
	}

	m.mu.Lock()
	m.installed[installed.ID] = installed
	if app, ok := m.catalog[storeApp.ID]; ok {
		app.Installed = true
	}
	m.mu.Unlock()

	return installed, nil
}

func (m *AppStoreManager) processManifest(manifest, appID, dataDir string, req *models.AppInstallRequest) string {
	// Get system values
	puid := "1000"
	pgid := "1000"
	tz := os.Getenv("TZ")
	if tz == "" {
		tz = "UTC"
	}

	// Find available port if needed
	webUIPort := m.findAvailablePort(8080)

	// Replace CasaOS system variables
	replacements := map[string]string{
		"$PUID":         puid,
		"${PUID}":       puid,
		"$PGID":         pgid,
		"${PGID}":       pgid,
		"$TZ":           tz,
		"${TZ}":         tz,
		"$AppID":        appID,
		"${AppID}":      appID,
		"${WEBUI_PORT}": fmt.Sprintf("%d", webUIPort),
	}

	result := manifest
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	// Replace data path references
	result = strings.ReplaceAll(result, "/DATA/AppData/$AppID", dataDir)
	result = strings.ReplaceAll(result, "/DATA/AppData/${AppID}", dataDir)

	// Apply env overrides
	for key, val := range req.EnvOverrides {
		result = strings.ReplaceAll(result, fmt.Sprintf("${%s}", key), val)
	}

	return result
}

func (m *AppStoreManager) findAvailablePort(start int) int {
	// User apps should be in range 6100-6999
	end := 6999
	if start < 6100 {
		start = 6100
	}
	for port := start; port <= end; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	return start
}

// GetInstalledApps returns all installed apps
func (m *AppStoreManager) GetInstalledApps() []*models.InstalledApp {
	m.mu.RLock()
	defer m.mu.RUnlock()

	apps := make([]*models.InstalledApp, 0, len(m.installed))
	for _, app := range m.installed {
		// Refresh status
		m.refreshAppStatus(app)
		apps = append(apps, app)
	}

	sort.Slice(apps, func(i, j int) bool {
		return apps[i].Name < apps[j].Name
	})

	return apps
}

// GetInstalledApp returns a specific installed app
func (m *AppStoreManager) GetInstalledApp(appID string) *models.InstalledApp {
	m.mu.RLock()
	defer m.mu.RUnlock()

	app := m.installed[appID]
	if app != nil {
		m.refreshAppStatus(app)
	}
	return app
}

func (m *AppStoreManager) refreshAppStatus(app *models.InstalledApp) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	deployMode := m.getDeployMode(app.ID)

	if deployMode == "stack" {
		// Swarm stack: check services via docker stack ps
		cmd := exec.CommandContext(ctx, "docker", "stack", "ps", app.ID, "--format", "{{.CurrentState}}", "--no-trunc")
		output, err := cmd.Output()
		if err != nil {
			app.Status = "stopped"
			return
		}

		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) == 0 || lines[0] == "" {
			app.Status = "stopped"
			return
		}

		running := false
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "running") {
				running = true
				break
			}
		}

		if running {
			app.Status = "running"
		} else {
			app.Status = "stopped"
		}
		return
	}

	// Legacy compose mode
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", app.ComposeFile, "ps", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		app.Status = "error"
		return
	}

	// Parse container status
	var containers []map[string]interface{}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var c map[string]interface{}
		if err := json.Unmarshal([]byte(line), &c); err == nil {
			containers = append(containers, c)
		}
	}

	if len(containers) == 0 {
		app.Status = "stopped"
		return
	}

	// Check if any container is running
	running := false
	for _, c := range containers {
		state, _ := c["State"].(string)
		if state == "running" {
			running = true
			break
		}
	}

	if running {
		app.Status = "running"
	} else {
		app.Status = "stopped"
	}

	// Update containers info
	app.Containers = make([]models.AppContainer, 0)
	for _, c := range containers {
		app.Containers = append(app.Containers, models.AppContainer{
			ID:     getString(c, "ID"),
			Name:   getString(c, "Name"),
			Image:  getString(c, "Image"),
			Status: getString(c, "Status"),
			State:  getString(c, "State"),
		})
	}
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// getDeployMode returns the deploy mode for an installed app
func (m *AppStoreManager) getDeployMode(appID string) string {
	var mode string
	err := m.db.db.QueryRow(`SELECT COALESCE(deploy_mode, 'compose') FROM apps WHERE name = ?`, appID).Scan(&mode)
	if err != nil {
		return "compose" // default to compose for legacy apps
	}
	return mode
}

// StartApp starts an installed app
func (m *AppStoreManager) StartApp(appID string) error {
	app := m.GetInstalledApp(appID)
	if app == nil {
		return fmt.Errorf("app not found: %s", appID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if m.getDeployMode(appID) == "stack" {
		// Swarm stack: redeploy
		cmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
			"-c", app.ComposeFile,
			"--resolve-image=never",
			appID,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("stack deploy failed: %s", string(output))
		}
	} else {
		// Legacy compose mode
		cmd := exec.CommandContext(ctx, "docker", "compose", "-f", app.ComposeFile, "start")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("start failed: %s", string(output))
		}
	}

	app.Status = "running"
	m.updateAppStatus(appID, "running")
	return nil
}

// StopApp stops an installed app
func (m *AppStoreManager) StopApp(appID string) error {
	app := m.GetInstalledApp(appID)
	if app == nil {
		return fmt.Errorf("app not found: %s", appID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if m.getDeployMode(appID) == "stack" {
		// Swarm stack: remove the stack (preserves data, can redeploy to start)
		cmd := exec.CommandContext(ctx, "docker", "stack", "rm", appID)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("stack rm failed: %s", string(output))
		}
	} else {
		// Legacy compose mode
		cmd := exec.CommandContext(ctx, "docker", "compose", "-f", app.ComposeFile, "stop")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("stop failed: %s", string(output))
		}
	}

	app.Status = "stopped"
	m.updateAppStatus(appID, "stopped")
	return nil
}

// RestartApp restarts an installed app
func (m *AppStoreManager) RestartApp(appID string) error {
	app := m.GetInstalledApp(appID)
	if app == nil {
		return fmt.Errorf("app not found: %s", appID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if m.getDeployMode(appID) == "stack" {
		// Swarm stack: force update redeploys all services
		cmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
			"-c", app.ComposeFile,
			"--resolve-image=never",
			appID,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("stack redeploy failed: %s", string(output))
		}
	} else {
		// Legacy compose mode
		cmd := exec.CommandContext(ctx, "docker", "compose", "-f", app.ComposeFile, "restart")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("restart failed: %s", string(output))
		}
	}

	app.Status = "running"
	m.updateAppStatus(appID, "running")
	return nil
}

// RemoveApp removes an installed app
func (m *AppStoreManager) RemoveApp(appID string, deleteData bool) error {
	app := m.GetInstalledApp(appID)
	if app == nil {
		return fmt.Errorf("app not found: %s", appID)
	}

	// Remove NPM proxy host (npm_proxy_id now tracked in fqdns table)
	var npmProxyID int
	m.db.db.QueryRow(`SELECT COALESCE(f.npm_proxy_id, 0) FROM fqdns f
		JOIN apps a ON a.id = f.app_id WHERE a.name = ? AND f.npm_proxy_id > 0 LIMIT 1`,
		appID).Scan(&npmProxyID)
	if npmProxyID > 0 {
		if err := m.removeNPMProxyHost(npmProxyID); err != nil {
			log.Printf("Warning: Failed to remove NPM proxy: %v", err)
		}
	}

	// Remove DNS entry via PiholeManager
	appFQDN := fmt.Sprintf("%s.%s", appID, m.baseDomain)
	if err := m.removePiholeDNS(appFQDN); err != nil {
		log.Printf("Warning: Failed to remove DNS entry for %s: %v", appFQDN, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Stop and remove containers
	if m.getDeployMode(appID) == "stack" {
		// Swarm stack: remove the stack
		cmd := exec.CommandContext(ctx, "docker", "stack", "rm", appID)
		cmd.CombinedOutput() // Best-effort
	} else {
		// Legacy compose mode
		cmd := exec.CommandContext(ctx, "docker", "compose", "-f", app.ComposeFile, "down", "--rmi", "all", "-v")
		cmd.CombinedOutput() // Best-effort
	}

	// Get base app directory (parent of appconfig)
	appConfigDir := filepath.Dir(app.ComposeFile)
	appBaseDir := filepath.Dir(appConfigDir)

	if deleteData {
		// Remove entire app directory including data
		os.RemoveAll(appBaseDir)
	} else {
		// Remove only appconfig, keep appdata
		os.RemoveAll(appConfigDir)
	}

	// Remove from database (unified apps table)
	m.db.db.Exec(`DELETE FROM apps WHERE name = ? AND source = 'casaos'`, appID)

	// Update catalog
	m.mu.Lock()
	delete(m.installed, appID)
	if app.StoreAppID != "" {
		if storeApp, ok := m.catalog[app.StoreAppID]; ok {
			storeApp.Installed = false
		}
	}
	m.mu.Unlock()

	return nil
}

func (m *AppStoreManager) updateAppStatus(appID, status string) {
	// Status is not persisted in the unified apps table (Swarm is truth).
	// Only update the timestamp to track last state change.
	m.db.db.Exec(`UPDATE apps SET updated_at = ? WHERE name = ?`,
		time.Now().Format(time.RFC3339), appID)
}

// ValidateAppName validates an app name
func ValidateAppName(name string) bool {
	matched, _ := regexp.MatchString(`^[a-z0-9][a-z0-9_-]*$`, name)
	return matched
}

// ============================================================================
// NPM (Nginx Proxy Manager) API Integration
// ============================================================================

// NPMCredentials for API authentication
type NPMCredentials struct {
	Identity string `json:"identity"`
	Secret   string `json:"secret"`
}

// NPMTokenResponse from /api/tokens
type NPMTokenResponse struct {
	Token   string `json:"token"`
	Expires string `json:"expires"`
}

// NPMProxyHost represents a proxy host in NPM
type NPMProxyHost struct {
	ID                    int      `json:"id,omitempty"`
	DomainNames           []string `json:"domain_names"`
	ForwardHost           string   `json:"forward_host"`
	ForwardPort           int      `json:"forward_port"`
	ForwardScheme         string   `json:"forward_scheme"`
	CertificateID         int      `json:"certificate_id,omitempty"`
	SSLForced             bool     `json:"ssl_forced"`
	BlockExploits         bool     `json:"block_exploits"`
	CachingEnabled        bool     `json:"caching_enabled"`
	AllowWebsocketUpgrade bool     `json:"allow_websocket_upgrade"`
	AccessListID          int      `json:"access_list_id"`
	AdvancedConfig        string   `json:"advanced_config"`
	Enabled               bool     `json:"enabled"`
	Meta                  struct {
		LetsencryptAgree bool   `json:"letsencrypt_agree"`
		DNSChallenge     bool   `json:"dns_challenge"`
		NginxOnline      bool   `json:"nginx_online"`
		NginxErr         string `json:"nginx_err"`
	} `json:"meta"`
}

// initNPMToken obtains an API token from NPM
func (m *AppStoreManager) initNPMToken() {
	// Wait for NPM to be ready
	time.Sleep(10 * time.Second)

	// Try to get token with default credentials
	// In production, these should be read from /cubeos/coreapps/npm/.env
	creds := NPMCredentials{
		Identity: "admin@cubeos.cube",
		Secret:   "changeme",
	}

	// Read actual credentials from NPM env if available
	envPath := filepath.Join(m.coreAppsPath, "npm", ".env")
	if data, err := os.ReadFile(envPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "NPM_ADMIN_EMAIL=") {
				creds.Identity = strings.TrimPrefix(line, "NPM_ADMIN_EMAIL=")
			}
			if strings.HasPrefix(line, "NPM_ADMIN_PASSWORD=") {
				creds.Secret = strings.TrimPrefix(line, "NPM_ADMIN_PASSWORD=")
			}
		}
	}

	token, err := m.getNPMToken(creds)
	if err != nil {
		log.Printf("Warning: Failed to get NPM token: %v", err)
		return
	}

	m.mu.Lock()
	m.npmToken = token
	m.mu.Unlock()

	log.Println("NPM API token acquired successfully")
}

// getNPMToken requests a token from NPM API
func (m *AppStoreManager) getNPMToken(creds NPMCredentials) (string, error) {
	payload := map[string]string{
		"identity": creds.Identity,
		"secret":   creds.Secret,
	}

	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post(
		m.npmAPIURL+"/tokens",
		"application/json",
		strings.NewReader(string(jsonData)),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("NPM API error %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp NPMTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.Token, nil
}

// addNPMProxyHost creates a proxy host in NPM for an app and returns the proxy host ID
func (m *AppStoreManager) addNPMProxyHost(appName, fqdn string, port int, scheme string, websocket bool) (int, error) {
	m.mu.RLock()
	token := m.npmToken
	m.mu.RUnlock()

	if token == "" {
		return 0, fmt.Errorf("NPM API token not available")
	}

	proxyHost := NPMProxyHost{
		DomainNames:           []string{fqdn},
		ForwardHost:           m.gatewayIP,
		ForwardPort:           port,
		ForwardScheme:         scheme,
		SSLForced:             false, // User can enable later
		BlockExploits:         true,
		CachingEnabled:        false,
		AllowWebsocketUpgrade: websocket,
		AccessListID:          0,
		AdvancedConfig:        "",
		Enabled:               true,
	}

	jsonData, _ := json.Marshal(proxyHost)

	req, err := http.NewRequest("POST", m.npmAPIURL+"/nginx/proxy-hosts", strings.NewReader(string(jsonData)))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("NPM API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response to get the proxy host ID
	var result NPMProxyHost
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to parse NPM response: %w", err)
	}

	return result.ID, nil
}

// removeNPMProxyHost removes a proxy host from NPM
func (m *AppStoreManager) removeNPMProxyHost(proxyID int) error {
	if proxyID == 0 {
		return nil // No proxy to remove
	}

	m.mu.RLock()
	token := m.npmToken
	m.mu.RUnlock()

	if token == "" {
		return fmt.Errorf("NPM API token not available")
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/nginx/proxy-hosts/%d", m.npmAPIURL, proxyID), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("NPM API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetNPMProxyHosts returns all proxy hosts from NPM
func (m *AppStoreManager) GetNPMProxyHosts() ([]NPMProxyHost, error) {
	m.mu.RLock()
	token := m.npmToken
	m.mu.RUnlock()

	if token == "" {
		return nil, fmt.Errorf("NPM API token not available")
	}

	req, err := http.NewRequest("GET", m.npmAPIURL+"/nginx/proxy-hosts", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var hosts []NPMProxyHost
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, err
	}

	return hosts, nil
}

// ============================================================================
// App Configuration Editor (docker-compose.yml and .env)
// ============================================================================

// AppConfig represents an app's configuration files
type AppConfig struct {
	AppID        string `json:"app_id"`
	AppPath      string `json:"app_path"`
	IsCoreApp    bool   `json:"is_core_app"`
	ComposeYAML  string `json:"compose_yaml"`
	EnvContent   string `json:"env_content"`
	LastModified string `json:"last_modified"`
}

// GetAppConfig returns the configuration files for an app
func (m *AppStoreManager) GetAppConfig(appID string, isCoreApp bool) (*AppConfig, error) {
	var appPath, configPath string
	if isCoreApp {
		// Core apps: /cubeos/coreapps/{app}/docker-compose.yml (flat)
		appPath = filepath.Join(m.coreAppsPath, appID)
		configPath = appPath
	} else {
		// User apps: /cubeos/apps/{app}/appconfig/docker-compose.yml (nested)
		appPath = filepath.Join(m.appsPath, appID)
		configPath = filepath.Join(appPath, "appconfig")
		// Fallback to flat structure for legacy apps
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			configPath = appPath
		}
	}

	// Check if app directory exists
	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("app not found: %s", appID)
	}

	config := &AppConfig{
		AppID:     appID,
		AppPath:   configPath,
		IsCoreApp: isCoreApp,
	}

	// Read docker-compose.yml
	composePath := filepath.Join(configPath, "docker-compose.yml")
	if data, err := os.ReadFile(composePath); err == nil {
		config.ComposeYAML = string(data)
		if info, err := os.Stat(composePath); err == nil {
			config.LastModified = info.ModTime().Format(time.RFC3339)
		}
	}

	// Read .env file
	envPath := filepath.Join(configPath, ".env")
	if data, err := os.ReadFile(envPath); err == nil {
		config.EnvContent = string(data)
	}

	return config, nil
}

// UpdateAppConfig updates the configuration files for an app
func (m *AppStoreManager) UpdateAppConfig(appID string, isCoreApp bool, composeYAML, envContent string) error {
	var appPath, configPath string
	if isCoreApp {
		// Core apps: /cubeos/coreapps/{app}/docker-compose.yml (flat)
		appPath = filepath.Join(m.coreAppsPath, appID)
		configPath = appPath
	} else {
		// User apps: /cubeos/apps/{app}/appconfig/docker-compose.yml (nested)
		appPath = filepath.Join(m.appsPath, appID)
		configPath = filepath.Join(appPath, "appconfig")
		// Fallback to flat structure for legacy apps
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			configPath = appPath
		}
	}

	// Check if app directory exists
	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		return fmt.Errorf("app not found: %s", appID)
	}

	// Backup existing files
	backupDir := filepath.Join(configPath, ".backups", time.Now().Format("20060102-150405"))
	os.MkdirAll(backupDir, 0755)

	composePath := filepath.Join(configPath, "docker-compose.yml")
	envPath := filepath.Join(configPath, ".env")

	// Backup compose file
	if data, err := os.ReadFile(composePath); err == nil {
		os.WriteFile(filepath.Join(backupDir, "docker-compose.yml"), data, 0644)
	}

	// Backup env file
	if data, err := os.ReadFile(envPath); err == nil {
		os.WriteFile(filepath.Join(backupDir, ".env"), data, 0644)
	}

	// Validate docker-compose.yml syntax
	if composeYAML != "" {
		var testYAML interface{}
		if err := yaml.Unmarshal([]byte(composeYAML), &testYAML); err != nil {
			return fmt.Errorf("invalid YAML syntax: %w", err)
		}
		if err := os.WriteFile(composePath, []byte(composeYAML), 0644); err != nil {
			return fmt.Errorf("failed to write docker-compose.yml: %w", err)
		}
	}

	// Write .env file
	if envContent != "" {
		if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
			return fmt.Errorf("failed to write .env: %w", err)
		}
	}

	return nil
}

// RestartAppWithConfig restarts an app after config change
func (m *AppStoreManager) RestartAppWithConfig(appID string, isCoreApp bool) error {
	var appPath, configPath string
	if isCoreApp {
		// Core apps: /cubeos/coreapps/{app}/docker-compose.yml (flat)
		appPath = filepath.Join(m.coreAppsPath, appID)
		configPath = appPath
	} else {
		// User apps: /cubeos/apps/{app}/appconfig/docker-compose.yml (nested)
		appPath = filepath.Join(m.appsPath, appID)
		configPath = filepath.Join(appPath, "appconfig")
		// Fallback to flat structure for legacy apps
		if _, err := os.Stat(filepath.Join(configPath, "docker-compose.yml")); os.IsNotExist(err) {
			configPath = appPath
		}
	}

	composePath := filepath.Join(configPath, "docker-compose.yml")
	envPath := filepath.Join(configPath, ".env")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Check deploy mode for user apps
	deployMode := m.getDeployMode(appID)
	if !isCoreApp && deployMode == "stack" {
		// Swarm stack: redeploy with updated config
		cmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
			"-c", composePath,
			"--resolve-image=never",
			appID,
		)
		cmd.Dir = configPath
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to redeploy stack: %s", string(output))
		}
		return nil
	}

	// Compose mode (core apps and legacy user apps)
	stopCmd := exec.CommandContext(ctx, "docker", "compose", "-f", composePath, "--env-file", envPath, "down")
	stopCmd.Dir = configPath
	if output, err := stopCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop: %s", string(output))
	}

	startCmd := exec.CommandContext(ctx, "docker", "compose", "-f", composePath, "--env-file", envPath, "up", "-d")
	startCmd.Dir = configPath
	if output, err := startCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start: %s", string(output))
	}

	return nil
}

// ListCoreApps returns all core apps
func (m *AppStoreManager) ListCoreApps() ([]AppConfig, error) {
	entries, err := os.ReadDir(m.coreAppsPath)
	if err != nil {
		return nil, err
	}

	var apps []AppConfig
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		config, err := m.GetAppConfig(entry.Name(), true)
		if err != nil {
			continue
		}
		apps = append(apps, *config)
	}

	return apps, nil
}

// GetConfigBackups returns available backups for an app
func (m *AppStoreManager) GetConfigBackups(appID string, isCoreApp bool) ([]string, error) {
	var configPath string
	if isCoreApp {
		configPath = filepath.Join(m.coreAppsPath, appID)
	} else {
		// User apps store backups in appconfig/.backups
		configPath = filepath.Join(m.appsPath, appID, "appconfig")
		// Fallback to flat structure for legacy apps
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			configPath = filepath.Join(m.appsPath, appID)
		}
	}

	backupDir := filepath.Join(configPath, ".backups")
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, nil // No backups yet
	}

	var backups []string
	for _, entry := range entries {
		if entry.IsDir() {
			backups = append(backups, entry.Name())
		}
	}

	return backups, nil
}

// RestoreConfigBackup restores a config backup
func (m *AppStoreManager) RestoreConfigBackup(appID string, isCoreApp bool, backupName string) error {
	var configPath string
	if isCoreApp {
		configPath = filepath.Join(m.coreAppsPath, appID)
	} else {
		// User apps store backups in appconfig/.backups, restore to appconfig/
		configPath = filepath.Join(m.appsPath, appID, "appconfig")
		// Fallback to flat structure for legacy apps
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			configPath = filepath.Join(m.appsPath, appID)
		}
	}

	backupDir := filepath.Join(configPath, ".backups", backupName)
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupName)
	}

	// Restore compose file to configPath (not appPath)
	if data, err := os.ReadFile(filepath.Join(backupDir, "docker-compose.yml")); err == nil {
		if err := os.WriteFile(filepath.Join(configPath, "docker-compose.yml"), data, 0644); err != nil {
			return fmt.Errorf("failed to restore docker-compose.yml: %w", err)
		}
	}

	// Restore env file to configPath
	if data, err := os.ReadFile(filepath.Join(backupDir, ".env")); err == nil {
		if err := os.WriteFile(filepath.Join(configPath, ".env"), data, 0644); err != nil {
			return fmt.Errorf("failed to restore .env: %w", err)
		}
	}

	return nil
}

// removePiholeDNS removes DNS entry from Pi-hole via PiholeManager
func (m *AppStoreManager) removePiholeDNS(fqdn string) error {
	if m.pihole == nil {
		return fmt.Errorf("PiholeManager not configured")
	}
	return m.pihole.RemoveEntry(fqdn)
}
