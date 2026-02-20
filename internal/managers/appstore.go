package managers

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// AppStoreManager handles app store and installed app operations
type AppStoreManager struct {
	db           *DatabaseManager
	pihole       *PiholeManager
	ports        *PortManager // Port allocation with triple-source validation
	dataPath     string
	cachePath    string
	appsPath     string // /cubeos/apps - user apps, freely removable
	coreAppsPath string // /cubeos/coreapps - system critical, protected
	appDataPath  string // deprecated - now per-app at /cubeos/apps/{app}/appdata
	baseDomain   string
	gatewayIP    string
	npm          *NPMManager // NPM service account (managed by npm.go)
	stores       map[string]*models.AppStore
	catalog      map[string]*models.StoreApp
	installed    map[string]*models.InstalledApp
	mu           sync.RWMutex

	// Registry-aware install flow (T15/T16)
	registryURL    string       // Local registry URL (e.g., http://10.42.24.1:5000)
	registryClient *http.Client // HTTP client for registry API calls
	onlineMu       sync.Mutex   // Protects online cache
	onlineCached   bool         // Cached online status
	onlineCacheAt  time.Time    // When online status was last checked
}

// NewAppStoreManager creates a new app store manager with centralized config
func NewAppStoreManager(cfg *config.Config, db *DatabaseManager, dataPath string, pihole *PiholeManager, npm *NPMManager, ports *PortManager) *AppStoreManager {
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
		npm:          npm,
		ports:        ports,
		dataPath:     dataPath,
		cachePath:    cachePath,
		appsPath:     appsPath,
		coreAppsPath: coreAppsPath,
		appDataPath:  "", // deprecated - now per-app
		baseDomain:   cfg.Domain,
		gatewayIP:    cfg.GatewayIP,
		stores:       make(map[string]*models.AppStore),
		catalog:      make(map[string]*models.StoreApp),
		installed:    make(map[string]*models.InstalledApp),
	}

	// Registry-aware install flow: resolve registry URL from env or default
	registryURL := os.Getenv("REGISTRY_URL")
	if registryURL == "" {
		registryURL = "http://" + cfg.GatewayIP + ":5000"
	}
	m.registryURL = registryURL
	m.registryClient = &http.Client{Timeout: 5 * time.Second}

	m.initDB()
	m.loadStores()
	m.loadInstalledApps()
	m.loadCatalog()

	// B100: Seed default CasaOS store if no stores exist.
	// Without this, the Browse tab shows "No Apps Found" on first boot.
	m.seedDefaultStore()

	return m
}

// initDB ensures app store tables exist.
// Core table creation is handled by database.InitSchema().
// The apps table already has all needed columns (deploy_mode, store_app_id, etc.)
func (m *AppStoreManager) initDB() {
	// Ensure store_app_id column exists for older databases
	m.db.db.Exec(`ALTER TABLE apps ADD COLUMN store_app_id TEXT DEFAULT NULL`)

	// Add data column to app_catalog for full JSON roundtrip (existing columns
	// miss fields like tagline, tips, author, screenshots, etc.)
	m.db.db.Exec(`ALTER TABLE app_catalog ADD COLUMN data TEXT DEFAULT '{}'`)
}

// seedDefaultStore registers the CasaOS official app store if no stores exist.
// B100: Without a default store, the Browse tab shows empty on first boot.
// After seeding, triggers a background sync if the device appears to be online.
func (m *AppStoreManager) seedDefaultStore() {
	m.mu.RLock()
	storeCount := len(m.stores)
	m.mu.RUnlock()

	if storeCount > 0 {
		return // Already have stores, nothing to seed
	}

	const defaultStoreURL = "https://github.com/IceWhaleTech/CasaOS-AppStore"
	const defaultStoreName = "CasaOS Official"
	const defaultStoreDesc = "Official CasaOS-compatible app store"

	log.Info().Msg("AppStoreManager: no stores found, seeding default CasaOS store (B100)")

	store, err := m.RegisterStore(defaultStoreURL, defaultStoreName, defaultStoreDesc)
	if err != nil {
		log.Error().Err(err).Msg("AppStoreManager: failed to seed default store")
		return
	}

	// Trigger background sync — non-blocking, will populate the catalog if online.
	// If offline, the user can manually sync later via the dashboard "Sync Stores" button.
	go func() {
		if err := m.SyncStore(store.ID); err != nil {
			log.Warn().Err(err).Msg("AppStoreManager: background sync of default store failed (device may be offline)")
		} else {
			log.Info().Int("catalog_size", len(m.catalog)).Msg("AppStoreManager: default store synced successfully")
		}
	}()
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
		log.Warn().Err(err).Msg("error iterating app stores")
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
		COALESCE(webui_type, 'browser') as webui_type,
		COALESCE(compose_path, '') as compose_file, COALESCE(data_path, '') as data_path,
		created_at, updated_at
		FROM apps WHERE source = 'casaos'`)
	if err != nil {
		return
	}
	defer rows.Close()

	var orphans []string
	for rows.Next() {
		var app models.InstalledApp
		var installedAt, updatedAt string
		rows.Scan(&app.ID, &app.StoreID, &app.StoreAppID, &app.Name, &app.Title, &app.Description,
			&app.Icon, &app.Category, &app.Version, &app.WebUI, &app.WebUIType,
			&app.ComposeFile,
			&app.DataPath, &installedAt, &updatedAt)
		app.InstalledAt, _ = time.Parse(time.RFC3339, installedAt)
		app.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

		// Reconcile: if the compose file is gone AND no Swarm stack exists,
		// the app was removed outside the API (manual rm -rf / stack rm).
		// Mark for cleanup instead of loading a ghost record.
		composeExists := app.ComposeFile != "" && fileExists(app.ComposeFile)
		stackExists := swarmStackExists(app.ID)
		if !composeExists && !stackExists {
			log.Warn().Str("app", app.ID).
				Str("compose", app.ComposeFile).
				Msg("orphaned installed app record — compose and stack both missing, cleaning up")
			orphans = append(orphans, app.ID)
			continue
		}

		app.Status = "unknown" // Will be refreshed from Swarm at query time
		m.installed[app.ID] = &app
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("error iterating installed apps")
	}

	// Remove orphaned records from DB
	for _, id := range orphans {
		m.db.db.Exec("DELETE FROM apps WHERE name = ?", id)
		log.Info().Str("app", id).Msg("removed orphaned installed app record from database")
	}
}

// loadCatalog loads cached catalog entries from SQLite.
// This ensures the catalog survives API restarts without requiring a network sync.
func (m *AppStoreManager) loadCatalog() {
	rows, err := m.db.db.Query(`SELECT id, data, COALESCE(manifest_path, '') FROM app_catalog WHERE data != '' AND data != '{}'`)
	if err != nil {
		log.Warn().Err(err).Msg("failed to query app_catalog")
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id, data, manifestPath string
		if err := rows.Scan(&id, &data, &manifestPath); err != nil {
			continue
		}
		var app models.StoreApp
		if err := json.Unmarshal([]byte(data), &app); err != nil {
			log.Warn().Str("id", id).Err(err).Msg("failed to unmarshal catalog entry")
			continue
		}

		// Restore ManifestPath (excluded from JSON via json:"-")
		app.ManifestPath = manifestPath

		// Cross-reference installed status
		for _, inst := range m.installed {
			if inst.StoreAppID == app.ID {
				app.Installed = true
				break
			}
		}

		m.catalog[id] = &app
		count++
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("error iterating app_catalog rows")
	}

	if count > 0 {
		log.Info().Int("count", count).Msg("loaded app catalog from database")
	}
}

// persistCatalog writes catalog entries for a store to SQLite.
// Called after SyncStore() populates m.catalog from parsed manifests.
func (m *AppStoreManager) persistCatalog(storeID string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Delete old entries for this store, then insert fresh
	m.db.db.Exec(`DELETE FROM app_catalog WHERE store_id = ?`, storeID)

	for _, app := range m.catalog {
		if app.StoreID != storeID {
			continue
		}

		dataJSON, err := json.Marshal(app)
		if err != nil {
			log.Warn().Str("id", app.ID).Err(err).Msg("failed to marshal catalog entry")
			continue
		}

		titleJSON, _ := json.Marshal(app.Title)
		descJSON, _ := json.Marshal(app.Description)
		archJSON, _ := json.Marshal(app.Architectures)

		_, err = m.db.db.Exec(`INSERT OR REPLACE INTO app_catalog 
			(id, store_id, name, title, description, icon_url, category, version, architectures, manifest_path, data, cached_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			app.ID, app.StoreID, app.Name, string(titleJSON), string(descJSON),
			app.Icon, app.Category, app.Version, string(archJSON), app.ManifestPath,
			string(dataJSON), time.Now().Format(time.RFC3339))
		if err != nil {
			log.Warn().Str("id", app.ID).Err(err).Msg("failed to persist catalog entry")
		}
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

	// Clean catalog from DB (CASCADE should handle this, but be explicit)
	m.db.db.Exec(`DELETE FROM app_catalog WHERE store_id = ?`, storeID)

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

	// Persist catalog to SQLite for restart survival
	m.persistCatalog(storeID)

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
	os.MkdirAll(appData, 0777) // 0777: containers may run as non-root users
	os.Chmod(appData, 0777)    // Explicit chmod to override umask

	// Allocate a port in the user app range (6100-6999) via triple-source validation
	allocatedPort, err := m.ports.AllocateUserPort()
	if err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	// Process manifest with variable substitution
	processedManifest := m.processManifest(string(manifestData), req.AppName, appData, req)

	// Remap the main published port to our allocated CubeOS port (6100-6999)
	// This prevents CasaOS manifests from colliding with infrastructure ports
	processedManifest, err = remapPorts(processedManifest, allocatedPort, storeApp.PortMap)
	if err != nil {
		log.Warn().Err(err).Str("app", req.AppName).Msg("port remapping failed, using original ports")
	}

	// Remap external bind mounts to safe defaults under /cubeos/apps/{app}/appdata/
	overrides := req.VolumeOverrides
	if overrides == nil {
		overrides = make(map[string]string)
	}
	var remapResults []RemapResult
	processedManifest, remapResults, err = RemapExternalVolumes(processedManifest, req.AppName, appData, overrides)
	if err != nil {
		log.Warn().Err(err).Str("app", req.AppName).Msg("volume remapping failed, using original paths")
	}

	// Write docker-compose.yml to appconfig
	composePath := filepath.Join(appConfig, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(processedManifest), 0644); err != nil {
		return nil, fmt.Errorf("failed to write compose file: %w", err)
	}

	// Pre-create bind mount source directories.
	// Docker Swarm (unlike docker compose) does NOT auto-create host paths for bind mounts.
	// Parse the written compose and mkdir -p every host path under /cubeos/apps/.
	preCreateBindMounts(processedManifest)

	// T16: Offline awareness — verify images are available before deploying.
	// After rewriteImagesToLocalRegistry (T15), images in the local registry
	// already have localhost:5000/ prefix. Non-local images need upstream pull.
	// If we're offline and an image isn't available locally, fail early.
	imageRefs := extractImageRefs(processedManifest)
	for _, ref := range imageRefs {
		// Images from local registry are always available
		if strings.HasPrefix(ref, "localhost:5000/") {
			continue
		}
		// Check if the image is already in Docker's local store
		inspectCmd := exec.Command("docker", "image", "inspect", ref)
		if inspectCmd.Run() == nil {
			continue // Image available locally
		}
		// Image not local — check if we can pull it
		if !m.isOnline() {
			os.RemoveAll(appBase)
			return nil, fmt.Errorf("OFFLINE_IMAGE_UNAVAILABLE: image %s is not cached locally and device is offline", ref)
		}
		log.Info().Str("image", ref).Msg("image not cached, will pull from upstream")
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

	// Build WebUI URL using configured gateway IP and the ALLOCATED port (not original)
	webUI := ""
	appPort := allocatedPort
	if storeApp.PortMap != "" {
		scheme := storeApp.Scheme
		if scheme == "" {
			scheme = "http"
		}
		index := storeApp.Index
		if index == "" {
			index = "/"
		}
		webUI = fmt.Sprintf("%s://%s:%d%s", scheme, m.gatewayIP, allocatedPort, index)
	}
	if appPort == 0 {
		appPort = allocatedPort
	}

	// Build FQDN for this app using a clean subdomain
	subdomain := prettifySubdomain(req.AppName, req.StoreID)
	log.Info().Str("app", req.AppName).Str("store", req.StoreID).Str("subdomain", subdomain).Msg("prettified subdomain for FQDN")

	// Check for FQDN collision with existing DNS entries
	appFQDN := fmt.Sprintf("%s.%s", subdomain, m.baseDomain)
	if m.pihole != nil {
		if existing, _ := m.pihole.GetEntry(appFQDN); existing != nil {
			// Collision — fall back to full app name
			log.Warn().Str("fqdn", appFQDN).Msg("FQDN collision, using full app name")
			appFQDN = fmt.Sprintf("%s.%s", req.AppName, m.baseDomain)
		}
	}

	// Create NPM proxy host for FQDN access (non-fatal)
	var npmProxyID int
	if m.npm != nil && m.npm.IsAuthenticated() {
		host := &NPMProxyHostExtended{
			DomainNames:   []string{appFQDN},
			ForwardHost:   m.gatewayIP,
			ForwardPort:   appPort,
			ForwardScheme: "http",
		}
		if created, err := m.npm.CreateProxyHost(host); err != nil {
			log.Warn().Err(err).Str("fqdn", appFQDN).Msg("failed to create NPM proxy")
		} else {
			npmProxyID = created.ID
		}
	} else {
		log.Warn().Str("fqdn", appFQDN).Msg("NPM not available, skipping proxy creation")
	}

	// Create Pi-hole DNS entry for FQDN (non-fatal)
	if m.pihole != nil {
		if err := m.pihole.AddEntry(appFQDN, m.gatewayIP); err != nil {
			log.Warn().Err(err).Str("fqdn", appFQDN).Msg("failed to add DNS entry")
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

	// Get the app_id for foreign key references (port_allocations, fqdns)
	var appID int64
	if err := m.db.db.QueryRow("SELECT id FROM apps WHERE name = ?", installed.Name).Scan(&appID); err != nil {
		log.Error().Err(err).Str("app", installed.Name).Msg("failed to find app_id after insert")
	} else {
		// Record port allocation (ON DELETE CASCADE will clean up on uninstall)
		if portErr := m.ports.AllocatePort(appID, allocatedPort, "tcp", "Web UI", true); portErr != nil {
			log.Error().Err(portErr).Int("port", allocatedPort).Int64("app_id", appID).
				Msg("failed to record port allocation (port is still in use)")
		} else {
			log.Info().Int("port", allocatedPort).Int64("app_id", appID).Str("app", installed.Name).
				Msg("recorded port allocation")
		}
	}

	// Store FQDN in the fqdns table (for DNS cleanup during uninstall)
	if appFQDN != "" && appID > 0 {
		// Extract subdomain from the (possibly prettified) FQDN
		fqdnSubdomain := strings.TrimSuffix(appFQDN, "."+m.baseDomain)
		_, fqdnErr := m.db.db.Exec(`INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port, npm_proxy_id)
			VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
			appID, appFQDN, fqdnSubdomain, appPort, npmProxyID)
		if fqdnErr != nil {
			log.Error().Err(fqdnErr).Str("fqdn", appFQDN).Int64("app_id", appID).Int("port", appPort).
				Msg("failed to insert FQDN record")
		} else {
			log.Info().Str("fqdn", appFQDN).Int64("app_id", appID).Int("port", appPort).
				Msg("stored FQDN record")
		}
	}

	// Store volume mappings
	if len(remapResults) > 0 {
		m.StoreVolumeMappings(req.AppName, remapResults)
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

	// Default internal web UI port for CasaOS variable substitution.
	// This is the container-internal port, NOT the host-allocated port.
	// The host port is determined by remapPorts() using the allocated CubeOS port.
	webUIPort := 8080

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
	// CasaOS manifests use both variable form and hardcoded app name:
	//   /DATA/AppData/$AppID/...     (variable)
	//   /DATA/AppData/big-bear-xxx/  (hardcoded)
	result = strings.ReplaceAll(result, "/DATA/AppData/$AppID", dataDir)
	result = strings.ReplaceAll(result, "/DATA/AppData/${AppID}", dataDir)
	result = strings.ReplaceAll(result, "/DATA/AppData/"+appID, dataDir)

	// Apply env overrides
	for key, val := range req.EnvOverrides {
		result = strings.ReplaceAll(result, fmt.Sprintf("${%s}", key), val)
	}

	// Rewrite image references to use local registry where available (T15).
	// This enables offline installs for apps whose images are pre-loaded.
	result = m.rewriteImagesToLocalRegistry(result)

	// Sanitize Swarm-incompatible directives (depends_on map, container_name, etc.)
	sanitized, err := sanitizeForSwarm(result)
	if err != nil {
		log.Warn().Err(err).Str("app", appID).Msg("failed to sanitize manifest for Swarm, using as-is")
		return result
	}
	return sanitized
}

// ──────────────────────────────────────────────────────────────────────────────
// Registry-Aware Install Flow (T15/T16)
// ──────────────────────────────────────────────────────────────────────────────

// rewriteImagesToLocalRegistry rewrites image references in a compose manifest
// to use the local Docker registry (localhost:5000) when the image is available
// there. This enables offline installs for apps whose images are pre-loaded.
//
// Rules:
//   - Skip images already prefixed with localhost:5000/
//   - Skip CubeOS own images (ghcr.io/cubeos-app/)
//   - Check local registry via HEAD request on manifest
//   - If image exists locally → rewrite to localhost:5000/{repo}:{tag}
//   - If not → leave original (Docker will pull from upstream if online)
func (m *AppStoreManager) rewriteImagesToLocalRegistry(manifest string) string {
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &compose); err != nil {
		log.Warn().Err(err).Msg("registry rewrite: failed to parse YAML, skipping rewrite")
		return manifest
	}

	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return manifest
	}

	changed := false
	for svcName, svcDef := range services {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}
		image, ok := svc["image"].(string)
		if !ok || image == "" {
			continue
		}

		// Skip already-local images
		if strings.HasPrefix(image, "localhost:5000/") {
			continue
		}
		// Skip CubeOS own images (built and deployed separately)
		if strings.HasPrefix(image, "ghcr.io/cubeos-app/") {
			continue
		}

		repo, tag := normalizeImageRef(image)

		// Check if image exists in local registry
		if m.checkRegistryImage(repo, tag) {
			newImage := fmt.Sprintf("localhost:5000/%s:%s", repo, tag)
			svc["image"] = newImage
			changed = true
			log.Info().Str("service", svcName).Str("from", image).Str("to", newImage).Msg("registry rewrite: image found locally")
		}
	}

	if !changed {
		return manifest
	}

	// Re-serialize YAML — yaml.v3 preserves field order for maps
	out, err := yaml.Marshal(compose)
	if err != nil {
		log.Warn().Err(err).Msg("registry rewrite: failed to re-serialize YAML, using original")
		return manifest
	}
	return string(out)
}

// normalizeImageRef strips the registry host and splits into repo + tag.
// Examples:
//
//	"nginx"                           → "library/nginx", "latest"
//	"nginx:1.25"                      → "library/nginx", "1.25"
//	"kiwix/kiwix-serve:3.8.1"        → "kiwix/kiwix-serve", "3.8.1"
//	"docker.io/library/nginx:latest"  → "library/nginx", "latest"
//	"ghcr.io/user/repo:v1"           → "user/repo", "v1"
func normalizeImageRef(image string) (repo, tag string) {
	// Strip known registry hosts
	ref := image
	for _, prefix := range []string{
		"docker.io/", "index.docker.io/",
		"ghcr.io/", "quay.io/", "gcr.io/",
		"registry.hub.docker.com/",
	} {
		ref = strings.TrimPrefix(ref, prefix)
	}

	// Split repo:tag
	if idx := strings.LastIndex(ref, ":"); idx > 0 && !strings.Contains(ref[idx:], "/") {
		repo = ref[:idx]
		tag = ref[idx+1:]
	} else {
		repo = ref
		tag = "latest"
	}

	// Docker Hub images without a namespace use "library/" prefix
	// (e.g., "nginx" → "library/nginx") — but our local registry stores
	// them as-is (e.g., "tsl0922/ttyd"), so only add library/ for truly
	// bare names without any slash.
	// Actually, skopeo stores with the full path as pushed, so we should
	// match however the image was pushed to the local registry.
	// Leave as-is — the registry check will determine if it exists.

	return repo, tag
}

// checkRegistryImage checks whether a specific image:tag exists in the local
// Docker registry via a HEAD request on the manifest endpoint.
func (m *AppStoreManager) checkRegistryImage(repo, tag string) bool {
	// Construct manifest URL — repo name with slashes is a valid path in v2 API
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", m.registryURL, repo, tag)

	req, err := http.NewRequest("HEAD", manifestURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := m.registryClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// isOnline checks if the device has internet connectivity by pinging Docker Hub.
// Result is cached for 30 seconds to avoid per-install latency.
func (m *AppStoreManager) isOnline() bool {
	m.onlineMu.Lock()
	defer m.onlineMu.Unlock()

	// Return cached result if fresh (within 30s)
	if !m.onlineCacheAt.IsZero() && time.Since(m.onlineCacheAt) < 30*time.Second {
		return m.onlineCached
	}

	// Ping Docker Hub registry endpoint
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Head("https://registry-1.docker.io/v2/")
	if err != nil {
		m.onlineCached = false
		m.onlineCacheAt = time.Now()
		return false
	}
	defer resp.Body.Close()

	// 200 or 401 (unauthorized but reachable) both indicate online
	m.onlineCached = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
	m.onlineCacheAt = time.Now()
	return m.onlineCached
}

// extractImageRefs extracts all image references from a compose manifest YAML.
func extractImageRefs(manifest string) []string {
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &compose); err != nil {
		return nil
	}
	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return nil
	}

	var refs []string
	for _, svcDef := range services {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}
		if image, ok := svc["image"].(string); ok && image != "" {
			refs = append(refs, image)
		}
	}
	return refs
}

// remapPorts rewrites the host-published port in a compose manifest so that the
// app's main web UI port uses the CubeOS-allocated port (6100-6999 range) instead
// of whatever the CasaOS manifest originally declared.
//
// Without this, CasaOS manifests like LibreTranslate (5000:5000) would collide
// with CubeOS infrastructure services (registry uses 5000).
//
// portMap is the original web UI port from x-casaos metadata (e.g. "5000").
// If portMap is empty, the first published port of the first service is remapped.
func remapPorts(manifest string, allocatedPort int, portMap string) (string, error) {
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &compose); err != nil {
		return manifest, fmt.Errorf("failed to parse compose for port remapping: %w", err)
	}

	services, ok := compose["services"]
	if !ok {
		return manifest, nil
	}
	svcMap, ok := services.(map[string]interface{})
	if !ok {
		return manifest, nil
	}

	// Determine the original host port to find and replace
	var originalPort int
	if portMap != "" {
		fmt.Sscanf(portMap, "%d", &originalPort)
	}

	remapped := false
	for svcName, svcDef := range svcMap {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}

		ports, ok := svc["ports"].([]interface{})
		if !ok || len(ports) == 0 {
			continue
		}

		for i, p := range ports {
			switch port := p.(type) {
			case string:
				// Short form: "5000:5000", "5000:5000/tcp", "0.0.0.0:5000:5000"
				hostPort, containerPort, extra := parseShortPort(port)
				if originalPort > 0 && hostPort != originalPort {
					continue
				}
				// Remap
				newMapping := fmt.Sprintf("%d:%s", allocatedPort, containerPort)
				if extra != "" {
					newMapping = fmt.Sprintf("%s:%s", extra, newMapping)
				}
				ports[i] = newMapping
				log.Info().Str("service", svcName).
					Str("from", port).Str("to", newMapping).
					Msg("remapped port for CubeOS allocation")
				remapped = true

			case map[string]interface{}:
				// Long form: {target: 5000, published: 5000, protocol: tcp}
				published := toInt(port["published"])
				if originalPort > 0 && published != originalPort {
					continue
				}
				port["published"] = allocatedPort
				log.Info().Str("service", svcName).
					Int("from", published).Int("to", allocatedPort).
					Msg("remapped port for CubeOS allocation")
				remapped = true
			}

			// If we had no portMap hint, remap only the first port found
			if originalPort == 0 && remapped {
				break
			}
		}
		if remapped {
			break
		}
	}

	if !remapped {
		log.Warn().Int("allocatedPort", allocatedPort).Msg("no ports found to remap in manifest")
	}

	// B59: Normalize ALL published ports to int across all services.
	// yaml.v3 preserves quoted values as strings (e.g. published: "8384"),
	// which Docker Compose rejects with "ports.published must be a integer".
	// This ensures every long-form port entry has an integer published value.
	for _, svcDef := range svcMap {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}
		ports, ok := svc["ports"].([]interface{})
		if !ok {
			continue
		}
		for _, p := range ports {
			if port, ok := p.(map[string]interface{}); ok {
				if pub, exists := port["published"]; exists {
					port["published"] = toInt(pub)
				}
				if tgt, exists := port["target"]; exists {
					port["target"] = toInt(tgt)
				}
			}
		}
	}

	out, err := yaml.Marshal(compose)
	if err != nil {
		return manifest, fmt.Errorf("failed to serialize port-remapped compose: %w", err)
	}
	return string(out), nil
}

// parseShortPort parses Docker compose short port syntax.
// Returns (hostPort, containerPortWithProto, bindIP).
// Examples:
//
//	"5000:5000"           → (5000, "5000", "")
//	"5000:5000/tcp"       → (5000, "5000/tcp", "")
//	"0.0.0.0:5000:5000"  → (5000, "5000", "0.0.0.0")
//	"8080:80"             → (8080, "80", "")
func parseShortPort(s string) (hostPort int, containerPort string, bindIP string) {
	// Strip protocol suffix for parsing, re-add to containerPort
	proto := ""
	if idx := strings.LastIndex(s, "/"); idx > 0 {
		proto = s[idx:]
		s = s[:idx]
	}

	parts := strings.Split(s, ":")
	switch len(parts) {
	case 3:
		// bindIP:hostPort:containerPort
		bindIP = parts[0]
		fmt.Sscanf(parts[1], "%d", &hostPort)
		containerPort = parts[2] + proto
	case 2:
		// hostPort:containerPort
		fmt.Sscanf(parts[0], "%d", &hostPort)
		containerPort = parts[1] + proto
	case 1:
		// Just containerPort (no host mapping)
		containerPort = parts[0] + proto
	}
	return
}

// toInt converts an interface{} to int (handles int, float64, string).
func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		var i int
		fmt.Sscanf(n, "%d", &i)
		return i
	}
	return 0
}

// fileExists returns true if the path exists and is accessible.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// prettifySubdomain strips common CasaOS store prefixes from app names
// to produce clean, user-friendly FQDNs.
//
// Examples:
//
//	"big-bear-libretranslate", "big-bear"     → "libretranslate"
//	"big-bear-ghostfolio", "big-bear"         → "ghostfolio"
//	"linuxserver-plex", "linuxserver"         → "plex"
//	"nextcloud", "casaos-official"            → "nextcloud"
//	"big-bear-npm", "big-bear"               → "npm"
func prettifySubdomain(appName, storeID string) string {
	// Known store prefixes to strip (order: longest first)
	knownPrefixes := []string{
		"big-bear-",
		"linuxserver-",
	}

	// Also try the store ID as a prefix (handles future stores dynamically)
	if storeID != "" && !strings.Contains(storeID, "official") {
		storePrefix := storeID + "-"
		// Add to front so it's tried first
		knownPrefixes = append([]string{storePrefix}, knownPrefixes...)
	}

	// Deduplicate (store ID might match a known prefix)
	seen := make(map[string]bool)
	var prefixes []string
	for _, p := range knownPrefixes {
		if !seen[p] {
			seen[p] = true
			prefixes = append(prefixes, p)
		}
	}

	result := appName
	for _, prefix := range prefixes {
		if strings.HasPrefix(appName, prefix) {
			stripped := strings.TrimPrefix(appName, prefix)
			// Don't strip if it leaves an empty string or a single character
			if len(stripped) > 1 {
				result = stripped
				break
			}
		}
	}

	return result
}

// preCreateBindMounts parses a compose YAML and creates all bind mount host
// directories. Docker Swarm does NOT auto-create bind mount source paths
// (unlike docker compose), so containers get "bind source path does not exist"
// rejections without this step.
func preCreateBindMounts(manifest string) {
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &compose); err != nil {
		return
	}
	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return
	}

	for _, svcDef := range services {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}
		volumes, ok := svc["volumes"].([]interface{})
		if !ok {
			continue
		}
		for _, v := range volumes {
			var hostPath string
			switch vol := v.(type) {
			case string:
				// Short form: "/host/path:/container/path" or "/host/path:/container/path:ro"
				parts := strings.SplitN(vol, ":", 3)
				if len(parts) >= 2 && strings.HasPrefix(parts[0], "/") {
					hostPath = parts[0]
				}
			case map[string]interface{}:
				// Long form: {type: bind, source: /host/path, target: /container/path}
				if t, _ := vol["type"].(string); t == "bind" || t == "" {
					if src, ok := vol["source"].(string); ok && strings.HasPrefix(src, "/") {
						hostPath = src
					}
				}
			}
			if hostPath != "" {
				// Use 0777 because containers may run as non-root users
				// (e.g. libretranslate runs as uid 1032). The container's
				// entrypoint can tighten permissions as needed.
				// Note: os.MkdirAll respects umask, so we must chmod explicitly.
				if err := os.MkdirAll(hostPath, 0777); err != nil {
					log.Warn().Err(err).Str("path", hostPath).Msg("failed to pre-create bind mount directory")
				} else {
					os.Chmod(hostPath, 0777)
					log.Debug().Str("path", hostPath).Msg("pre-created bind mount directory for Swarm")
				}
			}
		}
	}
}

// swarmStackExists returns true if a Docker Swarm stack with the given name
// has any services (running or otherwise).
func swarmStackExists(stackName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "stack", "services", stackName, "--format", "{{.ID}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) != ""
}

// sanitizeForSwarm transforms a CasaOS docker-compose.yml into a format compatible
// with `docker stack deploy`. This is a comprehensive, single-pass sanitizer based on
// the full CasaOS manifest specification and Docker Swarm's compose file restrictions.
//
// CasaOS manifests target single-node Docker with direct hardware access. Swarm abstracts
// away host-level resources, so many directives must be stripped or converted.
//
// Transformation categories:
//
//	ROOT LEVEL:    Strip name, x-casaos, all x-* extensions, version
//	SERVICE LEVEL: Strip 15+ unsupported directives, convert restart/cpu_shares/network_mode
//	NETWORK LEVEL: Convert all drivers to overlay, strip driver_opts and explicit names
//	VOLUME LEVEL:  Strip bind.create_host_path and other unsupported options
//
// Returns the sanitized YAML string and any error. On parse failure, returns the original
// manifest unchanged so existing working apps aren't broken.
func sanitizeForSwarm(manifest string) (string, error) {
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &compose); err != nil {
		return "", fmt.Errorf("failed to parse compose YAML: %w", err)
	}

	var warnings []string

	// =========================================================================
	// PHASE 1: Root-level cleanup
	// =========================================================================

	// Strip root "name:" — stack name comes from CLI argument, not the file.
	// CasaOS uses this as the project name and store_app_id.
	if _, exists := compose["name"]; exists {
		delete(compose, "name")
	}

	// Strip "version:" — deprecated in modern compose, can cause warnings
	if _, exists := compose["version"]; exists {
		delete(compose, "version")
	}

	// Strip all x-* extensions at root level (x-casaos metadata, etc.)
	for key := range compose {
		if strings.HasPrefix(key, "x-") {
			delete(compose, key)
		}
	}

	// =========================================================================
	// PHASE 2: Service-level transformations
	// =========================================================================

	services, ok := compose["services"]
	if !ok {
		return manifest, nil
	}
	svcMap, ok := services.(map[string]interface{})
	if !ok {
		return manifest, nil
	}

	// Directives to strip entirely — no Swarm equivalent exists.
	// Grouped by reason:
	stripDirectives := []string{
		// Container identity (Swarm auto-names as stack_service_slot)
		"container_name",
		// Hardware passthrough (no Swarm equivalent)
		"privileged",
		"devices",
		// Security options (silently ignored but can cause parse issues)
		"security_opt",
		"userns_mode",
		"cgroup_parent",
		// Build context (Swarm deploys pre-built images only)
		"build",
		// Legacy networking (replaced by Swarm overlay)
		"links",
		"external_links",
		// Inheritance (actively rejected by stack deploy)
		"extends",
		// Process namespace sharing (not supported in Swarm services)
		"pid",
		"ipc",
		// TTY/stdin (not supported in Swarm services)
		"stdin_open",
		"tty",
		// Platform hint (can conflict with --resolve-image=never)
		"platform",
	}

	for svcName, svcDef := range svcMap {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}

		// --- Strip unsupported directives ---
		for _, key := range stripDirectives {
			if val, exists := svc[key]; exists {
				delete(svc, key)
				// Track critical removals that affect app functionality
				switch key {
				case "privileged":
					if b, ok := val.(bool); ok && b {
						warnings = append(warnings, fmt.Sprintf(
							"service '%s': removed privileged mode — app may not function correctly", svcName))
					}
				case "devices":
					warnings = append(warnings, fmt.Sprintf(
						"service '%s': removed devices passthrough — hardware features unavailable", svcName))
				}
			}
		}

		// --- Strip all x-* extensions at service level ---
		for key := range svc {
			if strings.HasPrefix(key, "x-") {
				delete(svc, key)
			}
		}

		// --- Convert depends_on map → list ---
		// CasaOS uses: depends_on: {postgres: {condition: service_healthy}}
		// Swarm requires: depends_on: [postgres]   (or strip entirely)
		// Swarm ignores depends_on for scheduling anyway, but map form causes parse error.
		if deps, exists := svc["depends_on"]; exists {
			switch d := deps.(type) {
			case map[string]interface{}:
				depList := make([]string, 0, len(d))
				for depName := range d {
					depList = append(depList, depName)
				}
				sort.Strings(depList)
				svc["depends_on"] = depList
			case []interface{}:
				// Already a list — keep as-is
			default:
				delete(svc, "depends_on")
			}
		}

		// --- Convert restart: → deploy.restart_policy ---
		// Swarm ignores compose-level "restart:" and logs "Ignoring unsupported options".
		// Convert to the Swarm-native deploy.restart_policy so behavior is preserved.
		if restart, exists := svc["restart"]; exists {
			restartStr, _ := restart.(string)
			deploy := getOrCreateMap(svc, "deploy")
			if _, hasPolicy := deploy["restart_policy"]; !hasPolicy && restartStr != "" {
				condition := "any"
				switch restartStr {
				case "no":
					condition = "none"
				case "on-failure":
					condition = "on-failure"
				case "always", "unless-stopped":
					condition = "any"
				}
				deploy["restart_policy"] = map[string]interface{}{
					"condition": condition,
				}
			}
			delete(svc, "restart")
		}

		// --- Convert network_mode ---
		// Swarm does not support network_mode: host/bridge/container:X
		if nm, exists := svc["network_mode"]; exists {
			if nmStr, ok := nm.(string); ok {
				switch {
				case nmStr == "host":
					warnings = append(warnings, fmt.Sprintf(
						"service '%s': removed network_mode:host — mDNS/DHCP/discovery may not work", svcName))
					delete(svc, "network_mode")
				case nmStr == "bridge":
					delete(svc, "network_mode")
				case strings.HasPrefix(nmStr, "container:"):
					warnings = append(warnings, fmt.Sprintf(
						"service '%s': removed network_mode:%s — container networking not supported in Swarm", svcName, nmStr))
					delete(svc, "network_mode")
				case strings.HasPrefix(nmStr, "service:"):
					warnings = append(warnings, fmt.Sprintf(
						"service '%s': removed network_mode:%s — service networking not supported in Swarm", svcName, nmStr))
					delete(svc, "network_mode")
				default:
					delete(svc, "network_mode")
				}
			}
		}

		// --- Convert cpu_shares → deploy.resources.limits.cpus ---
		// CasaOS commonly sets cpu_shares: 90 (relative weight, default 1024)
		// Convert to approximate CPU limit fraction
		if cpuShares, exists := svc["cpu_shares"]; exists {
			if shares, ok := toFloat64(cpuShares); ok && shares > 0 {
				deploy := getOrCreateMap(svc, "deploy")
				resources := getOrCreateMap(deploy, "resources")
				limits := getOrCreateMap(resources, "limits")
				if _, hasCPU := limits["cpus"]; !hasCPU {
					// cpu_shares is relative to 1024 default; convert to fractional CPUs
					cpuFraction := shares / 1024.0
					if cpuFraction < 0.1 {
						cpuFraction = 0.1
					}
					limits["cpus"] = fmt.Sprintf("%.2f", cpuFraction)
				}
			}
			delete(svc, "cpu_shares")
		}

		// --- Convert mem_limit → deploy.resources.limits.memory ---
		if memLimit, exists := svc["mem_limit"]; exists {
			deploy := getOrCreateMap(svc, "deploy")
			resources := getOrCreateMap(deploy, "resources")
			limits := getOrCreateMap(resources, "limits")
			if _, hasMem := limits["memory"]; !hasMem {
				limits["memory"] = memLimit
			}
			delete(svc, "mem_limit")
		}
		// Also handle memswap_limit and mem_reservation
		delete(svc, "memswap_limit")
		if memRes, exists := svc["mem_reservation"]; exists {
			deploy := getOrCreateMap(svc, "deploy")
			resources := getOrCreateMap(deploy, "resources")
			reservations := getOrCreateMap(resources, "reservations")
			if _, hasMem := reservations["memory"]; !hasMem {
				reservations["memory"] = memRes
			}
			delete(svc, "mem_reservation")
		}

		// --- Convert shm_size → tmpfs mount on /dev/shm ---
		if shmSize, exists := svc["shm_size"]; exists {
			// Add a tmpfs mount for /dev/shm with the specified size
			if sizeStr, ok := shmSize.(string); ok && sizeStr != "" {
				tmpfsEntry := map[string]interface{}{
					"type":   "tmpfs",
					"target": "/dev/shm",
					"tmpfs": map[string]interface{}{
						"size": parseShmSize(sizeStr),
					},
				}
				if existingVolumes, ok := svc["volumes"].([]interface{}); ok {
					svc["volumes"] = append(existingVolumes, tmpfsEntry)
				}
			}
			delete(svc, "shm_size")
		}

		// --- Clean up volume bind options not supported by stack deploy ---
		if volumes, ok := svc["volumes"].([]interface{}); ok {
			for i, vol := range volumes {
				if volMap, ok := vol.(map[string]interface{}); ok {
					// Remove bind.create_host_path (not supported in stack deploy)
					if bind, ok := volMap["bind"].(map[string]interface{}); ok {
						delete(bind, "create_host_path")
						if len(bind) == 0 {
							delete(volMap, "bind")
						}
					}
					volumes[i] = volMap
				}
			}
		}

		// --- Strip cap_add/cap_drop ---
		// Supported in Docker 20.10+ Swarm but unreliable on older versions.
		// For maximum compatibility, strip them. Apps that truly need NET_ADMIN
		// (Pi-hole, VPN) should be deployed via Docker Compose, not Swarm.
		if _, exists := svc["cap_add"]; exists {
			warnings = append(warnings, fmt.Sprintf(
				"service '%s': removed cap_add — elevated capabilities not supported in Swarm stacks", svcName))
			delete(svc, "cap_add")
		}
		delete(svc, "cap_drop")

		// --- Ensure deploy section has task history limit for ARM64 memory ---
		deploy := getOrCreateMap(svc, "deploy")
		if _, exists := deploy["replicas"]; !exists {
			deploy["replicas"] = 1
		}
	}

	// =========================================================================
	// PHASE 3: Network-level transformations
	// =========================================================================

	// Swarm requires all service networks to use the overlay driver.
	// CasaOS manifests typically define bridge networks or leave driver unset (defaults to bridge).
	if networks, ok := compose["networks"]; ok {
		if netMap, ok := networks.(map[string]interface{}); ok {
			for netName, netDef := range netMap {
				switch nd := netDef.(type) {
				case map[string]interface{}:
					nd["driver"] = "overlay"
					// Remove bridge-specific driver_opts
					delete(nd, "driver_opts")
					// Remove explicit name (Swarm auto-prefixes with stack name)
					delete(nd, "name")
					// Remove enable_ipv6 (not always supported in overlay)
					delete(nd, "enable_ipv6")
					// Remove IPAM config if bridge-specific
					if ipam, ok := nd["ipam"].(map[string]interface{}); ok {
						if driver, ok := ipam["driver"].(string); ok && driver == "default" {
							delete(nd, "ipam")
						}
					}
				case nil:
					// Bare network definition: "mynet:" with no config
					netMap[netName] = map[string]interface{}{
						"driver": "overlay",
					}
				}
			}
		}
	}

	// =========================================================================
	// PHASE 4: Volume-level cleanup
	// =========================================================================

	// Strip unsupported options from top-level volume definitions
	if volumes, ok := compose["volumes"]; ok {
		if volMap, ok := volumes.(map[string]interface{}); ok {
			for _, volDef := range volMap {
				if vd, ok := volDef.(map[string]interface{}); ok {
					// Remove bind-specific options at top level
					delete(vd, "bind")
				}
			}
		}
	}

	// =========================================================================
	// PHASE 5: Log warnings
	// =========================================================================

	if len(warnings) > 0 {
		for _, w := range warnings {
			log.Warn().Str("context", "swarm-sanitizer").Msg(w)
		}
	}

	out, err := yaml.Marshal(compose)
	if err != nil {
		return "", fmt.Errorf("failed to serialize sanitized compose: %w", err)
	}
	return string(out), nil
}

// getOrCreateMap retrieves a nested map by key, creating it if absent.
// Ensures the parent map always contains the key pointing to a map[string]interface{}.
func getOrCreateMap(parent map[string]interface{}, key string) map[string]interface{} {
	if existing, ok := parent[key].(map[string]interface{}); ok {
		return existing
	}
	m := make(map[string]interface{})
	parent[key] = m
	return m
}

// toFloat64 converts an interface{} (int, float64, string) to float64.
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case string:
		var f float64
		_, err := fmt.Sscanf(n, "%f", &f)
		return f, err == nil
	}
	return 0, false
}

// parseShmSize converts a human-readable size string (e.g. "64mb", "1g") to bytes.
func parseShmSize(size string) int64 {
	size = strings.TrimSpace(strings.ToLower(size))
	multiplier := int64(1)
	if strings.HasSuffix(size, "g") || strings.HasSuffix(size, "gb") {
		multiplier = 1024 * 1024 * 1024
		size = strings.TrimRight(size, "gb")
	} else if strings.HasSuffix(size, "m") || strings.HasSuffix(size, "mb") {
		multiplier = 1024 * 1024
		size = strings.TrimRight(size, "mb")
	} else if strings.HasSuffix(size, "k") || strings.HasSuffix(size, "kb") {
		multiplier = 1024
		size = strings.TrimRight(size, "kb")
	}
	var val float64
	fmt.Sscanf(size, "%f", &val)
	if val <= 0 {
		return 64 * 1024 * 1024 // default 64MB
	}
	return int64(val) * multiplier
}

// GetInstalledApps returns all installed apps
func (m *AppStoreManager) GetInstalledApps() []*models.InstalledApp {
	m.mu.RLock()
	apps := make([]*models.InstalledApp, 0, len(m.installed))
	for _, app := range m.installed {
		apps = append(apps, app)
	}
	m.mu.RUnlock()

	// Refresh status outside the lock — refreshAppStatus spawns Docker CLI
	// commands with 5s timeouts, which would starve writers if held under RLock
	for _, app := range apps {
		m.refreshAppStatus(app)
	}

	// Filter out apps that were auto-removed during reconciliation
	live := make([]*models.InstalledApp, 0, len(apps))
	for _, app := range apps {
		if app.Status != "removed" {
			live = append(live, app)
		}
	}

	sort.Slice(live, func(i, j int) bool {
		return live[i].Name < live[j].Name
	})

	return live
}

// GetInstalledApp returns a specific installed app
func (m *AppStoreManager) GetInstalledApp(appID string) *models.InstalledApp {
	m.mu.RLock()
	app := m.installed[appID]
	m.mu.RUnlock()

	if app != nil {
		m.refreshAppStatus(app)
		if app.Status == "removed" {
			return nil
		}
	}
	return app
}

// UpdateWebUIType changes the webui_type for an installed app.
// Valid values: "browser" (open in new tab) or "api" (show status modal).
func (m *AppStoreManager) UpdateWebUIType(appID string, webuiType string) error {
	if webuiType != "browser" && webuiType != "api" {
		return fmt.Errorf("invalid webui_type: %q (must be 'browser' or 'api')", webuiType)
	}

	app := m.GetInstalledApp(appID)
	if app == nil {
		return fmt.Errorf("app not found: %s", appID)
	}

	_, err := m.db.db.Exec("UPDATE apps SET webui_type = ?, updated_at = ? WHERE name = ?",
		webuiType, time.Now().Format(time.RFC3339), appID)
	if err != nil {
		return fmt.Errorf("failed to update webui_type: %w", err)
	}

	// Update in-memory state
	m.mu.Lock()
	if installed, ok := m.installed[appID]; ok {
		installed.WebUIType = webuiType
	}
	m.mu.Unlock()

	log.Info().Str("app", appID).Str("webui_type", webuiType).Msg("updated webui_type")
	return nil
}

func (m *AppStoreManager) refreshAppStatus(app *models.InstalledApp) {
	// Runtime reconciliation: if both compose file and stack are gone,
	// auto-remove the ghost record so the UI stays consistent.
	if app.ComposeFile != "" && !fileExists(app.ComposeFile) && !swarmStackExists(app.ID) {
		log.Warn().Str("app", app.ID).Msg("app compose and stack both missing at runtime — removing ghost record")
		m.mu.Lock()
		delete(m.installed, app.ID)
		// Clear the "Installed" flag on the catalog entry so the UI updates
		if app.StoreAppID != "" {
			if storeApp, ok := m.catalog[app.StoreAppID]; ok {
				storeApp.Installed = false
			}
		}
		m.mu.Unlock()
		m.db.db.Exec("DELETE FROM apps WHERE name = ?", app.ID)
		app.Status = "removed"
		return
	}

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
		if m.npm != nil && m.npm.IsAuthenticated() {
			if err := m.npm.DeleteProxyHost(npmProxyID); err != nil {
				log.Warn().Err(err).Int("proxyID", npmProxyID).Msg("failed to remove NPM proxy")
			}
		}
	}

	// Remove DNS entry via PiholeManager — use FQDN from database (may be prettified)
	var storedFQDN string
	var storeID string
	m.db.db.QueryRow(`SELECT f.fqdn FROM fqdns f
		JOIN apps a ON a.id = f.app_id WHERE a.name = ? LIMIT 1`, appID).Scan(&storedFQDN)
	if storedFQDN == "" {
		// Fallback: try prettified subdomain first (matches install behavior), then raw appID
		m.db.db.QueryRow(`SELECT store_id FROM apps WHERE name = ?`, appID).Scan(&storeID)
		prettified := prettifySubdomain(appID, storeID)
		fqdnsToTry := []string{
			fmt.Sprintf("%s.%s", prettified, m.baseDomain),
		}
		if prettified != appID {
			fqdnsToTry = append(fqdnsToTry, fmt.Sprintf("%s.%s", appID, m.baseDomain))
		}
		for _, fqdn := range fqdnsToTry {
			if err := m.removePiholeDNS(fqdn); err == nil {
				log.Info().Str("fqdn", fqdn).Msg("removed DNS entry via fallback")
			}
		}
	} else {
		if err := m.removePiholeDNS(storedFQDN); err != nil {
			log.Warn().Err(err).Str("fqdn", storedFQDN).Msg("failed to remove DNS entry")
		}
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
		// Clean up parent directory if empty (no appdata existed)
		if entries, err := os.ReadDir(appBaseDir); err == nil && len(entries) == 0 {
			os.Remove(appBaseDir)
		}
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
// NPM Types (shared with npm.go)
// ============================================================================

// NPMTokenResponse from /api/tokens — used by NPMManager.authenticate()
type NPMTokenResponse struct {
	Token   string `json:"token"`
	Expires string `json:"expires"`
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
