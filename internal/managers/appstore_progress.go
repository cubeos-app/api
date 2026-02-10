package managers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// InstallAppWithProgress runs the install pipeline while emitting SSE progress events.
// The caller is responsible for running this in a goroutine and closing job.Events.
func (m *AppStoreManager) InstallAppWithProgress(req *models.AppInstallRequest, job *Job) (*models.InstalledApp, error) {
	job.SetStatus(JobRunning)

	// Step 1: Validate (5%)
	job.Emit("validate", 5, "Validating app manifest...")
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

	// Step 2: Read manifest (10%)
	job.Emit("manifest", 10, "Reading configuration...")
	manifestData, err := os.ReadFile(storeApp.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// Step 3: Create directories (15%)
	job.Emit("directories", 15, "Creating app directories...")
	appBase := filepath.Join(m.appsPath, req.AppName)
	appConfig := filepath.Join(appBase, "appconfig")
	appData := filepath.Join(appBase, "appdata")
	os.MkdirAll(appConfig, 0755)
	os.MkdirAll(appData, 0777)
	os.Chmod(appData, 0777)

	// Step 4: Process manifest & allocate port (20-25%)
	job.Emit("compose", 20, "Preparing Docker configuration...")
	allocatedPort := m.findAvailablePort(6100)
	processedManifest := m.processManifest(string(manifestData), req.AppName, appData, req)

	job.Emit("port", 25, fmt.Sprintf("Allocated port %d", allocatedPort))
	processedManifest, err = remapPorts(processedManifest, allocatedPort, storeApp.PortMap)
	if err != nil {
		log.Warn().Err(err).Str("app", req.AppName).Msg("port remapping failed, using original ports")
	}

	// Step 4.5: Remap external volumes to safe defaults (27%)
	job.Emit("volumes", 27, "Configuring volume mounts...")
	var remapResults []RemapResult
	overrides := req.VolumeOverrides
	if overrides == nil {
		overrides = make(map[string]string)
	}
	processedManifest, remapResults, err = RemapExternalVolumes(processedManifest, req.AppName, appData, overrides)
	if err != nil {
		log.Warn().Err(err).Str("app", req.AppName).Msg("volume remapping failed, using original paths")
	} else if len(remapResults) > 0 {
		remapped := 0
		for _, r := range remapResults {
			if r.WasRemapped {
				remapped++
			}
		}
		if remapped > 0 {
			job.Emit("volumes", 28, fmt.Sprintf("Remapped %d external volume(s) to safe defaults", remapped))
		}
	}

	// Write docker-compose.yml
	composePath := filepath.Join(appConfig, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(processedManifest), 0644); err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to write compose file: %w", err)
	}

	// Pre-create bind mount dirs
	preCreateBindMounts(processedManifest)

	// Step 5: Deploy stack (30% → 60%)
	job.Emit("deploy", 30, "Deploying containers (pulling images)...")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	deployCmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
		"-c", composePath,
		"--resolve-image=never",
		req.AppName,
	)
	deployCmd.Dir = appConfig
	if output, err := deployCmd.CombinedOutput(); err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("stack deploy failed: %s", string(output))
	}

	// Step 6: Wait for services (60% → 75%)
	job.Emit("services", 60, "Waiting for services to start...")
	m.waitForSwarmServices(req.AppName, job)

	// Step 7: Configure DNS (80%)
	subdomain := prettifySubdomain(req.AppName, req.StoreID)
	appFQDN := fmt.Sprintf("%s.%s", subdomain, m.baseDomain)
	job.Emit("dns", 80, fmt.Sprintf("Configuring DNS: %s", appFQDN))

	if m.pihole != nil {
		if existing, _ := m.pihole.GetEntry(appFQDN); existing != nil {
			log.Warn().Str("fqdn", appFQDN).Msg("FQDN collision, using full app name")
			appFQDN = fmt.Sprintf("%s.%s", req.AppName, m.baseDomain)
		}
	}

	if m.pihole != nil {
		if err := m.pihole.AddEntry(appFQDN, m.gatewayIP); err != nil {
			log.Warn().Err(err).Str("fqdn", appFQDN).Msg("failed to add DNS entry")
		}
	}

	// Step 8: Configure proxy (85%)
	job.Emit("proxy", 85, "Setting up reverse proxy...")
	appPort := allocatedPort
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
	}

	// Step 9: Save to database (90%)
	job.Emit("database", 90, "Saving app configuration...")

	// Build WebUI URL
	webUI := ""
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

	title := req.Title
	if title == "" {
		title = storeApp.Title["en_us"]
		if title == "" {
			title = storeApp.Name
		}
	}

	if appFQDN != "" && webUI != "" {
		webUI = fmt.Sprintf("http://%s", appFQDN)
	}

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

	// Store FQDN in fqdns table
	if appFQDN != "" {
		fqdnSubdomain := strings.TrimSuffix(appFQDN, "."+m.baseDomain)
		var appID int64
		if err := m.db.db.QueryRow("SELECT id FROM apps WHERE name = ?", installed.Name).Scan(&appID); err != nil {
			log.Error().Err(err).Str("app", installed.Name).Msg("failed to find app_id for FQDN insert")
		} else {
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
	}

	// Store volume mappings (after DB insert so app_id exists)
	if len(remapResults) > 0 {
		m.StoreVolumeMappings(req.AppName, remapResults)
	}

	// Step 10: Health check (95%)
	job.Emit("health_check", 95, fmt.Sprintf("Verifying %s is accessible...", appFQDN))
	if appFQDN != "" {
		if err := m.healthCheckFQDN(appFQDN, 30*time.Second); err != nil {
			log.Warn().Err(err).Str("fqdn", appFQDN).Msg("health check failed (non-fatal)")
			// Non-fatal: app may take longer to start, polling will pick it up
		}
	}

	// Auto-detect web UI type (browser vs API) via Content-Type sniffing
	webuiType := detectWebUIType(webUI)
	installed.WebUIType = webuiType
	if webuiType != "browser" {
		log.Info().Str("app", req.AppName).Str("type", webuiType).Str("url", webUI).
			Msg("detected non-browser web UI type")
	}
	// Persist to DB
	m.db.db.Exec("UPDATE apps SET webui_type = ? WHERE name = ?", webuiType, installed.Name)

	// Update in-memory state
	m.mu.Lock()
	m.installed[installed.ID] = installed
	if app, ok := m.catalog[storeApp.ID]; ok {
		app.Installed = true
	}
	m.mu.Unlock()

	return installed, nil
}

// RemoveAppWithProgress runs the uninstall pipeline while emitting SSE progress events.
func (m *AppStoreManager) RemoveAppWithProgress(appID string, deleteData bool, job *Job) error {
	job.SetStatus(JobRunning)

	// Step 1: Validate (5%)
	job.Emit("validate", 5, "Validating app...")
	app := m.GetInstalledApp(appID)
	if app == nil {
		return fmt.Errorf("app not found: %s", appID)
	}

	// Step 2: Stop services / remove stack (15% → 40%)
	job.Emit("stop", 15, "Stopping services...")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if m.getDeployMode(appID) == "stack" {
		job.Emit("remove_stack", 25, "Removing Docker stack...")
		cmd := exec.CommandContext(ctx, "docker", "stack", "rm", appID)
		cmd.CombinedOutput() // Best-effort
	} else {
		job.Emit("remove_stack", 25, "Removing containers...")
		cmd := exec.CommandContext(ctx, "docker", "compose", "-f", app.ComposeFile, "down", "--rmi", "all", "-v")
		cmd.CombinedOutput()
	}

	// Step 3: Remove DNS (55%)
	job.Emit("remove_dns", 55, "Removing DNS entry...")

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

	// Step 4: Remove proxy (65%)
	job.Emit("remove_proxy", 65, "Removing reverse proxy...")

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

	// Step 5: Cleanup files (80%)
	job.Emit("cleanup", 80, "Cleaning up files...")

	appConfigDir := filepath.Dir(app.ComposeFile)
	appBaseDir := filepath.Dir(appConfigDir)

	if deleteData {
		os.RemoveAll(appBaseDir)
	} else {
		os.RemoveAll(appConfigDir)
		if entries, err := os.ReadDir(appBaseDir); err == nil && len(entries) == 0 {
			os.Remove(appBaseDir)
		}
	}

	// Step 6: Remove from database (90%)
	job.Emit("database", 90, "Removing configuration...")

	m.db.db.Exec(`DELETE FROM apps WHERE name = ? AND source = 'casaos'`, appID)

	// Update in-memory state
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

// waitForSwarmServices polls docker service ls until services for the stack are running.
// Emits per-service progress between 60-75%.
func (m *AppStoreManager) waitForSwarmServices(stackName string, job *Job) {
	deadline := time.Now().Add(90 * time.Second)
	attempt := 0

	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		attempt++

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "stack", "services",
			"--format", "{{.Name}}\t{{.Replicas}}", stackName).CombinedOutput()
		cancel()

		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		total := 0
		ready := 0
		for _, line := range lines {
			parts := strings.Split(line, "\t")
			if len(parts) < 2 {
				continue
			}
			total++
			// Replicas format: "1/1" or "0/1"
			replicas := parts[1]
			replicaParts := strings.Split(replicas, "/")
			if len(replicaParts) == 2 && replicaParts[0] == replicaParts[1] && replicaParts[0] != "0" {
				ready++
			}
		}

		if total > 0 {
			// Map ready/total to progress 60-75
			pct := 60 + int(float64(ready)/float64(total)*15)
			detail := fmt.Sprintf("Starting services (%d/%d ready)", ready, total)
			job.Emit("services", pct, detail)

			if ready >= total {
				return
			}

			// After 30 seconds of 0/N, surface the actual Docker error
			if attempt > 10 && ready == 0 {
				errMsg := m.getServiceTaskError(stackName)
				if errMsg != "" {
					job.Emit("services", pct, fmt.Sprintf("Warning: %s", errMsg))
				}
			}
		}
	}

	log.Warn().Str("stack", stackName).Msg("service readiness poll timed out (non-fatal)")
}

// healthCheckFQDN does an HTTP GET to the FQDN, retrying until success or timeout.
func (m *AppStoreManager) healthCheckFQDN(fqdn string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("http://%s", fqdn))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil // Any non-5xx is "up"
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("health check timed out for %s", fqdn)
}

// detectWebUIType does a HEAD request to the app's web UI URL and checks
// Content-Type to determine if it's a browser-friendly page or an API endpoint.
// Returns "browser" (text/html) or "api" (application/json, etc.).
// Defaults to "browser" on any error or ambiguous response.
func detectWebUIType(webUIURL string) string {
	if webUIURL == "" {
		return "browser"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Try HEAD first (fastest)
	resp, err := client.Head(webUIURL)
	if err != nil {
		log.Debug().Err(err).Str("url", webUIURL).Msg("HEAD failed for webui detection, defaulting to browser")
		return "browser"
	}
	resp.Body.Close()

	ct := strings.ToLower(resp.Header.Get("Content-Type"))

	// Some servers don't return Content-Type on HEAD, fall back to GET
	if ct == "" {
		resp, err = client.Get(webUIURL)
		if err != nil {
			return "browser"
		}
		resp.Body.Close()
		ct = strings.ToLower(resp.Header.Get("Content-Type"))
	}

	if strings.Contains(ct, "text/html") || strings.Contains(ct, "text/xhtml") {
		return "browser"
	}
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "text/plain") || strings.Contains(ct, "application/xml") {
		return "api"
	}

	// Default: assume browser-friendly
	return "browser"
}
