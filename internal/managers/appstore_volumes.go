package managers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// VolumeMapping represents a single bind mount mapping for an app.
type VolumeMapping struct {
	ID               int64  `json:"id,omitempty"`
	AppID            int64  `json:"app_id,omitempty"`
	ServiceName      string `json:"service_name"`
	ContainerPath    string `json:"container_path"`     // mount target inside container
	OriginalHostPath string `json:"original_host_path"` // path from manifest
	CurrentHostPath  string `json:"current_host_path"`  // actual path on host
	Description      string `json:"description"`        // human-readable label
	IsRemapped       bool   `json:"is_remapped"`        // TRUE if we changed it from original
	IsExternal       bool   `json:"is_external"`        // true if NOT under /cubeos/apps/
	IsConfig         bool   `json:"is_config"`          // true if config-like mount (/config, /data, /etc)
	ReadOnly         bool   `json:"read_only"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// RemapResult records what happened to a single volume during remapping.
type RemapResult struct {
	ServiceName   string `json:"service_name"`
	Original      string `json:"original"`       // /DATA/Media/Movies
	Remapped      string `json:"remapped"`       // /cubeos/apps/bazarr/appdata/movies
	ContainerPath string `json:"container_path"` // /movies
	WasRemapped   bool   `json:"was_remapped"`
	IsConfig      bool   `json:"is_config"`
	ReadOnly      bool   `json:"read_only"`
	Description   string `json:"description"`
}

// VolumeMappingUpdate represents a user request to change a volume path.
type VolumeMappingUpdate struct {
	ContainerPath string `json:"container_path"` // identifies which mapping
	NewHostPath   string `json:"new_host_path"`  // new host path
}

// VolumeMappingsResponse is returned by the GET volumes endpoint.
type VolumeMappingsResponse struct {
	AppID   string          `json:"app_id"`
	AppName string          `json:"app_name"`
	Volumes []VolumeMapping `json:"volumes"`
}

// VolumePreviewResponse is returned by the preview endpoint.
type VolumePreviewResponse struct {
	AppName string          `json:"app_name"`
	Volumes []VolumeMapping `json:"volumes"`
}

// configPatterns are container paths that indicate internal/config volumes.
// These should generally not be offered for user remapping.
var configPatterns = []string{
	"/config",
	"/data",
	"/etc",
	"/app/data",
	"/app/config",
	"/opt/data",
}

// restrictedPaths that users cannot select for volume mounts.
var restrictedPaths = []string{
	"/",
	"/boot",
	"/proc",
	"/sys",
	"/dev",
	"/run",
	"/tmp",
	"/cubeos/coreapps",
}

// ExtractBindMounts parses a compose YAML and returns all bind mount volumes
// with metadata about whether they're external/config/etc.
func ExtractBindMounts(composeYAML string) ([]VolumeMapping, error) {
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(composeYAML), &compose); err != nil {
		return nil, fmt.Errorf("failed to parse compose YAML: %w", err)
	}

	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return nil, nil // no services = no volumes
	}

	var mappings []VolumeMapping

	for svcName, svcDef := range services {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}

		volumes, ok := svc["volumes"].([]interface{})
		if !ok {
			continue
		}

		for _, v := range volumes {
			m := parseVolume(v, svcName)
			if m == nil {
				continue
			}
			mappings = append(mappings, *m)
		}
	}

	// Sort: external first, then internal; within each group, alphabetical by container path
	sort.Slice(mappings, func(i, j int) bool {
		if mappings[i].IsExternal != mappings[j].IsExternal {
			return mappings[i].IsExternal
		}
		return mappings[i].ContainerPath < mappings[j].ContainerPath
	})

	return mappings, nil
}

// parseVolume extracts a VolumeMapping from a single compose volume entry.
// Returns nil if the entry is not a bind mount or has no host path.
func parseVolume(v interface{}, svcName string) *VolumeMapping {
	var hostPath, containerPath string
	var readOnly bool

	switch vol := v.(type) {
	case string:
		// Short form: "/host/path:/container/path" or "/host/path:/container/path:ro"
		parts := strings.SplitN(vol, ":", 3)
		if len(parts) < 2 || !strings.HasPrefix(parts[0], "/") {
			return nil
		}
		hostPath = parts[0]
		containerPath = parts[1]
		if len(parts) == 3 {
			readOnly = strings.Contains(parts[2], "ro")
		}

	case map[string]interface{}:
		// Long form: {type: bind, source: /host/path, target: /container/path}
		volType, _ := vol["type"].(string)
		if volType != "" && volType != "bind" {
			return nil // named volume or tmpfs, skip
		}
		src, ok := vol["source"].(string)
		if !ok || !strings.HasPrefix(src, "/") {
			return nil
		}
		hostPath = src
		containerPath, _ = vol["target"].(string)
		if containerPath == "" {
			return nil
		}
		ro, _ := vol["read_only"].(bool)
		readOnly = ro

	default:
		return nil
	}

	isExternal := !strings.HasPrefix(hostPath, "/cubeos/apps/")
	isConfig := isConfigPath(containerPath)
	desc := descriptionFromPath(containerPath)

	return &VolumeMapping{
		ServiceName:      svcName,
		ContainerPath:    containerPath,
		OriginalHostPath: hostPath,
		CurrentHostPath:  hostPath,
		Description:      desc,
		IsRemapped:       false,
		IsExternal:       isExternal,
		IsConfig:         isConfig,
		ReadOnly:         readOnly,
	}
}

// isConfigPath returns true if the container path looks like an internal config mount.
func isConfigPath(containerPath string) bool {
	lower := strings.ToLower(containerPath)
	for _, pattern := range configPatterns {
		if lower == pattern || strings.HasPrefix(lower, pattern+"/") {
			return true
		}
	}
	return false
}

// descriptionFromPath generates a human-readable label from a container path.
// /movies → "Movies", /config → "Configuration", /var/log → "Log"
func descriptionFromPath(containerPath string) string {
	// Special cases
	switch strings.ToLower(containerPath) {
	case "/config":
		return "Configuration"
	case "/data":
		return "Data"
	case "/etc":
		return "System config"
	case "/var/log", "/logs":
		return "Logs"
	case "/cache":
		return "Cache"
	}

	// Use last path segment
	base := filepath.Base(containerPath)
	if base == "" || base == "." || base == "/" {
		return "Data"
	}

	// Capitalize first letter, replace hyphens/underscores with spaces
	base = strings.ReplaceAll(base, "-", " ")
	base = strings.ReplaceAll(base, "_", " ")
	if len(base) > 0 {
		base = strings.ToUpper(base[:1]) + base[1:]
	}
	return base
}

// RemapExternalVolumes rewrites external bind mounts to safe defaults under
// the app's appdata directory. Returns the modified compose YAML, a list of
// remap results, and any error.
//
// Only bind mounts with sources NOT under /cubeos/apps/{appName}/ are remapped.
// Paths already under the app's directory are left unchanged.
func RemapExternalVolumes(composeYAML, appName, appDataDir string, overrides map[string]string) (string, []RemapResult, error) {
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(composeYAML), &compose); err != nil {
		return composeYAML, nil, fmt.Errorf("failed to parse compose for volume remapping: %w", err)
	}

	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return composeYAML, nil, nil
	}

	var results []RemapResult
	seenBasenames := make(map[string]int) // track duplicate basenames

	appPrefix := fmt.Sprintf("/cubeos/apps/%s/", appName)

	for svcName, svcDef := range services {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}

		volumes, ok := svc["volumes"].([]interface{})
		if !ok {
			continue
		}

		for i, v := range volumes {
			switch vol := v.(type) {
			case string:
				result := remapShortVolume(vol, svcName, appPrefix, appDataDir, overrides, seenBasenames)
				if result != nil {
					volumes[i] = buildShortVolume(result.Remapped, result.ContainerPath, result.ReadOnly)
					results = append(results, *result)
				}

			case map[string]interface{}:
				result := remapLongVolume(vol, svcName, appPrefix, appDataDir, overrides, seenBasenames)
				if result != nil {
					vol["source"] = result.Remapped
					results = append(results, *result)
				}
			}
		}
	}

	// Pre-create all remapped directories
	for _, r := range results {
		if r.WasRemapped {
			if err := os.MkdirAll(r.Remapped, 0777); err != nil {
				log.Warn().Err(err).Str("path", r.Remapped).Msg("failed to pre-create remapped volume directory")
			} else {
				os.Chmod(r.Remapped, 0777)
			}
		}
	}

	out, err := yaml.Marshal(compose)
	if err != nil {
		return composeYAML, results, fmt.Errorf("failed to serialize remapped compose: %w", err)
	}

	return string(out), results, nil
}

// remapShortVolume handles short-form volume strings like "/host:/container:ro"
func remapShortVolume(vol, svcName, appPrefix, appDataDir string, overrides map[string]string, seenBasenames map[string]int) *RemapResult {
	parts := strings.SplitN(vol, ":", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "/") {
		return nil
	}

	hostPath := parts[0]
	containerPath := parts[1]
	readOnly := len(parts) == 3 && strings.Contains(parts[2], "ro")

	// Skip if already under this app's directory
	if strings.HasPrefix(hostPath, appPrefix) {
		return nil
	}

	// Check for user override
	if override, ok := overrides[containerPath]; ok && override != "" {
		return &RemapResult{
			ServiceName:   svcName,
			Original:      hostPath,
			Remapped:      override,
			ContainerPath: containerPath,
			WasRemapped:   hostPath != override,
			IsConfig:      isConfigPath(containerPath),
			ReadOnly:      readOnly,
			Description:   descriptionFromPath(containerPath),
		}
	}

	// Remap to safe default
	remapped := buildRemappedPath(appDataDir, containerPath, seenBasenames)

	return &RemapResult{
		ServiceName:   svcName,
		Original:      hostPath,
		Remapped:      remapped,
		ContainerPath: containerPath,
		WasRemapped:   true,
		IsConfig:      isConfigPath(containerPath),
		ReadOnly:      readOnly,
		Description:   descriptionFromPath(containerPath),
	}
}

// remapLongVolume handles long-form volume maps like {type: bind, source: ..., target: ...}
func remapLongVolume(vol map[string]interface{}, svcName, appPrefix, appDataDir string, overrides map[string]string, seenBasenames map[string]int) *RemapResult {
	volType, _ := vol["type"].(string)
	if volType != "" && volType != "bind" {
		return nil
	}

	src, ok := vol["source"].(string)
	if !ok || !strings.HasPrefix(src, "/") {
		return nil
	}

	target, _ := vol["target"].(string)
	if target == "" {
		return nil
	}

	ro, _ := vol["read_only"].(bool)

	// Skip if already under this app's directory
	if strings.HasPrefix(src, appPrefix) {
		return nil
	}

	// Check for user override
	if override, ok := overrides[target]; ok && override != "" {
		return &RemapResult{
			ServiceName:   svcName,
			Original:      src,
			Remapped:      override,
			ContainerPath: target,
			WasRemapped:   src != override,
			IsConfig:      isConfigPath(target),
			ReadOnly:      ro,
			Description:   descriptionFromPath(target),
		}
	}

	remapped := buildRemappedPath(appDataDir, target, seenBasenames)

	return &RemapResult{
		ServiceName:   svcName,
		Original:      src,
		Remapped:      remapped,
		ContainerPath: target,
		WasRemapped:   true,
		IsConfig:      isConfigPath(target),
		ReadOnly:      ro,
		Description:   descriptionFromPath(target),
	}
}

// buildRemappedPath creates a safe path under appDataDir based on the container path.
// Handles deduplication of basenames.
func buildRemappedPath(appDataDir, containerPath string, seenBasenames map[string]int) string {
	base := sanitizePathSegment(filepath.Base(containerPath))
	if base == "" || base == "." {
		base = "data"
	}

	// Deduplicate: if "movies" already used, next becomes "movies-2"
	seenBasenames[base]++
	if seenBasenames[base] > 1 {
		base = fmt.Sprintf("%s-%d", base, seenBasenames[base])
	}

	return filepath.Join(appDataDir, base)
}

// sanitizePathSegment converts a path segment to a safe, lowercase, hyphenated form.
// "TV Shows" → "tv-shows", "My.Data" → "my-data"
func sanitizePathSegment(s string) string {
	s = strings.ToLower(s)
	s = strings.TrimLeft(s, "/.")

	// Replace spaces, underscores, dots with hyphens
	re := regexp.MustCompile(`[\s_\.]+`)
	s = re.ReplaceAllString(s, "-")

	// Remove anything that isn't alphanumeric or hyphen
	re = regexp.MustCompile(`[^a-z0-9\-]`)
	s = re.ReplaceAllString(s, "")

	// Collapse multiple hyphens
	re = regexp.MustCompile(`-+`)
	s = re.ReplaceAllString(s, "-")

	return strings.Trim(s, "-")
}

// buildShortVolume reconstructs a short-form volume string.
func buildShortVolume(hostPath, containerPath string, readOnly bool) string {
	vol := hostPath + ":" + containerPath
	if readOnly {
		vol += ":ro"
	}
	return vol
}

// PreviewVolumes extracts and analyzes volumes from a store app's manifest
// WITHOUT modifying anything. Used by the frontend to show a pre-install preview.
func (m *AppStoreManager) PreviewVolumes(storeID, appName string) (*VolumePreviewResponse, error) {
	storeApp := m.GetApp(storeID, appName)
	if storeApp == nil {
		return nil, fmt.Errorf("app not found: %s/%s", storeID, appName)
	}

	manifestData, err := os.ReadFile(storeApp.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// Apply the same processing as install (variable substitution, sanitization)
	// but with a dummy data dir just for analysis
	dummyDataDir := fmt.Sprintf("/cubeos/apps/%s/appdata", appName)
	dummyReq := &AppInstallRequestForPreview{AppName: appName}
	processed := m.processManifestForPreview(string(manifestData), appName, dummyDataDir, dummyReq)

	volumes, err := ExtractBindMounts(processed)
	if err != nil {
		return nil, fmt.Errorf("failed to extract volumes: %w", err)
	}

	// For preview, set the remapped paths to show what WOULD happen
	appPrefix := fmt.Sprintf("/cubeos/apps/%s/", appName)
	seenBasenames := make(map[string]int)
	for i := range volumes {
		if !strings.HasPrefix(volumes[i].OriginalHostPath, appPrefix) {
			volumes[i].CurrentHostPath = buildRemappedPath(dummyDataDir, volumes[i].ContainerPath, seenBasenames)
			volumes[i].IsRemapped = true
		}
	}

	return &VolumePreviewResponse{
		AppName: appName,
		Volumes: volumes,
	}, nil
}

// AppInstallRequestForPreview is a minimal stand-in for preview-only manifest processing.
type AppInstallRequestForPreview struct {
	AppName string
}

// processManifestForPreview applies variable substitution without needing a full AppInstallRequest.
func (m *AppStoreManager) processManifestForPreview(manifest, appID, dataDir string, _ *AppInstallRequestForPreview) string {
	tz := os.Getenv("TZ")
	if tz == "" {
		tz = "UTC"
	}

	replacements := map[string]string{
		"$PUID":         "1000",
		"${PUID}":       "1000",
		"$PGID":         "1000",
		"${PGID}":       "1000",
		"$TZ":           tz,
		"${TZ}":         tz,
		"$AppID":        appID,
		"${AppID}":      appID,
		"${WEBUI_PORT}": "8080",
	}

	result := manifest
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	result = strings.ReplaceAll(result, "/DATA/AppData/$AppID", dataDir)
	result = strings.ReplaceAll(result, "/DATA/AppData/${AppID}", dataDir)
	result = strings.ReplaceAll(result, "/DATA/AppData/"+appID, dataDir)

	return result
}

// GetVolumeMappings returns the stored volume mappings for an installed app.
func (m *AppStoreManager) GetVolumeMappings(appID string) (*VolumeMappingsResponse, error) {
	// Look up the app's DB id
	var dbAppID int64
	var displayName string
	err := m.db.db.QueryRow(`SELECT id, COALESCE(display_name, name) FROM apps WHERE name = ?`, appID).Scan(&dbAppID, &displayName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("app not found: %s", appID)
		}
		return nil, fmt.Errorf("failed to query app: %w", err)
	}

	rows, err := m.db.db.Query(`SELECT id, container_path, original_host_path, current_host_path,
		description, is_remapped, is_config, read_only, created_at, updated_at
		FROM volume_mappings WHERE app_id = ? ORDER BY is_config ASC, container_path ASC`, dbAppID)
	if err != nil {
		return nil, fmt.Errorf("failed to query volume mappings: %w", err)
	}
	defer rows.Close()

	var volumes []VolumeMapping
	for rows.Next() {
		var vm VolumeMapping
		var isRemapped, isConfig, readOnly int
		err := rows.Scan(&vm.ID, &vm.ContainerPath, &vm.OriginalHostPath, &vm.CurrentHostPath,
			&vm.Description, &isRemapped, &isConfig, &readOnly, &vm.CreatedAt, &vm.UpdatedAt)
		if err != nil {
			continue
		}
		vm.AppID = dbAppID
		vm.IsRemapped = isRemapped == 1
		vm.IsConfig = isConfig == 1
		vm.ReadOnly = readOnly == 1
		vm.IsExternal = !strings.HasPrefix(vm.OriginalHostPath, fmt.Sprintf("/cubeos/apps/%s/", appID))
		volumes = append(volumes, vm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating volume mappings: %w", err)
	}

	// If no DB records exist, try extracting from the current compose file
	if len(volumes) == 0 {
		extracted, err := m.extractVolumesFromCompose(appID)
		if err == nil && len(extracted) > 0 {
			volumes = extracted
		}
	}

	return &VolumeMappingsResponse{
		AppID:   appID,
		AppName: displayName,
		Volumes: volumes,
	}, nil
}

// extractVolumesFromCompose reads the current compose file for an app and
// returns volume mappings. Used as fallback for apps installed before volume tracking.
func (m *AppStoreManager) extractVolumesFromCompose(appID string) ([]VolumeMapping, error) {
	composePath := filepath.Join(m.appsPath, appID, "appconfig", "docker-compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, err
	}

	return ExtractBindMounts(string(data))
}

// UpdateVolumeMappings applies user volume path changes, rewrites the compose file,
// and redeploys the stack.
func (m *AppStoreManager) UpdateVolumeMappings(appID string, updates []VolumeMappingUpdate) error {
	// Validate all new paths
	for _, u := range updates {
		if err := validateHostPath(u.NewHostPath); err != nil {
			return fmt.Errorf("invalid path %q: %w", u.NewHostPath, err)
		}
	}

	// Read current compose file
	composePath := filepath.Join(m.appsPath, appID, "appconfig", "docker-compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read compose file: %w", err)
	}

	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return fmt.Errorf("failed to parse compose: %w", err)
	}

	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no services in compose file")
	}

	// Build lookup: container_path → new host path
	updateMap := make(map[string]string)
	for _, u := range updates {
		updateMap[u.ContainerPath] = u.NewHostPath
	}

	// Rewrite volume entries
	for _, svcDef := range services {
		svc, ok := svcDef.(map[string]interface{})
		if !ok {
			continue
		}

		volumes, ok := svc["volumes"].([]interface{})
		if !ok {
			continue
		}

		for i, v := range volumes {
			switch vol := v.(type) {
			case string:
				parts := strings.SplitN(vol, ":", 3)
				if len(parts) >= 2 {
					if newPath, ok := updateMap[parts[1]]; ok {
						parts[0] = newPath
						volumes[i] = strings.Join(parts, ":")
					}
				}

			case map[string]interface{}:
				target, _ := vol["target"].(string)
				if newPath, ok := updateMap[target]; ok {
					vol["source"] = newPath
				}
			}
		}
	}

	// Create new host directories
	for _, u := range updates {
		if err := os.MkdirAll(u.NewHostPath, 0777); err != nil {
			log.Warn().Err(err).Str("path", u.NewHostPath).Msg("failed to create volume directory")
		} else {
			os.Chmod(u.NewHostPath, 0777)
		}
	}

	// Backup current compose
	backupDir := filepath.Join(filepath.Dir(composePath), ".backups", time.Now().Format("20060102-150405"))
	os.MkdirAll(backupDir, 0755)
	os.WriteFile(filepath.Join(backupDir, "docker-compose.yml"), data, 0644)

	// Write updated compose
	out, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to serialize updated compose: %w", err)
	}
	if err := os.WriteFile(composePath, out, 0644); err != nil {
		return fmt.Errorf("failed to write compose file: %w", err)
	}

	// Update volume_mappings table
	var dbAppID int64
	if err := m.db.db.QueryRow("SELECT id FROM apps WHERE name = ?", appID).Scan(&dbAppID); err == nil {
		for _, u := range updates {
			m.db.db.Exec(`UPDATE volume_mappings SET current_host_path = ?, is_remapped = TRUE, updated_at = ?
				WHERE app_id = ? AND container_path = ?`,
				u.NewHostPath, time.Now().Format(time.RFC3339), dbAppID, u.ContainerPath)
		}
	}

	// Redeploy stack
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
		"-c", composePath,
		"--resolve-image=never",
		appID,
	)
	cmd.Dir = filepath.Dir(composePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to redeploy stack: %s", string(output))
	}

	log.Info().Str("app", appID).Int("updates", len(updates)).Msg("volume mappings updated, stack redeployed")
	return nil
}

// StoreVolumeMappings persists volume mapping results to the database.
func (m *AppStoreManager) StoreVolumeMappings(appName string, remapResults []RemapResult) {
	var dbAppID int64
	if err := m.db.db.QueryRow("SELECT id FROM apps WHERE name = ?", appName).Scan(&dbAppID); err != nil {
		log.Warn().Err(err).Str("app", appName).Msg("failed to find app for volume mappings storage")
		return
	}

	now := time.Now().Format(time.RFC3339)
	for _, r := range remapResults {
		_, err := m.db.db.Exec(`INSERT INTO volume_mappings 
			(app_id, container_path, original_host_path, current_host_path, description, is_remapped, is_config, read_only, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(app_id, container_path) DO UPDATE SET
				current_host_path = excluded.current_host_path,
				is_remapped = excluded.is_remapped,
				updated_at = excluded.updated_at`,
			dbAppID, r.ContainerPath, r.Original, r.Remapped, r.Description, r.WasRemapped, r.IsConfig, r.ReadOnly, now, now)
		if err != nil {
			log.Warn().Err(err).Str("app", appName).Str("mount", r.ContainerPath).Msg("failed to store volume mapping")
		}
	}
}

// validateHostPath checks that a user-provided path is safe to use.
func validateHostPath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute")
	}

	cleanPath := filepath.Clean(path)
	for _, restricted := range restrictedPaths {
		if cleanPath == restricted {
			return fmt.Errorf("path %q is restricted", restricted)
		}
	}

	return nil
}

// getServiceTaskError checks why services in a stack are failing by
// inspecting task errors via `docker service ps`.
func (m *AppStoreManager) getServiceTaskError(stackName string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// List services in the stack
	out, err := exec.CommandContext(ctx, "docker", "stack", "services",
		"--format", "{{.Name}}", stackName).CombinedOutput()
	if err != nil {
		return ""
	}

	serviceNames := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, svcName := range serviceNames {
		if svcName == "" {
			continue
		}

		// Get the latest task error for this service
		taskOut, err := exec.CommandContext(ctx, "docker", "service", "ps",
			"--no-trunc",
			"--format", "{{.Error}}",
			"--filter", "desired-state=running",
			svcName).CombinedOutput()
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(taskOut), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				return fmt.Sprintf("%s: %s", svcName, line)
			}
		}

		// Also check shutdown/failed tasks for errors
		taskOut2, err := exec.CommandContext(ctx, "docker", "service", "ps",
			"--no-trunc",
			"--format", "{{.Error}}",
			"--filter", "desired-state=shutdown",
			svcName).CombinedOutput()
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(taskOut2), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				return fmt.Sprintf("%s: %s", svcName, line)
			}
		}
	}

	return ""
}

// BrowseDirectories lists subdirectories at a given path.
// Returns only directories, not files. Used by the directory picker UI.
func BrowseDirectories(path string) ([]DirEntry, error) {
	if path == "" {
		path = "/"
	}
	cleanPath := filepath.Clean(path)

	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("path not found: %s", cleanPath)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", cleanPath)
	}

	entries, err := os.ReadDir(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory: %w", err)
	}

	var dirs []DirEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip hidden directories
		if strings.HasPrefix(name, ".") {
			continue
		}

		fullPath := filepath.Join(cleanPath, name)
		isRestricted := false
		for _, r := range restrictedPaths {
			if fullPath == r {
				isRestricted = true
				break
			}
		}

		dirs = append(dirs, DirEntry{
			Name:         name,
			Path:         fullPath,
			IsRestricted: isRestricted,
		})
	}

	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].Name < dirs[j].Name
	})

	return dirs, nil
}

// DirEntry represents a directory for the browser UI.
type DirEntry struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	IsRestricted bool   `json:"is_restricted"`
}
