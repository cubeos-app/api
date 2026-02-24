package managers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/database"
	"cubeos-api/internal/models"
)

// defaultUpdateURL is the default GitHub Releases API endpoint for CubeOS.
const defaultUpdateURL = "https://api.github.com/repos/cubeos-app/releases/releases"

// UpdateManager handles checking for system updates, fetching release manifests,
// and caching results for offline use.
type UpdateManager struct {
	db            *sql.DB
	httpClient    *http.Client
	currentVer    string
	updateURL     string
	checkInterval time.Duration

	mu            sync.RWMutex
	latestRelease *models.ReleaseManifest
	lastChecked   time.Time
	lastError     error

	stopCh chan struct{}
}

// NewUpdateManager creates a new UpdateManager. It reads the current version
// from CUBEOS_VERSION env var and configures the update check URL.
func NewUpdateManager(db *sql.DB) *UpdateManager {
	currentVer := os.Getenv("CUBEOS_VERSION")
	if currentVer == "" {
		currentVer = "0.0.0"
	}

	updateURL := os.Getenv("CUBEOS_UPDATE_URL")
	if updateURL == "" {
		updateURL = defaultUpdateURL
	}

	// Read check interval from settings (default: 86400s = 24h)
	interval := 86400
	if db != nil {
		var val string
		err := db.QueryRow("SELECT value FROM settings WHERE key = 'update_check_interval'").Scan(&val)
		if err == nil {
			if parsed, e := strconv.Atoi(val); e == nil && parsed > 0 {
				interval = parsed
			}
		}
	}

	return &UpdateManager{
		db:            db,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		currentVer:    currentVer,
		updateURL:     updateURL,
		checkInterval: time.Duration(interval) * time.Second,
		stopCh:        make(chan struct{}),
	}
}

// Start begins the background update check goroutine.
// It checks if update_check_enabled is true before running.
func (m *UpdateManager) Start(ctx context.Context) {
	go m.checkLoop(ctx)
	log.Info().
		Str("version", m.currentVer).
		Str("interval", m.checkInterval.String()).
		Msg("UpdateManager: background update check started")
}

// Stop signals the background check loop to exit.
func (m *UpdateManager) Stop() {
	close(m.stopCh)
}

// CheckForUpdates performs an immediate update check and returns the result.
func (m *UpdateManager) CheckForUpdates(ctx context.Context) (*models.UpdateCheckResponse, error) {
	manifest, err := m.fetchAndCacheManifest(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("UpdateManager: fetch failed, trying cache")
		manifest = m.loadCachedManifest()
	}

	resp := &models.UpdateCheckResponse{
		CurrentVersion: m.currentVer,
		Channel:        detectChannel(m.currentVer),
		LastChecked:    m.getLastChecked().Format(time.RFC3339),
	}

	if manifest != nil {
		resp.LatestVersion = manifest.Version
		resp.UpdateAvailable = compareVersions(m.currentVer, manifest.Version) < 0
		resp.Release = manifest
	} else {
		resp.LatestVersion = m.currentVer
		resp.UpdateAvailable = false
	}

	return resp, nil
}

// GetLatestRelease returns the cached latest release manifest (thread-safe).
func (m *UpdateManager) GetLatestRelease() *models.ReleaseManifest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latestRelease
}

// IsUpdateAvailable returns whether a newer version is available (thread-safe).
func (m *UpdateManager) IsUpdateAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.latestRelease == nil {
		return false
	}
	return compareVersions(m.currentVer, m.latestRelease.Version) < 0
}

// GetUpdateHistory retrieves past update attempts from the database.
func (m *UpdateManager) GetUpdateHistory(ctx context.Context) ([]models.UpdateHistoryEntry, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	rows, err := m.db.QueryContext(ctx,
		"SELECT id, from_version, to_version, status, started_at, COALESCE(completed_at, ''), COALESCE(error_message, '') FROM update_history ORDER BY id DESC LIMIT 50")
	if err != nil {
		return nil, fmt.Errorf("query update history: %w", err)
	}
	defer rows.Close()

	var entries []models.UpdateHistoryEntry
	for rows.Next() {
		var e models.UpdateHistoryEntry
		if err := rows.Scan(&e.ID, &e.FromVersion, &e.ToVersion, &e.Status, &e.StartedAt, &e.CompletedAt, &e.ErrorMessage); err != nil {
			return nil, fmt.Errorf("scan update history: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ValidateUpdate checks whether the given release can be applied to the current system.
// It returns an error describing why the update is blocked, or nil if it's safe.
func (m *UpdateManager) ValidateUpdate(manifest *models.ReleaseManifest) error {
	if manifest == nil {
		return fmt.Errorf("manifest is nil")
	}

	// Check MinVersion gate
	if manifest.MinVersion != "" {
		if compareVersions(m.currentVer, manifest.MinVersion) < 0 {
			return fmt.Errorf("current version %s is below minimum required %s — intermediate update needed",
				m.currentVer, manifest.MinVersion)
		}
	}

	// Flag schema migration requirement (informational, not blocking)
	if manifest.SchemaVersion > 0 {
		currentSchema, err := database.GetSchemaVersion(m.db)
		if err == nil && manifest.SchemaVersion > currentSchema {
			log.Info().
				Int("current_schema", currentSchema).
				Int("required_schema", manifest.SchemaVersion).
				Msg("UpdateManager: update includes database migration")
		}
	}

	// Breaking changes are informational — logged but don't block (user must use Force flag)
	if len(manifest.Breaking) > 0 {
		log.Warn().
			Int("count", len(manifest.Breaking)).
			Strs("changes", manifest.Breaking).
			Msg("UpdateManager: update contains breaking changes")
	}

	return nil
}

// ---------------------------------------------------------------------------
// Background check loop
// ---------------------------------------------------------------------------

func (m *UpdateManager) checkLoop(ctx context.Context) {
	// Initial delay: wait 2 minutes after boot before first check
	select {
	case <-time.After(2 * time.Minute):
	case <-m.stopCh:
		return
	case <-ctx.Done():
		return
	}

	if !m.isCheckEnabled() {
		log.Info().Msg("UpdateManager: update_check_enabled=false, background check disabled")
		return
	}

	// Run first check
	m.runCheck(ctx)

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if m.isCheckEnabled() {
				m.runCheck(ctx)
			}
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (m *UpdateManager) runCheck(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	manifest, err := m.fetchAndCacheManifest(checkCtx)

	m.mu.Lock()
	m.lastChecked = time.Now()
	m.lastError = err
	if manifest != nil {
		m.latestRelease = manifest
	}
	m.mu.Unlock()

	if err != nil {
		// Try cached manifest as fallback
		cached := m.loadCachedManifest()
		if cached != nil {
			m.mu.Lock()
			m.latestRelease = cached
			m.mu.Unlock()
			log.Warn().Err(err).Str("cached_version", cached.Version).
				Msg("UpdateManager: fetch failed, using cached manifest")
		} else {
			log.Warn().Err(err).Msg("UpdateManager: fetch failed, no cache available")
		}
		return
	}

	if manifest != nil {
		available := compareVersions(m.currentVer, manifest.Version) < 0
		log.Info().
			Str("current", m.currentVer).
			Str("latest", manifest.Version).
			Bool("update_available", available).
			Msg("UpdateManager: check complete")
	}
}

// ---------------------------------------------------------------------------
// Fetch and parse
// ---------------------------------------------------------------------------

// githubRelease represents a single release from the GitHub Releases API.
type githubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	Prerelease  bool   `json:"prerelease"`
}

func (m *UpdateManager) fetchAndCacheManifest(ctx context.Context) (*models.ReleaseManifest, error) {
	// Check if device is offline
	if m.isOffline() {
		cached := m.loadCachedManifest()
		if cached != nil {
			return cached, nil
		}
		return nil, nil // Not an error — just no updates available offline
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.updateURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "CubeOS/"+m.currentVer)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update check failed: HTTP %d", resp.StatusCode)
	}

	var releases []githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("parse releases: %w", err)
	}

	if len(releases) == 0 {
		return nil, nil
	}

	// Find the latest compatible release
	manifest := m.findBestRelease(releases)
	if manifest == nil {
		return nil, nil
	}

	// Cache the manifest
	m.cacheManifest(manifest)

	// Record last check time
	m.recordLastCheck()

	return manifest, nil
}

// findBestRelease picks the latest release that is compatible with the current channel.
func (m *UpdateManager) findBestRelease(releases []githubRelease) *models.ReleaseManifest {
	currentChannel := detectChannel(m.currentVer)
	var best *models.ReleaseManifest

	for _, rel := range releases {
		version := strings.TrimPrefix(rel.TagName, "v")
		relChannel := detectChannel(version)

		// Alpha users see alpha+beta+stable; beta users see beta+stable; stable sees stable only
		if !channelCompatible(currentChannel, relChannel) {
			continue
		}

		manifest := parseGitHubRelease(rel)
		if best == nil || compareVersions(best.Version, manifest.Version) < 0 {
			best = manifest
		}
	}

	return best
}

// parseGitHubRelease converts a GitHub release into our internal ReleaseManifest.
func parseGitHubRelease(rel githubRelease) *models.ReleaseManifest {
	version := strings.TrimPrefix(rel.TagName, "v")
	channel := "stable"
	if rel.Prerelease {
		channel = detectChannel(version)
	}

	notes, breaking, images := parseReleaseBody(rel.Body)

	return &models.ReleaseManifest{
		Version:      version,
		ReleaseDate:  rel.PublishedAt,
		Channel:      channel,
		ReleaseNotes: notes,
		Breaking:     breaking,
		Images:       images,
	}
}

// parseReleaseBody extracts structured sections from the release body markdown.
func parseReleaseBody(body string) (notes string, breaking []string, images map[string]string) {
	images = make(map[string]string)

	if body == "" {
		return "", nil, images
	}

	lines := strings.Split(body, "\n")
	section := "notes"
	var notesBuilder strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect section headers
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "## breaking") {
			section = "breaking"
			continue
		}
		if strings.HasPrefix(lower, "## images") {
			section = "images"
			continue
		}
		if strings.HasPrefix(trimmed, "## ") && section != "notes" {
			// Another section header after breaking/images — stop parsing structured data
			section = "other"
			continue
		}

		switch section {
		case "notes":
			// Everything before the first structured section is release notes
			if strings.HasPrefix(lower, "## breaking") || strings.HasPrefix(lower, "## images") {
				continue
			}
			notesBuilder.WriteString(line)
			notesBuilder.WriteString("\n")

		case "breaking":
			// Parse bullet list items
			if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
				breaking = append(breaking, strings.TrimSpace(trimmed[2:]))
			}

		case "images":
			// Parse key=value pairs
			if idx := strings.Index(trimmed, "="); idx > 0 {
				key := strings.TrimSpace(trimmed[:idx])
				val := strings.TrimSpace(trimmed[idx+1:])
				if key != "" && val != "" {
					images[key] = val
				}
			}
		}
	}

	notes = strings.TrimSpace(notesBuilder.String())
	return notes, breaking, images
}

// ---------------------------------------------------------------------------
// Semver comparison
// ---------------------------------------------------------------------------

// compareVersions compares two semver strings and returns -1, 0, or 1.
// Handles pre-release identifiers: 0.2.0-alpha.01 < 0.2.0-beta.01 < 0.2.0
func compareVersions(a, b string) int {
	aMajor, aMinor, aPatch, aPre := parseSemver(a)
	bMajor, bMinor, bPatch, bPre := parseSemver(b)

	if c := intCmp(aMajor, bMajor); c != 0 {
		return c
	}
	if c := intCmp(aMinor, bMinor); c != 0 {
		return c
	}
	if c := intCmp(aPatch, bPatch); c != 0 {
		return c
	}

	// Pre-release comparison:
	// - No pre-release > any pre-release (1.0.0 > 1.0.0-alpha)
	// - Compare pre-release identifiers lexically with numeric sub-parts
	return comparePrerelease(aPre, bPre)
}

// parseSemver splits "1.2.3-alpha.01" into (1, 2, 3, "alpha.01").
func parseSemver(v string) (major, minor, patch int, pre string) {
	v = strings.TrimPrefix(v, "v")

	// Split off pre-release
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		pre = v[idx+1:]
		v = v[:idx]
	}

	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 1 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return
}

// comparePrerelease compares pre-release identifiers per semver spec.
// Empty pre-release (stable) has HIGHER precedence than any pre-release.
func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	// No pre-release (stable) > any pre-release
	if a == "" {
		return 1
	}
	if b == "" {
		return -1
	}

	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		if i >= len(aParts) {
			return -1 // a has fewer identifiers → lower precedence
		}
		if i >= len(bParts) {
			return 1 // b has fewer identifiers → lower precedence
		}

		aNum, aIsNum := tryParseInt(aParts[i])
		bNum, bIsNum := tryParseInt(bParts[i])

		switch {
		case aIsNum && bIsNum:
			if c := intCmp(aNum, bNum); c != 0 {
				return c
			}
		case aIsNum:
			return -1 // numeric < string per semver spec
		case bIsNum:
			return 1
		default:
			if c := strings.Compare(aParts[i], bParts[i]); c != 0 {
				return c
			}
		}
	}
	return 0
}

func tryParseInt(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func intCmp(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Channel detection and compatibility
// ---------------------------------------------------------------------------

var preReleaseChannelRe = regexp.MustCompile(`^(alpha|beta|rc)`)

// detectChannel determines the release channel from a version string.
func detectChannel(version string) string {
	_, _, _, pre := parseSemver(version)
	if pre == "" {
		return "stable"
	}
	match := preReleaseChannelRe.FindString(pre)
	if match != "" {
		return match
	}
	return "stable"
}

// channelCompatible returns true if a release on relChannel is visible to a user on currentChannel.
// Alpha users see everything; beta users see beta+stable; stable users see stable only.
func channelCompatible(currentChannel, relChannel string) bool {
	order := map[string]int{"alpha": 0, "beta": 1, "rc": 2, "stable": 3}
	cur, ok1 := order[currentChannel]
	rel, ok2 := order[relChannel]
	if !ok1 || !ok2 {
		return true // Unknown channel — show it
	}
	return rel >= cur
}

// ---------------------------------------------------------------------------
// Settings helpers (DB-backed)
// ---------------------------------------------------------------------------

func (m *UpdateManager) isCheckEnabled() bool {
	if m.db == nil {
		return true
	}
	var val string
	err := m.db.QueryRow("SELECT value FROM settings WHERE key = 'update_check_enabled'").Scan(&val)
	if err != nil {
		return true // Default enabled
	}
	return val != "false"
}

func (m *UpdateManager) isOffline() bool {
	if m.db == nil {
		return false
	}
	var mode string
	err := m.db.QueryRow("SELECT mode FROM network_config WHERE id = 1").Scan(&mode)
	if err != nil {
		return false
	}
	return mode == "offline_hotspot"
}

func (m *UpdateManager) loadCachedManifest() *models.ReleaseManifest {
	if m.db == nil {
		return nil
	}
	var cached string
	err := m.db.QueryRow("SELECT value FROM settings WHERE key = 'update_manifest_cache'").Scan(&cached)
	if err != nil || cached == "" || cached == "{}" {
		return nil
	}

	var manifest models.ReleaseManifest
	if err := json.Unmarshal([]byte(cached), &manifest); err != nil {
		log.Warn().Err(err).Msg("UpdateManager: failed to parse cached manifest")
		return nil
	}
	if manifest.Version == "" {
		return nil
	}
	return &manifest
}

func (m *UpdateManager) cacheManifest(manifest *models.ReleaseManifest) {
	if m.db == nil || manifest == nil {
		return
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		log.Warn().Err(err).Msg("UpdateManager: failed to marshal manifest for cache")
		return
	}
	_, err = m.db.Exec("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('update_manifest_cache', ?, CURRENT_TIMESTAMP)", string(data))
	if err != nil {
		log.Warn().Err(err).Msg("UpdateManager: failed to cache manifest")
	}
}

func (m *UpdateManager) recordLastCheck() {
	if m.db == nil {
		return
	}
	now := time.Now().Format(time.RFC3339)
	_, err := m.db.Exec("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('last_update_check', ?, CURRENT_TIMESTAMP)", now)
	if err != nil {
		log.Warn().Err(err).Msg("UpdateManager: failed to record last check time")
	}
}

func (m *UpdateManager) getLastChecked() time.Time {
	m.mu.RLock()
	t := m.lastChecked
	m.mu.RUnlock()

	if !t.IsZero() {
		return t
	}

	// Fallback: read from settings
	if m.db != nil {
		var val string
		err := m.db.QueryRow("SELECT value FROM settings WHERE key = 'last_update_check'").Scan(&val)
		if err == nil && val != "" {
			if parsed, e := time.Parse(time.RFC3339, val); e == nil {
				return parsed
			}
		}
	}
	return time.Now()
}
