package managers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// RegistrySyncManager handles background synchronization of registry images
// with upstream sources when the device is online.
type RegistrySyncManager struct {
	db          *sql.DB
	registryURL string
	httpClient  *http.Client

	mu         sync.Mutex
	lastSync   time.Time
	lastResult *SyncResult
	running    bool

	stopCh chan struct{}
}

// SyncResult captures the outcome of a sync cycle.
type SyncResult struct {
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Checked     int       `json:"checked"`
	Updated     int       `json:"updated"`
	Failed      int       `json:"failed"`
	Skipped     int       `json:"skipped"`
	Details     []string  `json:"details"`
	Error       string    `json:"error,omitempty"`
}

// CoreRegistryImages defines which images to sync from upstream.
// Format: upstream_ref -> local_repo
var CoreRegistryImages = map[string]string{
	"docker.io/pihole/pihole:latest":             "pihole/pihole",
	"docker.io/jc21/nginx-proxy-manager:latest":  "jc21/nginx-proxy-manager",
	"ghcr.io/cubeos-app/api:latest":              "cubeos-app/api",
	"ghcr.io/cubeos-app/hal:latest":              "cubeos-app/hal",
	"ghcr.io/cubeos-app/dashboard:latest":        "cubeos-app/dashboard",
	"ghcr.io/cubeos-app/cubeos-docsindex:latest": "cubeos-app/cubeos-docsindex",
	"docker.io/amir20/dozzle:latest":             "amir20/dozzle",
}

// CuratedRegistryImages are curated apps with pinned versions.
var CuratedRegistryImages = map[string]string{
	"docker.io/kiwix/kiwix-serve:3.8.1": "kiwix/kiwix-serve",
	"docker.io/tsl0922/ttyd:latest":     "tsl0922/ttyd",
}

// NewRegistrySyncManager creates a new sync manager.
func NewRegistrySyncManager(db *sql.DB, registryURL string) *RegistrySyncManager {
	if registryURL == "" {
		registryURL = "http://10.42.24.1:5000"
	}
	return &RegistrySyncManager{
		db:          db,
		registryURL: registryURL,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		stopCh:      make(chan struct{}),
	}
}

// Start begins the background sync loop. Call once at API startup.
func (m *RegistrySyncManager) Start() {
	go m.syncLoop()
	log.Info().Msg("RegistrySyncManager: background sync started (6h interval)")
}

// Stop signals the sync loop to exit.
func (m *RegistrySyncManager) Stop() {
	close(m.stopCh)
}

// GetLastResult returns the most recent sync result.
func (m *RegistrySyncManager) GetLastResult() *SyncResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastResult
}

// IsRunning returns whether a sync is currently in progress.
func (m *RegistrySyncManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// TriggerSync runs a sync cycle immediately (non-blocking, returns error if already running).
func (m *RegistrySyncManager) TriggerSync() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("sync already in progress")
	}
	m.mu.Unlock()

	go m.runSync()
	return nil
}

func (m *RegistrySyncManager) syncLoop() {
	// Initial delay: wait 5 minutes after boot before first check
	select {
	case <-time.After(5 * time.Minute):
	case <-m.stopCh:
		return
	}

	// Run immediately on first tick, then every 6 hours
	m.runSync()

	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.runSync()
		case <-m.stopCh:
			return
		}
	}
}

func (m *RegistrySyncManager) runSync() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	result := &SyncResult{
		StartedAt: time.Now(),
	}

	// Check auto-update setting
	if !m.isAutoUpdateEnabled() {
		result.CompletedAt = time.Now()
		result.Details = append(result.Details, "auto_update disabled, skipping sync")
		m.mu.Lock()
		m.lastResult = result
		m.lastSync = time.Now()
		m.mu.Unlock()
		log.Debug().Msg("RegistrySync: auto_update disabled, skipping")
		return
	}

	// Check connectivity
	if !m.isOnline() {
		result.CompletedAt = time.Now()
		result.Details = append(result.Details, "device offline, skipping sync")
		m.mu.Lock()
		m.lastResult = result
		m.lastSync = time.Now()
		m.mu.Unlock()
		log.Debug().Msg("RegistrySync: device offline, skipping")
		return
	}

	log.Info().Msg("RegistrySync: starting sync cycle")

	// Sync core images
	for upstream, localRepo := range CoreRegistryImages {
		m.syncImage(upstream, localRepo, "latest", result)
	}

	// Sync curated images (pinned tags)
	for upstream, localRepo := range CuratedRegistryImages {
		// Extract tag from upstream ref
		parts := strings.SplitN(upstream, ":", 2)
		tag := "latest"
		if len(parts) == 2 {
			tag = parts[1]
		}
		m.syncImage(upstream, localRepo, tag, result)
	}

	result.CompletedAt = time.Now()
	m.mu.Lock()
	m.lastResult = result
	m.lastSync = time.Now()
	m.mu.Unlock()

	log.Info().
		Int("checked", result.Checked).
		Int("updated", result.Updated).
		Int("failed", result.Failed).
		Dur("duration", result.CompletedAt.Sub(result.StartedAt)).
		Msg("RegistrySync: sync cycle complete")
}

func (m *RegistrySyncManager) syncImage(upstreamRef, localRepo, tag string, result *SyncResult) {
	result.Checked++
	localRef := fmt.Sprintf("localhost:5000/%s:%s", localRepo, tag)

	// Pull upstream image
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pullCmd := exec.CommandContext(ctx, "docker", "pull", "--quiet", upstreamRef)
	pullOut, err := pullCmd.CombinedOutput()
	if err != nil {
		result.Failed++
		detail := fmt.Sprintf("FAIL pull %s: %s", upstreamRef, strings.TrimSpace(string(pullOut)))
		result.Details = append(result.Details, detail)
		log.Warn().Str("image", upstreamRef).Err(err).Msg("RegistrySync: pull failed")
		return
	}

	// Get upstream digest
	upstreamDigest := m.getLocalDigest(upstreamRef)
	if upstreamDigest == "" {
		result.Failed++
		result.Details = append(result.Details, fmt.Sprintf("FAIL digest %s: could not get digest", upstreamRef))
		return
	}

	// Get current local registry digest
	localDigest := m.getRegistryDigest(localRepo, tag)

	if upstreamDigest == localDigest && localDigest != "" {
		result.Skipped++
		result.Details = append(result.Details, fmt.Sprintf("SKIP %s: already up to date", localRepo))
		return
	}

	// Retag and push to local registry
	tagCmd := exec.CommandContext(ctx, "docker", "tag", upstreamRef, localRef)
	if out, err := tagCmd.CombinedOutput(); err != nil {
		result.Failed++
		result.Details = append(result.Details, fmt.Sprintf("FAIL tag %s: %s", localRef, strings.TrimSpace(string(out))))
		return
	}

	pushCmd := exec.CommandContext(ctx, "docker", "push", localRef)
	if out, err := pushCmd.CombinedOutput(); err != nil {
		result.Failed++
		result.Details = append(result.Details, fmt.Sprintf("FAIL push %s: %s", localRef, strings.TrimSpace(string(out))))
		return
	}

	result.Updated++
	result.Details = append(result.Details, fmt.Sprintf("UPDATED %s (old=%s new=%s)", localRepo, truncDigest(localDigest), truncDigest(upstreamDigest)))
	log.Info().Str("image", localRepo).Str("tag", tag).Msg("RegistrySync: image updated")
}

// getLocalDigest gets the digest of a locally-pulled Docker image.
func (m *RegistrySyncManager) getLocalDigest(imageRef string) string {
	out, err := exec.Command("docker", "inspect", "--format", "{{index .RepoDigests 0}}", imageRef).Output()
	if err != nil {
		return ""
	}
	// Format: registry/repo@sha256:abc...
	parts := strings.SplitN(strings.TrimSpace(string(out)), "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// getRegistryDigest gets the digest from the local registry via HTTP API.
func (m *RegistrySyncManager) getRegistryDigest(repo, tag string) string {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", m.registryURL, repo, tag)
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}
	return resp.Header.Get("Docker-Content-Digest")
}

func (m *RegistrySyncManager) isAutoUpdateEnabled() bool {
	if m.db == nil {
		return true // default enabled
	}
	var val string
	err := m.db.QueryRow("SELECT value FROM settings WHERE key = 'registry_auto_update'").Scan(&val)
	if err != nil {
		return true // default enabled if not set
	}
	return val != "false"
}

func (m *RegistrySyncManager) isOnline() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Head("https://registry-1.docker.io/v2/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
}

func truncDigest(digest string) string {
	if len(digest) > 19 {
		return digest[:19] + "..."
	}
	return digest
}
