package managers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// FileBrowserClient manages credentials sync with the Dufs file manager.
// Dufs uses HTTP Basic Auth configured via --auth on the command line.
// To change the password, we update the docker-compose.yml and redeploy
// the Swarm stack — similar to the Pi-hole sync approach.
//
// Password sync happens at three points:
//   - First boot: setup.go calls SyncAdminPasswordWithRetry("admin", newPassword)
//   - Password change: handlers.go calls SyncAdminPassword(oldPassword, newPassword)
//   - API startup: main.go calls EnsurePasswordSynced(db) to catch missed syncs
type FileBrowserClient struct {
	baseURL     string
	composeFile string // /cubeos/coreapps/filebrowser/appconfig/docker-compose.yml
	stackName   string // filebrowser
	httpClient  *http.Client
}

// NewFileBrowserClient creates a new Dufs file manager sync client.
// baseURL should be the full URL to the Dufs instance, e.g. "http://10.42.24.1:6013".
func NewFileBrowserClient(baseURL string) *FileBrowserClient {
	return &FileBrowserClient{
		baseURL:     baseURL,
		composeFile: "/cubeos/coreapps/filebrowser/appconfig/docker-compose.yml",
		stackName:   "filebrowser",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// checkPassword verifies if the given password works for Dufs by attempting
// HTTP Basic Auth against the root endpoint.
func (c *FileBrowserClient) checkPassword(password string) bool {
	req, err := http.NewRequest("GET", c.baseURL+"/", nil)
	if err != nil {
		return false
	}
	req.SetBasicAuth("admin", password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// readCurrentPassword extracts the current admin password from the
// docker-compose.yml --auth argument.
// Format: --auth "admin:PASSWORD@/:rw"
func (c *FileBrowserClient) readCurrentPassword() string {
	data, err := os.ReadFile(c.composeFile)
	if err != nil {
		return ""
	}

	// Match: --auth "admin:PASSWORD@/:rw"
	re := regexp.MustCompile(`--auth\s+"admin:([^@]+)@`)
	matches := re.FindSubmatch(data)
	if len(matches) < 2 {
		return ""
	}
	return string(matches[1])
}

// updateComposePassword updates the --auth argument in docker-compose.yml
// with the new password and redeploys the Swarm stack.
func (c *FileBrowserClient) updateComposePassword(newPassword string) error {
	data, err := os.ReadFile(c.composeFile)
	if err != nil {
		return fmt.Errorf("read compose file: %w", err)
	}

	// Replace: --auth "admin:OLD_PASSWORD@/:rw" → --auth "admin:NEW_PASSWORD@/:rw"
	re := regexp.MustCompile(`--auth\s+"admin:[^@]+@/:rw"`)
	newAuth := fmt.Sprintf(`--auth "admin:%s@/:rw"`, newPassword)
	updated := re.ReplaceAll(data, []byte(newAuth))

	if string(updated) == string(data) {
		return fmt.Errorf("no --auth pattern found in compose file")
	}

	if err := os.WriteFile(c.composeFile, updated, 0640); err != nil {
		return fmt.Errorf("write compose file: %w", err)
	}

	return nil
}

// redeployStack runs docker stack deploy to apply the updated compose file.
func (c *FileBrowserClient) redeployStack(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
		"-c", c.composeFile,
		c.stackName,
		"--resolve-image", "never",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("stack deploy failed: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// doSync updates the Dufs admin password by modifying the compose file
// and redeploying the Swarm stack.
func (c *FileBrowserClient) doSync(newPassword string) error {
	l := log.With().Str("component", "filebrowser-sync").Logger()

	// Step 1: Update the compose file
	if err := c.updateComposePassword(newPassword); err != nil {
		return fmt.Errorf("update compose: %w", err)
	}
	l.Debug().Msg("updated Dufs password in docker-compose.yml")

	// Step 2: Redeploy the stack
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := c.redeployStack(ctx); err != nil {
		return fmt.Errorf("redeploy: %w", err)
	}

	l.Info().Msg("Dufs file manager password synced successfully (compose + stack deploy)")
	return nil
}

// SyncAdminPassword updates the Dufs admin password. Non-fatal wrapper.
// The currentPassword parameter is ignored — Dufs doesn't need it for
// password changes (we update the compose file directly).
func (c *FileBrowserClient) SyncAdminPassword(currentPassword, newPassword string) {
	l := log.With().Str("component", "filebrowser-sync").Logger()

	if err := c.doSync(newPassword); err != nil {
		l.Warn().Err(err).Msg("Dufs password sync skipped")
	}
}

// SyncAdminPasswordWithRetry retries the password sync with backoff.
// Used during first boot when the stack may still be starting up.
// Designed to run as a goroutine — non-blocking, non-fatal.
//
// Retry schedule: 5s, 10s, 15s, 20s, 25s, 30s (6 attempts over ~2 min).
func (c *FileBrowserClient) SyncAdminPasswordWithRetry(currentPassword, newPassword string) {
	l := log.With().Str("component", "filebrowser-sync").Logger()

	const maxAttempts = 6
	backoff := 5 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := c.doSync(newPassword)
		if err == nil {
			return
		}

		if attempt == maxAttempts {
			l.Warn().Err(err).
				Int("attempts", maxAttempts).
				Msg("Dufs password sync failed after all retries")
			return
		}

		l.Debug().Err(err).
			Int("attempt", attempt).
			Dur("next_retry", backoff).
			Msg("Dufs not ready, will retry")

		time.Sleep(backoff)
		backoff += 5 * time.Second
	}
}

// EnsurePasswordSynced reads the admin password from the setup config in the
// database and syncs it to Dufs if needed. Uses HTTP Basic Auth to verify
// the current password.
//
// Called once during API startup as a background goroutine.
// Non-fatal — logs warnings on failure but never blocks the API.
func (c *FileBrowserClient) EnsurePasswordSynced(dbConn *sql.DB) {
	l := log.With().Str("component", "filebrowser-sync").Logger()

	// Only run if setup is complete
	var isComplete int
	if err := dbConn.QueryRow(`SELECT is_complete FROM setup_status WHERE id = 1`).Scan(&isComplete); err != nil {
		l.Debug().Err(err).Msg("cannot read setup_status — skipping Dufs sync")
		return
	}
	if isComplete != 1 {
		l.Debug().Msg("setup not complete — skipping Dufs sync")
		return
	}

	// Read the admin_password from setup config JSON
	var configJSON sql.NullString
	if err := dbConn.QueryRow(`SELECT config_json FROM setup_status WHERE id = 1`).Scan(&configJSON); err != nil || !configJSON.Valid || configJSON.String == "" {
		l.Debug().Msg("no setup config_json — skipping Dufs sync")
		return
	}

	var cfg models.SetupConfig
	if err := json.Unmarshal([]byte(configJSON.String), &cfg); err != nil {
		l.Warn().Err(err).Msg("failed to parse setup config_json")
		return
	}

	if cfg.AdminPassword == "" {
		l.Debug().Msg("no admin_password in setup config — skipping Dufs sync")
		return
	}

	// Quick check: does the compose file already have the correct password?
	if c.readCurrentPassword() == cfg.AdminPassword {
		l.Debug().Msg("Dufs password in compose already matches CubeOS — startup sync not needed")
		return
	}

	// Wait for the stack to be ready
	time.Sleep(5 * time.Second)

	l.Info().Msg("Dufs password out of sync — attempting startup resync")
	c.SyncAdminPasswordWithRetry("", cfg.AdminPassword)
}

// IsAvailable checks if the Dufs service is reachable.
func (c *FileBrowserClient) IsAvailable() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Dufs returns 401 if auth required (still means it's up)
	return resp.StatusCode < 500
}
