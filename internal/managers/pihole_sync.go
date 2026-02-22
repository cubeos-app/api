package managers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"cubeos-api/internal/models"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
)

// PiholePasswordClient manages password sync with the Pi-hole v6 web UI.
// Uses Docker exec to run `pihole setpassword` which produces the correct
// Balloon-SHA256 hash that Pi-hole v6 expects (NOT double-SHA256).
//
// Password sync happens at three points:
//   - First boot: setup.go calls SyncAdminPasswordWithRetry("cubeos", newPassword)
//   - Password change: handlers.go calls SyncAdminPassword(currentPassword, newPassword)
//   - API startup: main.go calls EnsurePasswordSynced(db) to catch missed syncs
type PiholePasswordClient struct {
	containerName string
	apiURL        string // http://10.42.24.1:6001
	envFilePath   string // /cubeos/coreapps/pihole/appconfig/.env (docker-compose .env)
	secretsPath   string // /cubeos/config/secrets.env
	httpClient    *http.Client
}

// NewPiholePasswordClient creates a new Pi-hole password sync client.
func NewPiholePasswordClient() *PiholePasswordClient {
	// Read pihole port from env (defaults.env sets PIHOLE_PORT=6001)
	piholePort := os.Getenv("PIHOLE_PORT")
	if piholePort == "" {
		piholePort = "6001"
	}
	gatewayIP := os.Getenv("GATEWAY_IP")
	if gatewayIP == "" {
		gatewayIP = "10.42.24.1"
	}

	return &PiholePasswordClient{
		containerName: "cubeos-pihole",
		apiURL:        fmt.Sprintf("http://%s:%s", gatewayIP, piholePort),
		envFilePath:   "/cubeos/coreapps/pihole/appconfig/.env",
		secretsPath:   "/cubeos/config/secrets.env",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// checkPassword verifies if the given password works for Pi-hole v6 web UI
// by attempting to authenticate via the Pi-hole v6 REST API.
func (c *PiholePasswordClient) checkPassword(password string) bool {
	body, _ := json.Marshal(map[string]string{"password": password})
	req, err := http.NewRequest("POST", c.apiURL+"/api/auth", bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	// Pi-hole v6 returns 200 with session data on successful auth
	return resp.StatusCode == http.StatusOK
}

// setPasswordViaExec runs `pihole setpassword <password>` inside the Pi-hole
// container via Docker exec. This produces the correct Balloon-SHA256 hash
// and FTL auto-reloads the config — no container restart needed.
func (c *PiholePasswordClient) setPasswordViaExec(ctx context.Context, newPassword string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()

	// Create exec instance
	execCreate, err := cli.ContainerExecCreate(ctx, c.containerName, container.ExecOptions{
		Cmd:          []string{"pihole", "setpassword", newPassword},
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return fmt.Errorf("exec create failed (is cubeos-pihole running?): %w", err)
	}

	// Start exec and wait for completion
	if err := cli.ContainerExecStart(ctx, execCreate.ID, container.ExecStartOptions{}); err != nil {
		return fmt.Errorf("exec start failed: %w", err)
	}

	// Wait for the command to finish (pihole setpassword is fast)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		inspect, err := cli.ContainerExecInspect(ctx, execCreate.ID)
		if err != nil {
			return fmt.Errorf("exec inspect failed: %w", err)
		}
		if !inspect.Running {
			if inspect.ExitCode != 0 {
				return fmt.Errorf("pihole setpassword exited with code %d", inspect.ExitCode)
			}
			return nil // Success
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("pihole setpassword timed out after 10s")
}

// doSync changes the Pi-hole web UI password using Docker exec.
// Also persists the password to .env and secrets.env for compose recreation.
func (c *PiholePasswordClient) doSync(newPassword string) error {
	l := log.With().Str("component", "pihole-sync").Logger()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set password via Docker exec (correct Balloon-SHA256 hashing)
	if err := c.setPasswordViaExec(ctx, newPassword); err != nil {
		return fmt.Errorf("setpassword exec: %w", err)
	}

	l.Debug().Msg("Pi-hole password set via docker exec")

	// Persist to .env file — docker-compose auto-reads .env in the compose
	// directory, so PIHOLE_PASSWORD survives container recreation via
	// FTLCONF_webserver_api_password=${PIHOLE_PASSWORD:-cubeos} in compose.
	if err := updateEnvFileEntry(c.envFilePath, "PIHOLE_PASSWORD", newPassword); err != nil {
		l.Warn().Err(err).Msg("failed to update pihole .env file")
	}

	// Persist to secrets.env (CubeOS reads this for startup sync)
	if err := updateEnvFileEntry(c.secretsPath, "CUBEOS_PIHOLE_PASSWORD", newPassword); err != nil {
		l.Warn().Err(err).Msg("failed to update secrets.env")
	}

	l.Info().Msg("Pi-hole web password synced successfully")
	return nil
}

// SyncAdminPassword changes the Pi-hole web password. Non-fatal wrapper.
func (c *PiholePasswordClient) SyncAdminPassword(currentPassword, newPassword string) {
	l := log.With().Str("component", "pihole-sync").Logger()

	if err := c.doSync(newPassword); err != nil {
		l.Warn().Err(err).Msg("Pi-hole password sync skipped")
	}
}

// SyncAdminPasswordWithRetry retries the password sync with backoff.
// Used during first boot when Pi-hole may still be starting up.
// Designed to run as a goroutine — non-blocking, non-fatal.
//
// Retry schedule: 5s, 10s, 15s, 20s, 25s, 30s (6 attempts over ~2 min).
func (c *PiholePasswordClient) SyncAdminPasswordWithRetry(currentPassword, newPassword string) {
	l := log.With().Str("component", "pihole-sync").Logger()

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
				Msg("Pi-hole password sync failed after all retries")
			return
		}

		l.Debug().Err(err).
			Int("attempt", attempt).
			Dur("next_retry", backoff).
			Msg("Pi-hole not ready, will retry")

		time.Sleep(backoff)
		backoff += 5 * time.Second
	}
}

// EnsurePasswordSynced reads the admin password from the setup config in the
// database and syncs it to Pi-hole if needed. Uses the Pi-hole REST API to
// verify the current password rather than comparing hashes.
//
// Called once during API startup as a background goroutine.
// Non-fatal — logs warnings on failure but never blocks the API.
func (c *PiholePasswordClient) EnsurePasswordSynced(dbConn *sql.DB) {
	l := log.With().Str("component", "pihole-sync").Logger()

	// Only run if setup is complete
	var isComplete int
	if err := dbConn.QueryRow(`SELECT is_complete FROM setup_status WHERE id = 1`).Scan(&isComplete); err != nil {
		l.Debug().Err(err).Msg("cannot read setup_status — skipping Pi-hole sync")
		return
	}
	if isComplete != 1 {
		l.Debug().Msg("setup not complete — skipping Pi-hole sync")
		return
	}

	// Read the admin_password from setup config JSON
	var configJSON sql.NullString
	if err := dbConn.QueryRow(`SELECT config_json FROM setup_status WHERE id = 1`).Scan(&configJSON); err != nil || !configJSON.Valid || configJSON.String == "" {
		l.Debug().Msg("no setup config_json — skipping Pi-hole sync")
		return
	}

	var cfg models.SetupConfig
	if err := json.Unmarshal([]byte(configJSON.String), &cfg); err != nil {
		l.Warn().Err(err).Msg("failed to parse setup config_json")
		return
	}

	if cfg.AdminPassword == "" {
		l.Debug().Msg("no admin_password in setup config — skipping Pi-hole sync")
		return
	}

	// Wait for Pi-hole container to be ready
	time.Sleep(10 * time.Second)

	// Check if Pi-hole already accepts the correct password via REST API
	if c.checkPassword(cfg.AdminPassword) {
		l.Debug().Msg("Pi-hole password already matches CubeOS — startup sync not needed")
		return
	}

	l.Info().Msg("Pi-hole password out of sync — attempting startup resync")
	c.SyncAdminPasswordWithRetry("cubeos", cfg.AdminPassword)
}

// Keep updateEnvFileEntry in npm_sync.go (shared utility).
// It's defined there since npm_sync.go was the original location.
// Both pihole_sync.go and filebrowser.go reference it.

// isContainerRunning checks if a Docker container exists and is running.
func isContainerRunning(containerName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return false
	}

	for _, c := range containers {
		for _, name := range c.Names {
			if strings.TrimPrefix(name, "/") == containerName {
				return true
			}
		}
	}
	return false
}
