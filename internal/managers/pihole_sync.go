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
//
// Pi-hole v6 uses FTLCONF_webserver_api_password env var to set the password.
// When this env var is set, `pihole setpassword` is BLOCKED (exit code 5).
// Therefore we sync by updating PIHOLE_PASSWORD in the .env file and
// restarting the container — Pi-hole generates the correct Balloon-SHA256
// hash from the env var on startup.
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

// restartContainer restarts the cubeos-pihole container via Docker API.
// Pi-hole re-reads FTLCONF_webserver_api_password on startup, generating
// the correct Balloon-SHA256 hash from the env var value.
func (c *PiholePasswordClient) restartContainer(ctx context.Context) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()

	timeout := 10
	if err := cli.ContainerRestart(ctx, c.containerName, container.StopOptions{Timeout: &timeout}); err != nil {
		return fmt.Errorf("container restart failed: %w", err)
	}

	return nil
}

// doSync changes the Pi-hole web UI password by updating the .env file
// (which feeds FTLCONF_webserver_api_password via docker-compose) and
// restarting the container so Pi-hole regenerates the Balloon-SHA256 hash.
func (c *PiholePasswordClient) doSync(newPassword string) error {
	l := log.With().Str("component", "pihole-sync").Logger()

	// Step 1: Update PIHOLE_PASSWORD in the pihole .env file.
	// The docker-compose maps this to FTLCONF_webserver_api_password.
	if err := updateEnvFileEntry(c.envFilePath, "PIHOLE_PASSWORD", newPassword); err != nil {
		return fmt.Errorf("failed to update pihole .env: %w", err)
	}
	l.Debug().Msg("updated PIHOLE_PASSWORD in .env")

	// Step 2: Persist to secrets.env (CubeOS reads this for startup sync)
	if err := updateEnvFileEntry(c.secretsPath, "CUBEOS_PIHOLE_PASSWORD", newPassword); err != nil {
		l.Warn().Err(err).Msg("failed to update secrets.env")
	}

	// Step 3: Restart Pi-hole container to pick up the new env var.
	// Pi-hole v6 reads FTLCONF_webserver_api_password on startup and
	// generates the correct Balloon-SHA256 hash internally.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := c.restartContainer(ctx); err != nil {
		return fmt.Errorf("restart: %w", err)
	}

	l.Info().Msg("Pi-hole web password synced successfully (env var + restart)")
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

	// Wait for Pi-hole container to be ready before checking password
	time.Sleep(10 * time.Second)

	// Check if Pi-hole already accepts the correct password via REST API
	if c.checkPassword(cfg.AdminPassword) {
		l.Debug().Msg("Pi-hole password already matches CubeOS — startup sync not needed")
		return
	}

	l.Info().Msg("Pi-hole password out of sync — attempting startup resync")
	c.SyncAdminPasswordWithRetry("cubeos", cfg.AdminPassword)
}

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
