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
	"time"

	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// PiholePasswordClient manages password sync with the Pi-hole v6 web UI.
//
// Pi-hole v6 uses FTLCONF_webserver_api_password env var to set the password.
// When this env var is set, `pihole setpassword` is BLOCKED (exit code 5).
// Therefore we sync by updating PIHOLE_PASSWORD in the .env file and
// recreating the container via `docker compose up -d` — this forces
// docker-compose to re-interpolate the env var. A plain `docker restart`
// does NOT re-read .env files.
//
// Password sync happens at three points:
//   - First boot: setup.go calls SyncAdminPasswordWithRetry("cubeos", newPassword)
//   - Password change: handlers.go calls SyncAdminPassword(currentPassword, newPassword)
//   - API startup: main.go calls EnsurePasswordSynced(db) to catch missed syncs
type PiholePasswordClient struct {
	containerName string
	apiURL        string // Pi-hole v6 REST API URL
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
	// Prefer DOCKER_HOST_GW (always reachable) over GATEWAY_IP (AP-only)
	gatewayIP := os.Getenv("DOCKER_HOST_GW")
	if gatewayIP == "" {
		gatewayIP = os.Getenv("GATEWAY_IP")
	}
	if gatewayIP == "" {
		gatewayIP = models.DefaultGatewayIP
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

// recreateContainer calls HAL to run `docker compose up -d` for Pi-hole.
// HAL runs on the host where the Docker Compose CLI plugin is available.
// The API container does not have docker compose installed.
//
// A plain `docker restart` does NOT re-read .env files — the container
// keeps the old environment from when it was first created.
func (c *PiholePasswordClient) recreateContainer(ctx context.Context) error {
	halURL := os.Getenv("HAL_URL")
	if halURL == "" {
		halURL = fmt.Sprintf("http://%s:6005/hal", models.DefaultGatewayIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, halURL+"/system/service/pihole/recreate", nil)
	if err != nil {
		return fmt.Errorf("create HAL request: %w", err)
	}

	// Add HAL authentication key if configured
	if halKey := os.Getenv("HAL_KEY"); halKey != "" {
		req.Header.Set("X-HAL-Key", halKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HAL recreate request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HAL recreate returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// doSync changes the Pi-hole web UI password by updating the .env file
// (which feeds FTLCONF_webserver_api_password via docker-compose) and
// recreating the container so Pi-hole regenerates the Balloon-SHA256 hash.
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

	// Step 3: Recreate Pi-hole container via docker compose up -d.
	// This forces docker-compose to re-interpolate the .env file,
	// passing the new PIHOLE_PASSWORD as FTLCONF_webserver_api_password.
	// Pi-hole v6 generates the Balloon-SHA256 hash from this env var on startup.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := c.recreateContainer(ctx); err != nil {
		return fmt.Errorf("recreate: %w", err)
	}

	l.Info().Msg("Pi-hole web password synced successfully (env var + compose recreate)")
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
