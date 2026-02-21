package managers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"cubeos-api/internal/models"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
)

// PiholePasswordClient manages password sync with the Pi-hole v6 web UI.
// Changes the password by computing the double-SHA256 hash and writing it
// directly to pihole.toml, then restarting the container.
//
// Password sync happens at three points:
//   - First boot: setup.go calls SyncAdminPasswordWithRetry("cubeos", newPassword)
//   - Password change: handlers.go calls SyncAdminPassword(currentPassword, newPassword)
//   - API startup: main.go calls EnsurePasswordSynced(db) to catch missed syncs
type PiholePasswordClient struct {
	containerName string
	tomlPath      string // /cubeos/coreapps/pihole/appdata/etc-pihole/pihole.toml
	envFilePath   string // /cubeos/coreapps/pihole/appconfig/.env
	secretsPath   string // /cubeos/config/secrets.env
}

// pwhashRegex matches the pwhash line in pihole.toml.
// Handles both quoted and unquoted values, with optional whitespace.
var pwhashRegex = regexp.MustCompile(`(?m)^(\s*pwhash\s*=\s*)("?)[a-fA-F0-9]*("?)\s*$`)

// NewPiholePasswordClient creates a new Pi-hole password sync client.
func NewPiholePasswordClient() *PiholePasswordClient {
	return &PiholePasswordClient{
		containerName: "cubeos-pihole",
		tomlPath:      "/cubeos/coreapps/pihole/appdata/etc-pihole/pihole.toml",
		envFilePath:   "/cubeos/coreapps/pihole/appconfig/.env",
		secretsPath:   "/cubeos/config/secrets.env",
	}
}

// piholePasswordHash computes Pi-hole v6's double-SHA256 password hash.
// Format: lowercase_hex(SHA256(lowercase_hex(SHA256(password))))
func piholePasswordHash(password string) string {
	h1 := sha256.Sum256([]byte(password))
	hex1 := fmt.Sprintf("%x", h1)
	h2 := sha256.Sum256([]byte(hex1))
	return fmt.Sprintf("%x", h2)
}

// doSync changes the Pi-hole web UI password by writing the hash directly
// to pihole.toml and restarting the container.
func (c *PiholePasswordClient) doSync(newPassword string) error {
	l := log.With().Str("component", "pihole-sync").Logger()

	// Compute the double-SHA256 hash
	pwhash := piholePasswordHash(newPassword)

	// Read current pihole.toml
	data, err := os.ReadFile(c.tomlPath)
	if err != nil {
		return fmt.Errorf("cannot read pihole.toml: %w", err)
	}

	content := string(data)

	// Replace the pwhash value
	if pwhashRegex.MatchString(content) {
		content = pwhashRegex.ReplaceAllString(content, fmt.Sprintf(`${1}"%s"`, pwhash))
	} else if strings.Contains(content, "[webserver.api]") {
		// pwhash line doesn't exist yet — insert after [webserver.api] section header
		content = strings.Replace(content, "[webserver.api]",
			fmt.Sprintf("[webserver.api]\n  pwhash = \"%s\"", pwhash), 1)
	} else if strings.Contains(content, "[webserver]") {
		// No [webserver.api] section — insert it after [webserver]
		content = strings.Replace(content, "[webserver]",
			fmt.Sprintf("[webserver]\n\n[webserver.api]\n  pwhash = \"%s\"", pwhash), 1)
	} else {
		// Fallback: append to end of file
		content += fmt.Sprintf("\n[webserver.api]\n  pwhash = \"%s\"\n", pwhash)
	}

	// Write back
	if err := os.WriteFile(c.tomlPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("cannot write pihole.toml: %w", err)
	}

	l.Debug().Msg("updated pwhash in pihole.toml")

	// Restart Pi-hole container to pick up the new config
	if err := c.restartContainer(); err != nil {
		l.Warn().Err(err).Msg("failed to restart pihole container (password will apply on next restart)")
	}

	// Persist to .env file (survives container recreations via docker-compose)
	if err := updateEnvFileEntry(c.envFilePath, "PIHOLE_PASSWORD", newPassword); err != nil {
		l.Warn().Err(err).Msg("failed to update pihole .env file")
	}

	// Persist to secrets.env
	if err := updateEnvFileEntry(c.secretsPath, "CUBEOS_PIHOLE_PASSWORD", newPassword); err != nil {
		l.Warn().Err(err).Msg("failed to update secrets.env")
	}

	l.Info().Msg("Pi-hole web password synced successfully")
	return nil
}

// restartContainer restarts the cubeos-pihole container via Docker API.
func (c *PiholePasswordClient) restartContainer() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()

	timeout := 10
	return cli.ContainerRestart(ctx, c.containerName, container.StopOptions{Timeout: &timeout})
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
// database and syncs it to Pi-hole if needed. This catches the case where
// first-boot sync failed and the API restarted.
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

	// Check if Pi-hole already has the correct password hash in pihole.toml
	expectedHash := piholePasswordHash(cfg.AdminPassword)
	if data, err := os.ReadFile(c.tomlPath); err == nil {
		if strings.Contains(string(data), expectedHash) {
			l.Debug().Msg("Pi-hole pwhash already matches CubeOS — startup sync not needed")
			return
		}
	}

	// Wait for Pi-hole container to be ready
	time.Sleep(5 * time.Second)

	l.Info().Msg("Pi-hole password out of sync — attempting startup resync")
	c.SyncAdminPasswordWithRetry("cubeos", cfg.AdminPassword)
}
