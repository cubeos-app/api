package managers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// NPM human admin email — the account created by first-boot, NOT the API service account.
const npmHumanAdminEmail = "admin@cubeos.cube"

// doSyncAdminPassword authenticates via service account and updates
// the human admin user's password to newPassword.
// Also persists the new password to .env and secrets.env files.
func (m *NPMManager) doSyncAdminPassword(newPassword string) error {
	l := log.With().Str("component", "npm-sync").Logger()

	// Ensure NPM manager is initialized (has a valid service account token)
	m.mu.RLock()
	ready := m.initialized
	m.mu.RUnlock()

	if !ready {
		return fmt.Errorf("NPMManager not initialized — cannot sync admin password")
	}

	// List users to find the human admin
	users, err := m.listUsers()
	if err != nil {
		return fmt.Errorf("failed to list NPM users: %w", err)
	}

	var adminUser *NPMUser
	for _, u := range users {
		if u.Email == npmHumanAdminEmail {
			adminUser = &u
			break
		}
	}

	if adminUser == nil {
		return fmt.Errorf("NPM human admin %s not found", npmHumanAdminEmail)
	}

	// NPM v2 PUT /api/users/{id} requires name, nickname, email, roles, is_disabled.
	// Use the exact values from the current user to avoid validation errors.
	// Ensure roles defaults to ["admin"] if empty.
	roles := adminUser.Roles
	if len(roles) == 0 {
		roles = []string{"admin"}
	}

	// NOTE: is_disabled must be sent as integer (0/1), not boolean.
	// NPM v2 returns 400 when it receives a JSON boolean for this field.
	update := map[string]interface{}{
		"name":        adminUser.Name,
		"nickname":    adminUser.Nickname,
		"email":       adminUser.Email,
		"roles":       roles,
		"is_disabled": 0,
		"secret":      newPassword,
	}

	resp, err := m.doRequest("PUT", fmt.Sprintf("/api/users/%d", adminUser.ID), update)
	if err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("NPM returned %d for admin password update: %s", resp.StatusCode, string(body))
	}

	// Persist to .env and secrets.env so the password survives restarts.
	// CUBEOS_NPM_PASSWORD is the HUMAN admin password — used by
	// bootstrapServiceAccount() to auth as admin, create service account.
	// After sync, this MUST be the new CubeOS password so bootstrap can
	// re-authenticate if the service account token expires.
	npmEnvPath := "/cubeos/coreapps/npm/.env"
	if err := updateEnvFileEntry(npmEnvPath, "NPM_ADMIN_PASSWORD", newPassword); err != nil {
		l.Warn().Err(err).Msg("failed to update npm .env file")
	}

	secretsPath := m.secretsFile
	if err := updateEnvFileEntry(secretsPath, "CUBEOS_NPM_PASSWORD", newPassword); err != nil {
		l.Warn().Err(err).Msg("failed to update secrets.env")
	}

	l.Info().Msg("NPM admin password synced successfully")
	return nil
}

// SyncAdminPassword changes the human admin password in NPM. Non-fatal wrapper.
func (m *NPMManager) SyncAdminPassword(currentPassword, newPassword string) {
	l := log.With().Str("component", "npm-sync").Logger()

	if err := m.doSyncAdminPassword(newPassword); err != nil {
		l.Warn().Err(err).Msg("NPM admin password sync skipped")
	}
}

// SyncAdminPasswordWithRetry retries the password sync with backoff.
// Used during first boot when NPM may still be initializing.
// Designed to run as a goroutine — non-blocking, non-fatal.
//
// Retry schedule: 5s, 10s, 15s, 20s, 25s, 30s (6 attempts over ~2 min).
func (m *NPMManager) SyncAdminPasswordWithRetry(currentPassword, newPassword string) {
	l := log.With().Str("component", "npm-sync").Logger()

	const maxAttempts = 6
	backoff := 5 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := m.doSyncAdminPassword(newPassword)
		if err == nil {
			return
		}

		if attempt == maxAttempts {
			l.Warn().Err(err).
				Int("attempts", maxAttempts).
				Msg("NPM admin password sync failed after all retries")
			return
		}

		l.Debug().Err(err).
			Int("attempt", attempt).
			Dur("next_retry", backoff).
			Msg("NPM not ready for admin sync, will retry")

		time.Sleep(backoff)
		backoff += 5 * time.Second
	}
}

// EnsureAdminPasswordSynced reads the admin password from setup config and
// syncs it to the NPM human admin account if needed.
//
// Called once during API startup as a background goroutine.
// Non-fatal — logs warnings on failure but never blocks the API.
func (m *NPMManager) EnsureAdminPasswordSynced(dbConn *sql.DB) {
	l := log.With().Str("component", "npm-sync").Logger()

	// Only run if setup is complete
	var isComplete int
	if err := dbConn.QueryRow(`SELECT is_complete FROM setup_status WHERE id = 1`).Scan(&isComplete); err != nil {
		l.Debug().Err(err).Msg("cannot read setup_status — skipping NPM admin sync")
		return
	}
	if isComplete != 1 {
		l.Debug().Msg("setup not complete — skipping NPM admin sync")
		return
	}

	// Read the admin_password from setup config JSON
	var configJSON sql.NullString
	if err := dbConn.QueryRow(`SELECT config_json FROM setup_status WHERE id = 1`).Scan(&configJSON); err != nil || !configJSON.Valid || configJSON.String == "" {
		l.Debug().Msg("no setup config_json — skipping NPM admin sync")
		return
	}

	var cfg models.SetupConfig
	if err := json.Unmarshal([]byte(configJSON.String), &cfg); err != nil {
		l.Warn().Err(err).Msg("failed to parse setup config_json")
		return
	}

	if cfg.AdminPassword == "" {
		l.Debug().Msg("no admin_password in setup config — skipping NPM admin sync")
		return
	}

	// Check if NPM admin password already matches by reading secrets.env
	if data, err := os.ReadFile(m.secretsFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "CUBEOS_NPM_PASSWORD=") {
				currentPw := strings.TrimPrefix(strings.TrimSpace(line), "CUBEOS_NPM_PASSWORD=")
				if currentPw == cfg.AdminPassword {
					l.Debug().Msg("NPM password in secrets.env already matches CubeOS — startup sync not needed")
					return
				}
			}
		}
	}

	// Wait for NPM to be ready (background init may still be running)
	time.Sleep(10 * time.Second)

	// Verify NPMManager is initialized before attempting sync
	m.mu.RLock()
	ready := m.initialized
	m.mu.RUnlock()
	if !ready {
		l.Warn().Msg("NPMManager not initialized after 10s — skipping admin password sync")
		return
	}

	l.Info().Msg("NPM admin password out of sync — attempting startup resync")
	m.SyncAdminPasswordWithRetry("", cfg.AdminPassword)
}

// updateEnvFileEntry updates or appends a key=value in an env file.
func updateEnvFileEntry(path, key, value string) error {
	var lines []string
	if data, err := os.ReadFile(path); err == nil {
		lines = strings.Split(string(data), "\n")
	}

	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+"=") {
			lines[i] = fmt.Sprintf("%s=%s", key, value)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}

	content := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0640)
}
