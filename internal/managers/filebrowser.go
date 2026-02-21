package managers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// FileBrowserClient manages credentials sync with the File Browser service.
// File Browser uses a non-standard X-Auth header (not Authorization: Bearer)
// and a unique envelope format for user updates.
//
// Password sync happens at three points:
//   - First boot: setup.go calls SyncAdminPasswordWithRetry("admin", newPassword)
//   - Password change: handlers.go calls SyncAdminPassword(oldPassword, newPassword)
//   - API startup: main.go calls EnsurePasswordSynced(db) to catch missed first-boot syncs
type FileBrowserClient struct {
	baseURL    string
	httpClient *http.Client
}

// FileBrowser minimum password length (enforced server-side by FB).
const fbMinPasswordLength = 6

// fbLoginRequest is the File Browser login payload.
type fbLoginRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Recaptcha string `json:"recaptcha"`
}

// fbUserUpdateRequest is the File Browser envelope format for user updates.
type fbUserUpdateRequest struct {
	What  string   `json:"what"`
	Which []string `json:"which"`
	Data  fbUser   `json:"data"`
}

// fbUser represents a File Browser user (subset of fields we care about).
type fbUser struct {
	ID           uint          `json:"id"`
	Username     string        `json:"username"`
	Password     string        `json:"password,omitempty"`
	Scope        string        `json:"scope"`
	Locale       string        `json:"locale"`
	ViewMode     string        `json:"viewMode"`
	SingleClick  bool          `json:"singleClick"`
	Perm         fbPermissions `json:"perm"`
	Commands     []string      `json:"commands"`
	LockPassword bool          `json:"lockPassword"`
}

// fbPermissions represents File Browser user permissions.
type fbPermissions struct {
	Admin    bool `json:"admin"`
	Execute  bool `json:"execute"`
	Create   bool `json:"create"`
	Rename   bool `json:"rename"`
	Modify   bool `json:"modify"`
	Delete   bool `json:"delete"`
	Share    bool `json:"share"`
	Download bool `json:"download"`
}

// NewFileBrowserClient creates a new File Browser API client.
// baseURL should be the full URL to the File Browser instance, e.g. "http://10.42.24.1:6013".
func NewFileBrowserClient(baseURL string) *FileBrowserClient {
	return &FileBrowserClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// login authenticates with File Browser and returns a JWT token.
// File Browser returns the token as raw text (not JSON-wrapped).
func (c *FileBrowserClient) login(username, password string) (string, error) {
	body, err := json.Marshal(fbLoginRequest{
		Username:  username,
		Password:  password,
		Recaptcha: "",
	})
	if err != nil {
		return "", fmt.Errorf("marshal login request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	tokenBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login returned %d: %s", resp.StatusCode, string(tokenBytes))
	}

	token := string(tokenBytes)
	if token == "" {
		return "", fmt.Errorf("empty token returned")
	}

	return token, nil
}

// getUser fetches a user by ID from File Browser.
func (c *FileBrowserClient) getUser(token string, userID uint) (*fbUser, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/users/%d", c.baseURL, userID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth", token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get user request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get user returned %d: %s", resp.StatusCode, string(body))
	}

	var user fbUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decode user response: %w", err)
	}

	return &user, nil
}

// updatePassword changes a user's password via the File Browser API.
// The password is sent as plaintext; File Browser hashes it server-side with bcrypt.
func (c *FileBrowserClient) updatePassword(token string, user *fbUser, newPassword string) error {
	user.Password = newPassword

	payload := fbUserUpdateRequest{
		What:  "user",
		Which: []string{"password"},
		Data:  *user,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal update request: %w", err)
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/users/%d", c.baseURL, user.ID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// doSync performs the actual login → fetch user → update password sequence.
// Returns nil on success, error otherwise.
func (c *FileBrowserClient) doSync(currentPassword, newPassword string) error {
	l := log.With().Str("component", "filebrowser-sync").Logger()

	if len(newPassword) < fbMinPasswordLength {
		return fmt.Errorf("password too short for File Browser (need %d+ chars, got %d)",
			fbMinPasswordLength, len(newPassword))
	}

	// Try authentication with multiple passwords (in order of likelihood)
	passwords := []string{currentPassword, "admin", newPassword}
	var token string
	var loginErr error

	for _, pw := range passwords {
		token, loginErr = c.login("admin", pw)
		if loginErr == nil {
			if pw == newPassword {
				// Already synced — password matches, nothing to do
				l.Debug().Msg("File Browser password already matches CubeOS — no sync needed")
				return nil
			}
			break
		}
	}

	if loginErr != nil {
		return fmt.Errorf("failed to authenticate with File Browser: %w", loginErr)
	}

	// Fetch current user to preserve existing fields (scope, permissions, etc.)
	user, err := c.getUser(token, 1)
	if err != nil {
		return fmt.Errorf("failed to fetch admin user: %w", err)
	}

	// Update password
	if err := c.updatePassword(token, user, newPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	l.Info().Msg("File Browser admin password synced successfully")
	return nil
}

// SyncAdminPassword updates the File Browser admin (user ID 1) password.
// It authenticates with currentPassword, then updates to newPassword.
// This is non-fatal — errors are logged but don't propagate to the caller.
//
// Flow:
//  1. Try login with admin/currentPassword
//  2. If that fails, try admin/admin (File Browser default)
//  3. If that fails, try admin/newPassword (already synced)
//  4. Fetch user 1 to get current fields
//  5. PUT user 1 with new password
func (c *FileBrowserClient) SyncAdminPassword(currentPassword, newPassword string) {
	l := log.With().Str("component", "filebrowser-sync").Logger()

	if err := c.doSync(currentPassword, newPassword); err != nil {
		l.Warn().Err(err).Msg("password sync skipped")
	}
}

// SyncAdminPasswordWithRetry retries the password sync with backoff.
// Used during first boot when FileBrowser may still be starting up.
// Designed to run as a goroutine — non-blocking, non-fatal.
//
// Retry schedule: 5s, 10s, 15s, 20s, 25s, 30s (6 attempts over ~2 min).
func (c *FileBrowserClient) SyncAdminPasswordWithRetry(currentPassword, newPassword string) {
	l := log.With().Str("component", "filebrowser-sync").Logger()

	const maxAttempts = 6
	backoff := 5 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := c.doSync(currentPassword, newPassword)
		if err == nil {
			return // Success
		}

		if attempt == maxAttempts {
			l.Warn().Err(err).
				Int("attempts", maxAttempts).
				Msg("File Browser password sync failed after all retries — user may need to log in with default password 'admin'")
			return
		}

		l.Debug().Err(err).
			Int("attempt", attempt).
			Dur("next_retry", backoff).
			Msg("File Browser not ready, will retry")

		time.Sleep(backoff)
		backoff += 5 * time.Second
	}
}

// EnsurePasswordSynced reads the admin password from the setup config in the
// database and syncs it to File Browser if needed. This catches the case where
// first-boot sync failed (e.g. FileBrowser wasn't ready) and the API restarted.
//
// Called once during API startup as a background goroutine.
// Non-fatal — logs warnings on failure but never blocks the API.
func (c *FileBrowserClient) EnsurePasswordSynced(dbConn *sql.DB) {
	l := log.With().Str("component", "filebrowser-sync").Logger()

	// Only run if setup is complete (otherwise first-boot flow handles it)
	var isComplete int
	if err := dbConn.QueryRow(`SELECT is_complete FROM setup_status WHERE id = 1`).Scan(&isComplete); err != nil {
		l.Debug().Err(err).Msg("cannot read setup_status — skipping startup sync")
		return
	}
	if isComplete != 1 {
		l.Debug().Msg("setup not complete — skipping startup FileBrowser sync")
		return
	}

	// Read the admin_password from setup config JSON
	var configJSON sql.NullString
	if err := dbConn.QueryRow(`SELECT config_json FROM setup_status WHERE id = 1`).Scan(&configJSON); err != nil || !configJSON.Valid || configJSON.String == "" {
		l.Debug().Msg("no setup config_json found — skipping startup sync")
		return
	}

	var cfg models.SetupConfig
	if err := json.Unmarshal([]byte(configJSON.String), &cfg); err != nil {
		l.Warn().Err(err).Msg("failed to parse setup config_json")
		return
	}

	if cfg.AdminPassword == "" {
		l.Debug().Msg("no admin_password in setup config — skipping startup sync")
		return
	}

	// Wait a moment for FileBrowser to be ready (it starts with Swarm, may need time)
	time.Sleep(5 * time.Second)

	// Quick check: can we log in with the target password already? If yes, we're good.
	if _, err := c.login("admin", cfg.AdminPassword); err == nil {
		l.Debug().Msg("File Browser password already matches CubeOS — startup sync not needed")
		return
	}

	// Try syncing — File Browser likely still has the default "admin" password
	l.Info().Msg("File Browser password out of sync — attempting startup resync")
	c.SyncAdminPasswordWithRetry("admin", cfg.AdminPassword)
}

// IsAvailable checks if the File Browser service is reachable.
func (c *FileBrowserClient) IsAvailable() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		// File Browser doesn't have /health, try root
		resp, err = c.httpClient.Get(c.baseURL + "/")
		if err != nil {
			return false
		}
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
}
