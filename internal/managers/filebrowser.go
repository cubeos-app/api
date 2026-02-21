package managers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// FileBrowserClient manages credentials sync with the File Browser service.
// File Browser uses a non-standard X-Auth header (not Authorization: Bearer)
// and a unique envelope format for user updates.
type FileBrowserClient struct {
	baseURL    string
	httpClient *http.Client
}

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

	// Try authentication with multiple passwords (in order of likelihood)
	passwords := []string{currentPassword, "admin", newPassword}
	var token string
	var loginErr error

	for _, pw := range passwords {
		token, loginErr = c.login("admin", pw)
		if loginErr == nil {
			break
		}
	}

	if loginErr != nil {
		l.Warn().Err(loginErr).Msg("failed to authenticate with File Browser — password sync skipped")
		return
	}

	// Fetch current user to preserve existing fields (scope, permissions, etc.)
	user, err := c.getUser(token, 1)
	if err != nil {
		l.Warn().Err(err).Msg("failed to fetch File Browser admin user")
		return
	}

	// Update password
	if err := c.updatePassword(token, user, newPassword); err != nil {
		l.Warn().Err(err).Msg("failed to update File Browser admin password")
		return
	}

	l.Info().Msg("File Browser admin password synced successfully")
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
