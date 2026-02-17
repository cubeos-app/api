package managers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cubeos-api/internal/config"

	"github.com/rs/zerolog/log"
)

// NPMManager handles Nginx Proxy Manager API interactions
// Uses service account pattern: api@cubeos.cube for API operations
// Human admin account is separate and can change password freely
type NPMManager struct {
	baseURL     string
	gatewayIP   string
	token       string
	tokenFile   string
	secretsFile string
	configDir   string
	httpClient  *http.Client
	mu          sync.RWMutex
	initialized bool
}

// NPM credential constants
const (
	// Service account for API operations (hidden from UI users)
	npmServiceEmail = "api@cubeos.cube"
	npmServiceName  = "CubeOS API"

	// Secrets.env keys
	npmAPIPasswordKey = "NPM_API_PASSWORD"

	// Bootstrap admin credentials
	// first-boot.sh writes CUBEOS_NPM_EMAIL/CUBEOS_NPM_PASSWORD to secrets.env
	// Setup wizard writes NPM_ADMIN_EMAIL/NPM_ADMIN_PASSWORD to npm/.env
	// We check both naming conventions for compatibility
	npmBootstrapEmailKey    = "CUBEOS_NPM_EMAIL"
	npmBootstrapPasswordKey = "CUBEOS_NPM_PASSWORD"

	// Legacy env var names (wizard / backward compat)
	npmBootstrapEmailKeyLegacy    = "NPM_ADMIN_EMAIL"
	npmBootstrapPasswordKeyLegacy = "NPM_ADMIN_PASSWORD"
)

// FlexBool handles NPM API returning enabled as bool or int
type FlexBool bool

func (fb *FlexBool) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*fb = FlexBool(b)
		return nil
	}
	var i int
	if err := json.Unmarshal(data, &i); err == nil {
		*fb = FlexBool(i != 0)
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s into FlexBool", string(data))
}

func (fb FlexBool) MarshalJSON() ([]byte, error) {
	return json.Marshal(bool(fb))
}

// NPMProxyHostExtended represents a proxy host in NPM with full API fields
// Note: This is separate from NPMProxyHost in appstore.go which has fewer fields
type NPMProxyHostExtended struct {
	ID                    int      `json:"id,omitempty"`
	CreatedOn             string   `json:"created_on,omitempty"`
	ModifiedOn            string   `json:"modified_on,omitempty"`
	DomainNames           []string `json:"domain_names"`
	ForwardScheme         string   `json:"forward_scheme"`
	ForwardHost           string   `json:"forward_host"`
	ForwardPort           int      `json:"forward_port"`
	CertificateID         int      `json:"certificate_id"`
	SSLForced             bool     `json:"ssl_forced"`
	HSTSEnabled           bool     `json:"hsts_enabled"`
	HSTSSubdomains        bool     `json:"hsts_subdomains"`
	HTTP2Support          bool     `json:"http2_support"`
	BlockExploits         bool     `json:"block_exploits"`
	CachingEnabled        bool     `json:"caching_enabled"`
	AllowWebsocketUpgrade bool     `json:"allow_websocket_upgrade"`
	AccessListID          int      `json:"access_list_id"`
	AdvancedConfig        string   `json:"advanced_config"`
	Enabled               FlexBool `json:"enabled"`
	Meta                  NPMMeta  `json:"meta"`
	Locations             []any    `json:"locations"`
}

// NPMMeta contains metadata for proxy hosts
type NPMMeta struct {
	LetsencryptAgree bool `json:"letsencrypt_agree"`
	DNSChallenge     bool `json:"dns_challenge"`
}

// NPMUser represents a user in NPM
// NOTE: NPM v3 changed is_disabled from int to bool. Using interface{}
// handles both formats during unmarshal (B56 fix).
type NPMUser struct {
	ID         int         `json:"id,omitempty"`
	CreatedOn  string      `json:"created_on,omitempty"`
	ModifiedOn string      `json:"modified_on,omitempty"`
	Name       string      `json:"name"`
	Nickname   string      `json:"nickname"`
	Email      string      `json:"email"`
	Avatar     string      `json:"avatar,omitempty"`
	IsDisabled interface{} `json:"is_disabled"`
	Roles      []string    `json:"roles"`
}

// NPMCreateUser is the request body for creating a user
type NPMCreateUser struct {
	Name       string   `json:"name"`
	Nickname   string   `json:"nickname"`
	Email      string   `json:"email"`
	Roles      []string `json:"roles"`
	IsDisabled bool     `json:"is_disabled"`
	Secret     string   `json:"secret,omitempty"`
}

// NewNPMManager creates a new NPM manager using centralized config
func NewNPMManager(cfg *config.Config, configDir string) *NPMManager {
	return &NPMManager{
		baseURL:     cfg.GetNPMURL(),
		gatewayIP:   cfg.GatewayIP,
		tokenFile:   filepath.Join(configDir, "npm_api_token"),
		secretsFile: filepath.Join(configDir, "secrets.env"),
		configDir:   configDir,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Init initializes the NPM manager with proper credential handling
// Priority order:
// 1. Try existing token from file
// 2. Try service account credentials from secrets.env
// 3. Bootstrap: create service account using admin credentials (with retry)
func (m *NPMManager) Init() error {
	// Step 1: Try existing token
	if m.tryLoadToken() {
		log.Info().Msg("NPM: using existing API token")
		m.initialized = true
		return nil
	}

	// Step 2: Try service account credentials from secrets.env
	if password := m.loadServiceAccountPassword(); password != "" {
		if err := m.authenticateServiceAccount(password); err == nil {
			log.Info().Msg("NPM: authenticated with service account")
			m.initialized = true
			return nil
		}
		log.Warn().Msg("NPM: service account auth failed, will try bootstrap")
	}

	// Step 3: Bootstrap with retry (NPM may not be ready yet on cold boot)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := m.bootstrapServiceAccount(); err != nil {
			lastErr = err
			log.Warn().Err(err).Int("attempt", attempt).Msg("NPM: bootstrap failed, retrying...")
			time.Sleep(time.Duration(attempt*10) * time.Second)
			continue
		}
		m.initialized = true
		return nil
	}

	log.Warn().Err(lastErr).Msg("NPM: bootstrap failed after 3 attempts, starting background retry")

	// Start background goroutine to keep trying
	go m.backgroundInit()

	// Don't return error - NPM integration is optional
	return nil
}

// backgroundInit retries NPM initialization periodically until success.
// This handles the case where NPM starts minutes after the API (cold boot).
func (m *NPMManager) backgroundInit() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for attempt := 0; attempt < 20; attempt++ { // Give up after ~10 minutes
		<-ticker.C

		m.mu.RLock()
		ready := m.initialized
		m.mu.RUnlock()
		if ready {
			return
		}

		// Try token first
		if m.tryLoadToken() {
			log.Info().Msg("NPM: background init succeeded with existing token")
			m.mu.Lock()
			m.initialized = true
			m.mu.Unlock()
			return
		}

		// Try service account password
		if password := m.loadServiceAccountPassword(); password != "" {
			if err := m.authenticateServiceAccount(password); err == nil {
				log.Info().Msg("NPM: background init authenticated with service account")
				m.mu.Lock()
				m.initialized = true
				m.mu.Unlock()
				return
			}
		}

		// Try full bootstrap
		if err := m.bootstrapServiceAccount(); err != nil {
			log.Debug().Err(err).Int("attempt", attempt+1).Msg("NPM: background init attempt failed")
			continue
		}

		log.Info().Int("attempt", attempt+1).Msg("NPM: background init bootstrap succeeded")
		m.mu.Lock()
		m.initialized = true
		m.mu.Unlock()
		return
	}

	log.Warn().Msg("NPM: background init gave up after 20 attempts (~10 min)")
}

// tryLoadToken attempts to load and verify existing token
func (m *NPMManager) tryLoadToken() bool {
	data, err := os.ReadFile(m.tokenFile)
	if err != nil || len(data) == 0 {
		return false
	}

	token := strings.TrimSpace(string(data))
	m.mu.Lock()
	m.token = token
	m.mu.Unlock()

	if m.verifyToken() {
		return true
	}

	// Token invalid, clear it
	m.mu.Lock()
	m.token = ""
	m.mu.Unlock()
	return false
}

// loadServiceAccountPassword reads the service account password from secrets.env
func (m *NPMManager) loadServiceAccountPassword() string {
	// First check environment variable (set from secrets.env by config loader)
	if password := os.Getenv(npmAPIPasswordKey); password != "" {
		return password
	}

	// Try to read directly from secrets.env file
	data, err := os.ReadFile(m.secretsFile)
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, npmAPIPasswordKey+"=") {
			return strings.TrimPrefix(line, npmAPIPasswordKey+"=")
		}
	}

	return ""
}

// authenticateServiceAccount logs in with the service account and saves token
func (m *NPMManager) authenticateServiceAccount(password string) error {
	return m.authenticate(npmServiceEmail, password)
}

// authenticate logs in with given credentials and saves token
func (m *NPMManager) authenticate(email, password string) error {
	payload := map[string]string{
		"identity": email,
		"secret":   password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal token request: %w", err)
	}

	resp, err := m.httpClient.Post(
		m.baseURL+"/api/tokens",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed (%s): %s", resp.Status, string(respBody))
	}

	var tokenResp NPMTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	m.mu.Lock()
	m.token = tokenResp.Token
	m.mu.Unlock()

	// Save token to file
	if err := m.saveToken(tokenResp.Token); err != nil {
		log.Warn().Err(err).Msg("NPM: failed to save token")
	}

	return nil
}

// saveToken persists the token to file
func (m *NPMManager) saveToken(token string) error {
	if err := os.MkdirAll(filepath.Dir(m.tokenFile), 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	return os.WriteFile(m.tokenFile, []byte(token), 0600)
}

// bootstrapServiceAccount creates the API service account using admin credentials
// This is called on first boot or when service account doesn't exist
func (m *NPMManager) bootstrapServiceAccount() error {
	// Get bootstrap (admin) credentials from environment
	// Try CUBEOS_NPM_* first (set by first-boot.sh), then NPM_ADMIN_* (set by wizard)
	adminEmail := os.Getenv(npmBootstrapEmailKey)
	if adminEmail == "" {
		adminEmail = os.Getenv(npmBootstrapEmailKeyLegacy)
	}
	adminPassword := os.Getenv(npmBootstrapPasswordKey)
	if adminPassword == "" {
		adminPassword = os.Getenv(npmBootstrapPasswordKeyLegacy)
	}

	if adminEmail == "" || adminPassword == "" {
		return fmt.Errorf("bootstrap credentials not configured (set %s/%s or %s/%s)",
			npmBootstrapEmailKey, npmBootstrapPasswordKey,
			npmBootstrapEmailKeyLegacy, npmBootstrapPasswordKeyLegacy)
	}

	log.Info().Msg("NPM: bootstrapping service account")

	// Step 1: Authenticate as admin
	if err := m.authenticate(adminEmail, adminPassword); err != nil {
		return fmt.Errorf("admin authentication failed: %w", err)
	}

	// Step 2: Check if service account already exists
	users, err := m.listUsers()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	for _, user := range users {
		if user.Email == npmServiceEmail {
			log.Info().Msg("NPM: service account already exists")
			// Service account exists but we don't have the password
			// Generate new password and update it
			return m.resetServiceAccountPassword()
		}
	}

	// Step 3: Generate random password for service account
	password, err := generateSecurePassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	// Step 4: Create service account
	if err := m.createServiceAccount(password); err != nil {
		return fmt.Errorf("failed to create service account: %w", err)
	}

	// Step 5: Save password to secrets.env
	if err := m.saveServiceAccountPassword(password); err != nil {
		return fmt.Errorf("failed to save service account password: %w", err)
	}

	// Step 6: Authenticate with service account
	if err := m.authenticateServiceAccount(password); err != nil {
		return fmt.Errorf("failed to authenticate service account: %w", err)
	}

	log.Info().Msg("NPM: service account bootstrap complete")
	return nil
}

// listUsers returns all NPM users (requires admin auth)
func (m *NPMManager) listUsers() ([]NPMUser, error) {
	resp, err := m.doRequest("GET", "/api/users", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list users: %s - %s", resp.Status, string(body))
	}

	var users []NPMUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users: %w", err)
	}

	return users, nil
}

// createServiceAccount creates the API service account
func (m *NPMManager) createServiceAccount(password string) error {
	user := NPMCreateUser{
		Name:       npmServiceName,
		Nickname:   "api",
		Email:      npmServiceEmail,
		Roles:      []string{"admin"},
		IsDisabled: false,
		Secret:     password,
	}

	resp, err := m.doRequest("POST", "/api/users", user)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create user: %s - %s", resp.Status, string(body))
	}

	return nil
}

// resetServiceAccountPassword generates new password and updates existing account
func (m *NPMManager) resetServiceAccountPassword() error {
	// Find the service account
	users, err := m.listUsers()
	if err != nil {
		return err
	}

	var serviceUser *NPMUser
	for _, u := range users {
		if u.Email == npmServiceEmail {
			serviceUser = &u
			break
		}
	}

	if serviceUser == nil {
		return fmt.Errorf("service account not found")
	}

	// Generate new password
	password, err := generateSecurePassword(32)
	if err != nil {
		return err
	}

	// Update password via API
	update := map[string]interface{}{
		"name":        serviceUser.Name,
		"nickname":    serviceUser.Nickname,
		"email":       serviceUser.Email,
		"roles":       serviceUser.Roles,
		"is_disabled": false,
		"secret":      password,
	}

	resp, err := m.doRequest("PUT", fmt.Sprintf("/api/users/%d", serviceUser.ID), update)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update password: %s - %s", resp.Status, string(body))
	}

	// Save new password
	if err := m.saveServiceAccountPassword(password); err != nil {
		return err
	}

	// Re-authenticate with new password
	return m.authenticateServiceAccount(password)
}

// saveServiceAccountPassword appends/updates the password in secrets.env
func (m *NPMManager) saveServiceAccountPassword(password string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(m.secretsFile), 0755); err != nil {
		return err
	}

	// Read existing content
	var lines []string
	if data, err := os.ReadFile(m.secretsFile); err == nil {
		lines = strings.Split(string(data), "\n")
	}

	// Update or add the password line
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, npmAPIPasswordKey+"=") {
			lines[i] = fmt.Sprintf("%s=%s", npmAPIPasswordKey, password)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("%s=%s", npmAPIPasswordKey, password))
	}

	// Write back
	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(m.secretsFile, []byte(content), 0600)
}

// generateSecurePassword generates a cryptographically secure password
func generateSecurePassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

// verifyToken checks if the current token is valid
func (m *NPMManager) verifyToken() bool {
	m.mu.RLock()
	token := m.token
	m.mu.RUnlock()

	if token == "" {
		return false
	}

	req, err := http.NewRequest("GET", m.baseURL+"/api/users/me", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// doRequest makes an authenticated request to NPM API
// If token is invalid, attempts to re-authenticate
func (m *NPMManager) doRequest(method, endpoint string, body interface{}) (*http.Response, error) {
	resp, err := m.doRequestOnce(method, endpoint, body)
	if err != nil {
		return nil, err
	}

	// If unauthorized, try to re-authenticate
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()

		// Try to re-authenticate
		if password := m.loadServiceAccountPassword(); password != "" {
			if err := m.authenticateServiceAccount(password); err == nil {
				// Retry the request with new token
				return m.doRequestOnce(method, endpoint, body)
			}
		}

		// Re-authentication failed, return an error
		return nil, fmt.Errorf("NPM authentication expired and re-authentication failed")
	}

	return resp, nil
}

// doRequestOnce makes a single authenticated request
func (m *NPMManager) doRequestOnce(method, endpoint string, body interface{}) (*http.Response, error) {
	m.mu.RLock()
	token := m.token
	m.mu.RUnlock()

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, m.baseURL+endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return m.httpClient.Do(req)
}

// ListProxyHosts returns all proxy hosts
func (m *NPMManager) ListProxyHosts() ([]NPMProxyHostExtended, error) {
	resp, err := m.doRequest("GET", "/api/nginx/proxy-hosts", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list proxy hosts: %s - %s", resp.Status, string(body))
	}

	var hosts []NPMProxyHostExtended
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, fmt.Errorf("failed to decode proxy hosts: %w", err)
	}

	return hosts, nil
}

// GetProxyHost returns a specific proxy host by ID
func (m *NPMManager) GetProxyHost(id int) (*NPMProxyHostExtended, error) {
	resp, err := m.doRequest("GET", fmt.Sprintf("/api/nginx/proxy-hosts/%d", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get proxy host: %s - %s", resp.Status, string(body))
	}

	var host NPMProxyHostExtended
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		return nil, fmt.Errorf("failed to decode proxy host: %w", err)
	}

	return &host, nil
}

// CreateProxyHost creates a new proxy host
func (m *NPMManager) CreateProxyHost(host *NPMProxyHostExtended) (*NPMProxyHostExtended, error) {
	// Set defaults
	if host.ForwardScheme == "" {
		host.ForwardScheme = "http"
	}
	if host.ForwardHost == "" {
		host.ForwardHost = m.gatewayIP
	}
	host.BlockExploits = true
	host.AllowWebsocketUpgrade = true
	host.Enabled = FlexBool(true)
	host.Meta = NPMMeta{LetsencryptAgree: false, DNSChallenge: false}
	host.Locations = []any{}

	resp, err := m.doRequest("POST", "/api/nginx/proxy-hosts", host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create proxy host: %s - %s", resp.Status, string(body))
	}

	var created NPMProxyHostExtended
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("failed to decode created proxy host: %w", err)
	}

	return &created, nil
}

// UpdateProxyHost updates an existing proxy host
func (m *NPMManager) UpdateProxyHost(id int, host *NPMProxyHostExtended) (*NPMProxyHostExtended, error) {
	resp, err := m.doRequest("PUT", fmt.Sprintf("/api/nginx/proxy-hosts/%d", id), host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to update proxy host: %s - %s", resp.Status, string(body))
	}

	var updated NPMProxyHostExtended
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, fmt.Errorf("failed to decode updated proxy host: %w", err)
	}

	return &updated, nil
}

// DeleteProxyHost deletes a proxy host
func (m *NPMManager) DeleteProxyHost(id int) error {
	resp, err := m.doRequest("DELETE", fmt.Sprintf("/api/nginx/proxy-hosts/%d", id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete proxy host: %s - %s", resp.Status, string(body))
	}

	return nil
}

// FindProxyHostByDomain finds a proxy host by domain name
func (m *NPMManager) FindProxyHostByDomain(domain string) (*NPMProxyHostExtended, error) {
	hosts, err := m.ListProxyHosts()
	if err != nil {
		return nil, err
	}

	for _, host := range hosts {
		for _, d := range host.DomainNames {
			if d == domain {
				return &host, nil
			}
		}
	}

	return nil, nil // Not found
}

// IsHealthy checks if NPM API is reachable
func (m *NPMManager) IsHealthy() bool {
	resp, err := m.httpClient.Get(m.baseURL + "/api/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// NPM returns 401 if running but not authenticated - that's fine
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
}

// IsAuthenticated checks if we have valid credentials
func (m *NPMManager) IsAuthenticated() bool {
	m.mu.RLock()
	token := m.token
	m.mu.RUnlock()
	return token != "" && m.verifyToken()
}

// GetBaseURL returns the NPM base URL (for status reporting)
func (m *NPMManager) GetBaseURL() string {
	return m.baseURL
}

// CoreProxyRule defines a proxy host that must exist for CubeOS to function.
type CoreProxyRule struct {
	Domain      string
	ForwardHost string
	ForwardPort int
	WebSocket   bool
	Description string
}

// GetCoreProxyRules returns the minimum proxy rules needed for out-of-box operation.
// All forward to gatewayIP (10.42.24.1) because NPM runs in host network mode
// and gatewayIP is future-proof if NPM ever moves to overlay networking.
func GetCoreProxyRules(gatewayIP string) []CoreProxyRule {
	return []CoreProxyRule{
		{Domain: "cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 6011, WebSocket: true, Description: "Dashboard"},
		{Domain: "api.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 6010, WebSocket: true, Description: "API"},
		{Domain: "pihole.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 6001, WebSocket: false, Description: "Pi-hole Admin"},
		{Domain: "npm.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 81, WebSocket: false, Description: "NPM Admin"},
		{Domain: "hal.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 6005, WebSocket: false, Description: "HAL"},
		{Domain: "dozzle.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 6012, WebSocket: true, Description: "Dozzle"},
		{Domain: "registry.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 5000, WebSocket: false, Description: "Registry"},
		{Domain: "docs.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 6032, WebSocket: false, Description: "DocsIndex"},
		{Domain: "terminal.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 6042, WebSocket: true, Description: "Terminal"},
		{Domain: "kiwix.cubeos.cube", ForwardHost: gatewayIP, ForwardPort: 6043, WebSocket: false, Description: "Kiwix Offline Library"},
	}
}

// EnsureCoreProxyHosts creates the minimum NPM proxy rules needed for CubeOS
// to work out of the box. Skips rules that already exist (idempotent).
// Returns the number of rules created and any error.
func (m *NPMManager) EnsureCoreProxyHosts() (int, error) {
	if !m.initialized {
		return 0, fmt.Errorf("NPM not initialized")
	}

	// Get existing proxy hosts to avoid duplicates
	existing, err := m.ListProxyHosts()
	if err != nil {
		return 0, fmt.Errorf("failed to list existing proxy hosts: %w", err)
	}

	// Build lookup of existing domains
	existingDomains := make(map[string]bool)
	for _, host := range existing {
		for _, d := range host.DomainNames {
			existingDomains[d] = true
		}
	}

	rules := GetCoreProxyRules(m.gatewayIP)
	created := 0

	for _, rule := range rules {
		if existingDomains[rule.Domain] {
			log.Debug().Str("domain", rule.Domain).Msg("NPM: core proxy rule already exists, skipping")
			continue
		}

		host := &NPMProxyHostExtended{
			DomainNames:           []string{rule.Domain},
			ForwardScheme:         "http",
			ForwardHost:           rule.ForwardHost,
			ForwardPort:           rule.ForwardPort,
			AllowWebsocketUpgrade: rule.WebSocket,
		}

		if _, err := m.CreateProxyHost(host); err != nil {
			log.Warn().Err(err).Str("domain", rule.Domain).Msg("NPM: failed to create core proxy rule")
			continue
		}

		log.Info().Str("domain", rule.Domain).Int("port", rule.ForwardPort).Str("service", rule.Description).Msg("NPM: created core proxy rule")
		created++
	}

	return created, nil
}
