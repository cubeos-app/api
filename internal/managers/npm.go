package managers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cubeos-api/internal/config"
)

// NPMManager handles Nginx Proxy Manager API interactions
type NPMManager struct {
	baseURL    string
	gatewayIP  string
	token      string
	tokenFile  string
	email      string
	password   string
	httpClient *http.Client
	mu         sync.RWMutex
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
	Enabled               int      `json:"enabled"`
	Meta                  NPMMeta  `json:"meta"`
	Locations             []any    `json:"locations"`
}

// NPMMeta contains metadata for proxy hosts
type NPMMeta struct {
	LetsencryptAgree bool `json:"letsencrypt_agree"`
	DNSChallenge     bool `json:"dns_challenge"`
}

// NewNPMManager creates a new NPM manager using centralized config
func NewNPMManager(cfg *config.Config, configDir string) *NPMManager {
	// Support configurable credentials via environment variables
	email := os.Getenv("NPM_EMAIL")
	if email == "" {
		email = "admin@example.com"
	}
	password := os.Getenv("NPM_PASSWORD")
	if password == "" {
		password = "changeme"
	}

	return &NPMManager{
		baseURL:   cfg.GetNPMURL(),
		gatewayIP: cfg.GatewayIP,
		tokenFile: filepath.Join(configDir, "npm_token"),
		email:     email,
		password:  password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Init initializes the NPM manager, loading or generating token
func (m *NPMManager) Init() error {
	// Try to load existing token
	if data, err := os.ReadFile(m.tokenFile); err == nil && len(data) > 0 {
		m.mu.Lock()
		m.token = string(data)
		m.mu.Unlock()
		// Verify token is still valid
		if m.verifyToken() {
			return nil
		}
		// Token invalid, clear it
		m.mu.Lock()
		m.token = ""
		m.mu.Unlock()
	}

	// Generate new token (only if we have credentials)
	if m.email != "" && m.password != "" {
		err := m.generateToken()
		if err != nil {
			// Log the error but don't fail - NPM integration is optional
			fmt.Printf("Warning: Failed to get NPM token: %v\n", err)
			fmt.Println("Hint: Set NPM_EMAIL and NPM_PASSWORD environment variables or provide a valid token file")
			return err
		}
	}

	return nil
}

// generateToken requests a new long-lived token from NPM
func (m *NPMManager) generateToken() error {
	payload := map[string]string{
		"identity": m.email,
		"secret":   m.password,
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
		return fmt.Errorf("token request failed: %s - %s", resp.Status, string(respBody))
	}

	// Use NPMTokenResponse from appstore.go (same package, no import needed)
	var tokenResp NPMTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	m.mu.Lock()
	m.token = tokenResp.Token
	m.mu.Unlock()

	// Save token to file
	if err := os.MkdirAll(filepath.Dir(m.tokenFile), 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	if err := os.WriteFile(m.tokenFile, []byte(m.token), 0600); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}

// verifyToken checks if the current token is valid
func (m *NPMManager) verifyToken() bool {
	m.mu.RLock()
	token := m.token
	m.mu.RUnlock()

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
func (m *NPMManager) doRequest(method, endpoint string, body interface{}) (*http.Response, error) {
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

	req.Header.Set("Authorization", "Bearer "+token)
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
	host.Enabled = 1
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
