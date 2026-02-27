// Package clients provides external service clients for Access Profile Phase 3.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const npmDefaultTimeout = 10 * time.Second

// NPMExternalClient communicates with an external Nginx Proxy Manager v2 instance.
// Used by the "advanced" access profile to manage proxy hosts on a remote NPM.
type NPMExternalClient struct {
	BaseURL    string
	Token      string
	httpClient *http.Client
}

// NewNPMExternalClient creates a new client for an external NPM instance.
func NewNPMExternalClient(baseURL, token string) *NPMExternalClient {
	return &NPMExternalClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Token:      token,
		httpClient: &http.Client{Timeout: npmDefaultTimeout},
	}
}

// NPMProxyHost represents a proxy host entry from the NPM API.
type NPMProxyHost struct {
	ID          int      `json:"id"`
	DomainNames []string `json:"domain_names"`
	ForwardHost string   `json:"forward_host"`
	ForwardPort int      `json:"forward_port"`
}

// CreateProxyHost creates a new proxy host on the external NPM.
func (c *NPMExternalClient) CreateProxyHost(ctx context.Context, domain, forwardHost string, forwardPort int) (int, error) {
	body := map[string]interface{}{
		"domain_names":            []string{domain},
		"forward_scheme":          "http",
		"forward_host":            forwardHost,
		"forward_port":            forwardPort,
		"access_list_id":          "0",
		"certificate_id":          0,
		"ssl_forced":              false,
		"caching_enabled":         false,
		"block_exploits":          false,
		"advanced_config":         "",
		"meta":                    map[string]interface{}{"letsencrypt_agree": false, "dns_challenge": false},
		"allow_websocket_upgrade": true,
		"http2_support":           false,
		"hsts_enabled":            false,
		"hsts_subdomains":         false,
		"locations":               []interface{}{},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("marshal proxy host: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/nginx/proxy-hosts", strings.NewReader(string(data)))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("npm request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("npm create proxy host returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode npm response: %w", err)
	}
	return result.ID, nil
}

// DeleteProxyHost removes a proxy host by ID.
func (c *NPMExternalClient) DeleteProxyHost(ctx context.Context, id int) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/api/nginx/proxy-hosts/%d", c.BaseURL, id), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("npm request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("npm delete proxy host %d returned %d: %s", id, resp.StatusCode, string(respBody))
	}
	return nil
}

// ListProxyHosts returns all proxy hosts from the external NPM.
func (c *NPMExternalClient) ListProxyHosts(ctx context.Context) ([]NPMProxyHost, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/api/nginx/proxy-hosts", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("npm list proxy hosts returned %d: %s", resp.StatusCode, string(respBody))
	}

	var hosts []NPMProxyHost
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, fmt.Errorf("decode npm response: %w", err)
	}
	return hosts, nil
}

// FindProxyHostByDomain returns the host ID for a domain, or 0 if not found.
func (c *NPMExternalClient) FindProxyHostByDomain(ctx context.Context, domain string) (int, error) {
	hosts, err := c.ListProxyHosts(ctx)
	if err != nil {
		return 0, err
	}
	for _, h := range hosts {
		for _, d := range h.DomainNames {
			if d == domain {
				return h.ID, nil
			}
		}
	}
	return 0, nil
}

// GetVersion returns the NPM version string (best-effort).
func (c *NPMExternalClient) GetVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/api/settings", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	var settings map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&settings); err != nil {
		return "", err
	}
	if v, ok := settings["version"].(string); ok {
		return v, nil
	}
	return "", nil
}
