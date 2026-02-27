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

const piholeDefaultTimeout = 10 * time.Second

// PiholeExternalClient communicates with an external Pi-hole v6 instance.
// Used by the "advanced" access profile to manage DNS on a remote Pi-hole.
type PiholeExternalClient struct {
	BaseURL    string
	Password   string
	sessionID  string
	httpClient *http.Client
}

// NewPiholeExternalClient creates a new client for an external Pi-hole instance.
func NewPiholeExternalClient(baseURL, password string) *PiholeExternalClient {
	return &PiholeExternalClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Password:   password,
		httpClient: &http.Client{Timeout: piholeDefaultTimeout},
	}
}

// Authenticate obtains a session SID from the Pi-hole v6 API.
func (c *PiholeExternalClient) Authenticate(ctx context.Context) error {
	body := fmt.Sprintf(`{"password":%q}`, c.Password)
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/auth", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pihole auth failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("pihole authentication failed: invalid password")
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pihole auth returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Session struct {
			SID string `json:"sid"`
		} `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode pihole auth response: %w", err)
	}
	c.sessionID = result.Session.SID
	return nil
}

// setAuth sets the appropriate auth header on a request.
func (c *PiholeExternalClient) setAuth(req *http.Request) {
	if c.sessionID != "" {
		req.Header.Set("X-FTL-SID", c.sessionID)
	} else if c.Password != "" {
		req.Header.Set("X-Pi-Hole-Password", c.Password)
	}
}

// AddDNSEntry adds a custom DNS entry (domain → IP).
func (c *PiholeExternalClient) AddDNSEntry(ctx context.Context, domain, ip string) error {
	body := fmt.Sprintf(`{"domain":%q,"ip":%q}`, domain, ip)
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/customdns", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create dns request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pihole add dns failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pihole add dns returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// DeleteDNSEntry removes a custom DNS entry by domain.
func (c *PiholeExternalClient) DeleteDNSEntry(ctx context.Context, domain string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.BaseURL+"/api/customdns/"+domain, nil)
	if err != nil {
		return fmt.Errorf("create dns delete request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pihole delete dns failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pihole delete dns returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// GetVersion returns the Pi-hole version string.
func (c *PiholeExternalClient) GetVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/api/info/version", nil)
	if err != nil {
		return "", err
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	var versionResp map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&versionResp); err != nil {
		return "", err
	}
	if v, ok := versionResp["version"].(string); ok {
		return v, nil
	}
	if core, ok := versionResp["core"].(map[string]interface{}); ok {
		if v, ok := core["version"].(string); ok {
			return v, nil
		}
	}
	return "", nil
}
