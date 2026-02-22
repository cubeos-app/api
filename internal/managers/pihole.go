package managers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cubeos-api/internal/circuitbreaker"
	"cubeos-api/internal/config"

	"github.com/rs/zerolog/log"
)

// PiholeManager manages DNS entries via the Pi-hole v6 REST API.
// Replaces file-based custom.list management with HTTP calls.
// DNS changes auto-apply in Pi-hole v6 — no reload needed.
type PiholeManager struct {
	baseURL    string // e.g. "http://10.42.24.1:6001"
	password   string // Pi-hole admin password
	cubeosIP   string // Gateway IP for DNS entries (e.g. "10.42.24.1")
	domain     string // e.g. "cubeos.cube"
	httpClient *http.Client
	cb         *circuitbreaker.CircuitBreaker

	mu        sync.Mutex // protects session state
	sid       string     // cached session ID
	sidExpiry time.Time  // when SID expires
}

// DNSEntry represents a DNS A record in Pi-hole.
type DNSEntry struct {
	IP     string `json:"ip"`
	Domain string `json:"domain"`
}

// NewPiholeManager creates a new Pi-hole manager using the v6 REST API.
// Does NOT authenticate at construction time — first auth happens lazily
// on the first API call, allowing graceful handling when Pi-hole is still starting.
func NewPiholeManager(cfg *config.Config) *PiholeManager {
	baseURL := fmt.Sprintf("http://%s:%d", cfg.GatewayIP, cfg.PiholePort)

	return &PiholeManager{
		baseURL:  baseURL,
		password: cfg.PiholePassword,
		cubeosIP: cfg.GatewayIP,
		domain:   cfg.Domain,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cb: circuitbreaker.New("pihole", circuitbreaker.DefaultConfig()),
	}
}

// authenticate performs POST /api/auth to obtain a session ID.
func (m *PiholeManager) authenticate(ctx context.Context) (string, error) {
	body, err := json.Marshal(map[string]string{"password": m.password})
	if err != nil {
		return "", fmt.Errorf("marshal auth body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL+"/api/auth", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth failed: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var authResp struct {
		Session struct {
			Valid    bool   `json:"valid"`
			SID      string `json:"sid"`
			Validity int    `json:"validity"` // seconds
		} `json:"session"`
	}
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return "", fmt.Errorf("parse auth response: %w", err)
	}

	if !authResp.Session.Valid || authResp.Session.SID == "" {
		return "", fmt.Errorf("auth returned invalid session")
	}

	// Cache SID at 80% of validity to avoid edge-case expirations
	validity := time.Duration(authResp.Session.Validity) * time.Second
	if validity <= 0 {
		validity = 300 * time.Second // default 5min
	}

	m.mu.Lock()
	m.sid = authResp.Session.SID
	m.sidExpiry = time.Now().Add(validity * 80 / 100)
	m.mu.Unlock()

	return authResp.Session.SID, nil
}

// getSID returns a valid session ID, re-authenticating if needed.
func (m *PiholeManager) getSID(ctx context.Context) (string, error) {
	m.mu.Lock()
	if m.sid != "" && time.Now().Before(m.sidExpiry) {
		sid := m.sid
		m.mu.Unlock()
		return sid, nil
	}
	m.mu.Unlock()

	return m.authenticate(ctx)
}

// invalidateSID clears the cached session, forcing re-auth on next call.
func (m *PiholeManager) invalidateSID() {
	m.mu.Lock()
	m.sid = ""
	m.sidExpiry = time.Time{}
	m.mu.Unlock()
}

// doRequest performs an authenticated HTTP request to the Pi-hole v6 API.
// Circuit breaker wraps the HTTP call. On 401, re-authenticates once and retries.
// Returns response body, HTTP status code, and error.
func (m *PiholeManager) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var respBody []byte
	var statusCode int

	cbErr := m.cb.Execute(func() error {
		sid, err := m.getSID(ctx)
		if err != nil {
			return fmt.Errorf("get session: %w", err)
		}

		respBody, statusCode, err = m.doRequestOnce(ctx, method, path, body, sid)
		if err != nil {
			return err
		}

		// On 401: invalidate SID, re-auth, retry once
		if statusCode == http.StatusUnauthorized {
			m.invalidateSID()
			sid, err = m.authenticate(ctx)
			if err != nil {
				return fmt.Errorf("re-auth after 401: %w", err)
			}
			respBody, statusCode, err = m.doRequestOnce(ctx, method, path, body, sid)
			if err != nil {
				return err
			}
		}

		// 5xx = breaker failure (returned to breaker via error)
		if statusCode >= 500 {
			return fmt.Errorf("pihole API error: HTTP %d: %s", statusCode, string(respBody))
		}

		// 4xx (except 401 handled above) = normal application response, not a breaker failure
		return nil
	})

	if cbErr != nil {
		return respBody, statusCode, cbErr
	}
	return respBody, statusCode, nil
}

// doRequestOnce performs a single HTTP request with the given SID.
func (m *PiholeManager) doRequestOnce(ctx context.Context, method, path string, body interface{}, sid string) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, m.baseURL+path, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-FTL-SID", sid)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response body: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// ReadCustomList reads all DNS A record entries from Pi-hole.
// GET /api/config/dns/hosts → JSON with hosts array.
func (m *PiholeManager) ReadCustomList() ([]DNSEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	body, statusCode, err := m.doRequest(ctx, http.MethodGet, "/api/config/dns/hosts", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS hosts: %w", err)
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d reading DNS hosts: %s", statusCode, string(body))
	}

	return parseDNSHostsResponse(body)
}

// parseDNSHostsResponse parses the Pi-hole v6 response for dns/hosts.
// Response format: {"config":{"dns":{"hosts":["IP HOSTNAME", ...]}}}
func parseDNSHostsResponse(body []byte) ([]DNSEntry, error) {
	var resp struct {
		Config struct {
			DNS struct {
				Hosts []string `json:"hosts"`
			} `json:"dns"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse dns hosts response: %w", err)
	}

	var entries []DNSEntry
	for _, line := range resp.Config.DNS.Hosts {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			entries = append(entries, DNSEntry{
				IP:     parts[0],
				Domain: parts[1],
			})
		}
	}

	return entries, nil
}

// WriteCustomList replaces all DNS A record entries with the given list.
// PATCH /api/config/dns/hosts with the full desired-state array.
func (m *PiholeManager) WriteCustomList(entries []DNSEntry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build the array of "IP HOSTNAME" strings
	var hosts []string
	for _, e := range entries {
		hosts = append(hosts, fmt.Sprintf("%s %s", e.IP, e.Domain))
	}

	_, statusCode, err := m.doRequest(ctx, http.MethodPatch, "/api/config/dns/hosts", hosts)
	if err != nil {
		return fmt.Errorf("failed to write DNS hosts: %w", err)
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status %d writing DNS hosts", statusCode)
	}

	return nil
}

// GetEntry finds a DNS entry by domain.
func (m *PiholeManager) GetEntry(domain string) (*DNSEntry, error) {
	entries, err := m.ReadCustomList()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.Domain == domain {
			return &entry, nil
		}
	}

	return nil, nil // Not found
}

// AddEntry adds or updates a DNS A record entry.
// PUT /api/config/dns/hosts/{IP}%20{domain} — idempotent.
// If the entry exists with a different IP, removes the old one first.
func (m *PiholeManager) AddEntry(domain string, ip string) error {
	if ip == "" {
		ip = m.cubeosIP
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if entry exists with a different IP — if so, remove old one first
	existing, err := m.GetEntry(domain)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("failed to check existing DNS entry, proceeding with add")
	} else if existing != nil && existing.IP != ip {
		oldPath := fmt.Sprintf("/api/config/dns/hosts/%s", url.PathEscape(existing.IP+" "+domain))
		_, _, _ = m.doRequest(ctx, http.MethodDelete, oldPath, nil)
	}

	// PUT is idempotent — safe to call even if entry already exists
	path := fmt.Sprintf("/api/config/dns/hosts/%s", url.PathEscape(ip+" "+domain))
	_, statusCode, err := m.doRequest(ctx, http.MethodPut, path, nil)
	if err != nil {
		return fmt.Errorf("failed to add DNS entry %s → %s: %w", domain, ip, err)
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status %d adding DNS entry %s", statusCode, domain)
	}

	return nil
}

// RemoveEntry removes a DNS A record by domain.
// Uses the gateway IP as the fast path (all CubeOS entries use cubeosIP).
// Falls back to read+search if the fast path returns 404.
func (m *PiholeManager) RemoveEntry(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Fast path: assume cubeosIP (all CubeOS DNS entries use gateway IP)
	path := fmt.Sprintf("/api/config/dns/hosts/%s", url.PathEscape(m.cubeosIP+" "+domain))
	_, statusCode, err := m.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		// If circuit is open, just return the error
		if err == circuitbreaker.ErrCircuitOpen {
			return err
		}
		// On network error, still try the slow path
		log.Debug().Err(err).Str("domain", domain).Msg("fast-path DNS delete failed, trying slow path")
	}

	if statusCode == http.StatusNoContent || statusCode == http.StatusOK {
		return nil
	}

	// Slow path: read all entries, find the IP, then delete
	if statusCode == http.StatusNotFound || err != nil {
		entries, readErr := m.ReadCustomList()
		if readErr != nil {
			return fmt.Errorf("failed to read DNS hosts for removal: %w", readErr)
		}

		for _, entry := range entries {
			if entry.Domain == domain {
				slowPath := fmt.Sprintf("/api/config/dns/hosts/%s", url.PathEscape(entry.IP+" "+domain))
				_, slowStatus, slowErr := m.doRequest(ctx, http.MethodDelete, slowPath, nil)
				if slowErr != nil {
					return fmt.Errorf("failed to remove DNS entry %s: %w", domain, slowErr)
				}
				if slowStatus == http.StatusNoContent || slowStatus == http.StatusOK {
					return nil
				}
				return fmt.Errorf("unexpected status %d removing DNS entry %s", slowStatus, domain)
			}
		}

		// Entry not found — nothing to remove
		return nil
	}

	return fmt.Errorf("unexpected status %d removing DNS entry %s", statusCode, domain)
}

// GetCubeOSDomains returns all DNS entries matching the configured base domain.
func (m *PiholeManager) GetCubeOSDomains() ([]DNSEntry, error) {
	entries, err := m.ReadCustomList()
	if err != nil {
		return nil, err
	}

	suffix := "." + m.domain
	var cubeosEntries []DNSEntry
	for _, entry := range entries {
		if strings.HasSuffix(entry.Domain, suffix) || entry.Domain == m.domain {
			cubeosEntries = append(cubeosEntries, entry)
		}
	}

	return cubeosEntries, nil
}

// ValidateDomain checks if a domain is valid for the configured base domain.
func (m *PiholeManager) ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	suffix := "." + m.domain
	if !strings.HasSuffix(domain, suffix) && domain != m.domain {
		return fmt.Errorf("domain must end with %s", suffix)
	}

	subdomain := strings.TrimSuffix(domain, suffix)
	if subdomain == "" || subdomain == domain {
		return nil // It's cubeos.cube itself
	}

	for _, c := range subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return fmt.Errorf("subdomain can only contain lowercase letters, numbers, hyphens, and dots")
		}
	}

	if strings.HasPrefix(subdomain, "-") || strings.HasSuffix(subdomain, "-") {
		return fmt.Errorf("subdomain cannot start or end with a hyphen")
	}

	return nil
}

// SyncFromList reads the current DNS entries and returns CubeOS domains.
func (m *PiholeManager) SyncFromList() ([]DNSEntry, error) {
	return m.GetCubeOSDomains()
}

// IsHealthy checks if Pi-hole is reachable via unauthenticated endpoint.
// GET /api/info/login — returns 200 when Pi-hole is running.
// Intentionally bypasses circuit breaker (used for recovery detection).
func (m *PiholeManager) IsHealthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.baseURL+"/api/info/login", nil)
	if err != nil {
		return false
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	return resp.StatusCode == http.StatusOK
}

// CircuitState returns the current state of the Pi-hole circuit breaker.
func (m *PiholeManager) CircuitState() circuitbreaker.State {
	return m.cb.State()
}
