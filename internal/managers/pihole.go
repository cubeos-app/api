package managers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"cubeos-api/internal/config"
)

// PiholeManager handles Pi-hole DNS custom.list management
type PiholeManager struct {
	customListPath string
	cubeosIP       string
	domain         string
	mu             sync.RWMutex
}

// DNSEntry represents a DNS entry in custom.list
type DNSEntry struct {
	IP     string `json:"ip"`
	Domain string `json:"domain"`
}

// NewPiholeManager creates a new Pi-hole manager using centralized config
func NewPiholeManager(cfg *config.Config, basePath string) *PiholeManager {
	return &PiholeManager{
		customListPath: filepath.Join(basePath, "coreapps/pihole/appdata/etc-pihole/hosts/custom.list"),
		cubeosIP:       cfg.GatewayIP,
		domain:         cfg.Domain,
	}
}

// SetCustomListPath allows overriding the custom.list path
func (m *PiholeManager) SetCustomListPath(path string) {
	m.customListPath = path
}

// ReadCustomList reads all DNS entries from custom.list
func (m *PiholeManager) ReadCustomList() ([]DNSEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	file, err := os.Open(m.customListPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []DNSEntry{}, nil
		}
		return nil, fmt.Errorf("failed to open custom.list: %w", err)
	}
	defer file.Close()

	var entries []DNSEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			entries = append(entries, DNSEntry{
				IP:     parts[0],
				Domain: parts[1],
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read custom.list: %w", err)
	}

	return entries, nil
}

// WriteCustomList writes all DNS entries to custom.list
func (m *PiholeManager) WriteCustomList(entries []DNSEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure directory exists
	dir := filepath.Dir(m.customListPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Sort entries for consistent output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Domain < entries[j].Domain
	})

	// Build content
	var lines []string
	for _, entry := range entries {
		lines = append(lines, fmt.Sprintf("%s %s", entry.IP, entry.Domain))
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}

	// Write atomically
	tmpPath := m.customListPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, m.customListPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// GetEntry finds a DNS entry by domain
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

// AddEntry adds or updates a DNS entry
func (m *PiholeManager) AddEntry(domain string, ip string) error {
	if ip == "" {
		ip = m.cubeosIP
	}

	entries, err := m.ReadCustomList()
	if err != nil {
		return err
	}

	// Check if exists and update
	found := false
	for i, entry := range entries {
		if entry.Domain == domain {
			entries[i].IP = ip
			found = true
			break
		}
	}

	// Add if not found
	if !found {
		entries = append(entries, DNSEntry{IP: ip, Domain: domain})
	}

	return m.WriteCustomList(entries)
}

// RemoveEntry removes a DNS entry by domain
func (m *PiholeManager) RemoveEntry(domain string) error {
	entries, err := m.ReadCustomList()
	if err != nil {
		return err
	}

	var newEntries []DNSEntry
	for _, entry := range entries {
		if entry.Domain != domain {
			newEntries = append(newEntries, entry)
		}
	}

	return m.WriteCustomList(newEntries)
}

// GetCubeOSDomains returns all domains matching the configured base domain
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

// ReloadDNS tells Pi-hole to reload its DNS configuration
func (m *PiholeManager) ReloadDNS() error {
	// Pi-hole v6: use 'pihole reloaddns' (not restartdns)
	cmd := exec.Command("docker", "exec", "cubeos-pihole", "pihole", "reloaddns")
	if err := cmd.Run(); err != nil {
		// Try direct pihole command
		cmd = exec.Command("pihole", "reloaddns")
		if err := cmd.Run(); err != nil {
			// Last resort: send SIGHUP to pihole-FTL
			cmd = exec.Command("pkill", "-HUP", "pihole-FTL")
			return cmd.Run()
		}
	}
	return nil
}

// ValidateDomain checks if a domain is valid for the configured base domain
func (m *PiholeManager) ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	suffix := "." + m.domain
	// Must end with .<domain> or be the base domain itself
	if !strings.HasSuffix(domain, suffix) && domain != m.domain {
		return fmt.Errorf("domain must end with %s", suffix)
	}

	// Extract subdomain
	subdomain := strings.TrimSuffix(domain, suffix)
	if subdomain == "" || subdomain == domain {
		return nil // It's cubeos.cube itself
	}

	// Validate subdomain format
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

// SyncFromList reads the current custom.list and returns domains that should be tracked
func (m *PiholeManager) SyncFromList() ([]DNSEntry, error) {
	entries, err := m.GetCubeOSDomains()
	if err != nil {
		return nil, err
	}
	return entries, nil
}
