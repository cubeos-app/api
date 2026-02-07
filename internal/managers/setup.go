package managers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/models"

	"golang.org/x/crypto/bcrypt"
)

// SetupManager handles first boot setup operations
type SetupManager struct {
	cfg        *config.Config
	db         *sql.DB
	configPath string
	setupDone  bool
}

// NewSetupManager creates a new setup manager
func NewSetupManager(cfg *config.Config, db *sql.DB) *SetupManager {
	m := &SetupManager{
		cfg:        cfg,
		db:         db,
		configPath: "/cubeos/config",
	}

	os.MkdirAll(m.configPath, 0755)
	m.initDB()
	m.checkSetupStatus()

	return m
}

// initDB creates setup-specific tables.
// Core tables (users, etc.) are created by database.InitSchema() — do NOT create them here.
func (m *SetupManager) initDB() {
	queries := []string{
		// setup_status and system_config are also in schema.go but CREATE IF NOT EXISTS is idempotent
		`CREATE TABLE IF NOT EXISTS setup_status (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			is_complete INTEGER DEFAULT 0,
			current_step INTEGER DEFAULT 0,
			started_at DATETIME,
			completed_at DATETIME,
			config_json TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS system_config (
			key TEXT PRIMARY KEY,
			value TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, q := range queries {
		m.db.Exec(q)
	}

	// Ensure setup_status row exists
	m.db.Exec(`INSERT OR IGNORE INTO setup_status (id, is_complete, current_step) VALUES (1, 0, 0)`)
}

// checkSetupStatus loads current setup state
func (m *SetupManager) checkSetupStatus() {
	var isComplete int
	m.db.QueryRow(`SELECT is_complete FROM setup_status WHERE id = 1`).Scan(&isComplete)
	m.setupDone = isComplete == 1
}

// IsSetupComplete returns whether first boot setup is done
func (m *SetupManager) IsSetupComplete() bool {
	return m.setupDone
}

// GetSetupStatus returns current setup progress
func (m *SetupManager) GetSetupStatus() *models.SetupStatus {
	status := &models.SetupStatus{
		TotalSteps: len(models.SetupWizardSteps),
	}

	var isComplete, currentStep int
	var startedAt, completedAt sql.NullString
	var configJSON sql.NullString

	err := m.db.QueryRow(`SELECT is_complete, current_step, started_at, completed_at, config_json 
		FROM setup_status WHERE id = 1`).Scan(&isComplete, &currentStep, &startedAt, &completedAt, &configJSON)

	if err != nil {
		return status
	}

	status.IsComplete = isComplete == 1
	status.CurrentStep = currentStep
	if startedAt.Valid {
		status.StartedAt = startedAt.String
	}
	if completedAt.Valid {
		status.CompletedAt = completedAt.String
	}

	// Determine completed steps
	for i := 0; i < currentStep && i < len(models.SetupWizardSteps); i++ {
		status.CompletedSteps = append(status.CompletedSteps, models.SetupWizardSteps[i].ID)
	}

	return status
}

// GetWizardSteps returns all wizard step definitions
func (m *SetupManager) GetWizardSteps() []models.SetupStep {
	return models.SetupWizardSteps
}

// GetDeploymentPurposes returns available deployment purposes
func (m *SetupManager) GetDeploymentPurposes() []models.DeploymentPurposeInfo {
	return models.DeploymentPurposes
}

// GetDNSProviders returns available DNS providers for Let's Encrypt
func (m *SetupManager) GetDNSProviders() []models.DNSProviderInfo {
	return models.DNSProviders
}

// GetTimezones returns available timezones
func (m *SetupManager) GetTimezones() []models.TimezoneInfo {
	// Common timezones grouped by region
	timezones := []models.TimezoneInfo{
		// Americas
		{ID: "America/New_York", Name: "Eastern Time", Offset: "-05:00", Region: "Americas"},
		{ID: "America/Chicago", Name: "Central Time", Offset: "-06:00", Region: "Americas"},
		{ID: "America/Denver", Name: "Mountain Time", Offset: "-07:00", Region: "Americas"},
		{ID: "America/Los_Angeles", Name: "Pacific Time", Offset: "-08:00", Region: "Americas"},
		{ID: "America/Anchorage", Name: "Alaska Time", Offset: "-09:00", Region: "Americas"},
		{ID: "America/Sao_Paulo", Name: "Brasilia Time", Offset: "-03:00", Region: "Americas"},
		{ID: "America/Mexico_City", Name: "Mexico City", Offset: "-06:00", Region: "Americas"},
		// Europe
		{ID: "Europe/London", Name: "London (GMT)", Offset: "+00:00", Region: "Europe"},
		{ID: "Europe/Paris", Name: "Central European", Offset: "+01:00", Region: "Europe"},
		{ID: "Europe/Berlin", Name: "Berlin", Offset: "+01:00", Region: "Europe"},
		{ID: "Europe/Amsterdam", Name: "Amsterdam", Offset: "+01:00", Region: "Europe"},
		{ID: "Europe/Moscow", Name: "Moscow", Offset: "+03:00", Region: "Europe"},
		{ID: "Europe/Istanbul", Name: "Istanbul", Offset: "+03:00", Region: "Europe"},
		// Asia Pacific
		{ID: "Asia/Tokyo", Name: "Japan", Offset: "+09:00", Region: "Asia"},
		{ID: "Asia/Shanghai", Name: "China", Offset: "+08:00", Region: "Asia"},
		{ID: "Asia/Singapore", Name: "Singapore", Offset: "+08:00", Region: "Asia"},
		{ID: "Asia/Dubai", Name: "Dubai", Offset: "+04:00", Region: "Asia"},
		{ID: "Asia/Kolkata", Name: "India", Offset: "+05:30", Region: "Asia"},
		{ID: "Australia/Sydney", Name: "Sydney", Offset: "+11:00", Region: "Pacific"},
		{ID: "Pacific/Auckland", Name: "New Zealand", Offset: "+13:00", Region: "Pacific"},
		{ID: "Pacific/Honolulu", Name: "Hawaii", Offset: "-10:00", Region: "Pacific"},
		// Africa
		{ID: "Africa/Cairo", Name: "Cairo", Offset: "+02:00", Region: "Africa"},
		{ID: "Africa/Johannesburg", Name: "South Africa", Offset: "+02:00", Region: "Africa"},
		{ID: "Africa/Lagos", Name: "Lagos", Offset: "+01:00", Region: "Africa"},
		// UTC
		{ID: "UTC", Name: "UTC (Coordinated Universal)", Offset: "+00:00", Region: "UTC"},
	}
	return timezones
}

// GetSystemRequirements returns device capabilities
func (m *SetupManager) GetSystemRequirements() *models.SystemRequirements {
	req := &models.SystemRequirements{
		Architecture: "arm64",
	}

	// Get RAM info
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				var kb int64
				fmt.Sscanf(line, "MemTotal: %d kB", &kb)
				req.TotalRAM = kb / 1024
			}
			if strings.HasPrefix(line, "MemAvailable:") {
				var kb int64
				fmt.Sscanf(line, "MemAvailable: %d kB", &kb)
				req.AvailableRAM = kb / 1024
			}
		}
	}

	// Get CPU cores
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		req.CPUCores = strings.Count(string(data), "processor")
	}

	// Check for WiFi
	if _, err := os.Stat("/sys/class/net/wlan0"); err == nil {
		req.HasWiFi = true
	}

	// Check for Bluetooth
	if _, err := os.Stat("/sys/class/bluetooth"); err == nil {
		req.HasBluetooth = true
	}

	// Detect device model
	if data, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		req.DeviceModel = strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
	}

	// Get storage info
	if output, err := exec.Command("df", "-BG", "/").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				fmt.Sscanf(fields[1], "%dG", &req.TotalStorage)
				fmt.Sscanf(fields[3], "%dG", &req.AvailStorage)
			}
		}
	}

	return req
}

// ValidateSetupConfig validates the setup configuration
func (m *SetupManager) ValidateSetupConfig(cfg *models.SetupConfig) *models.SetupValidation {
	result := &models.SetupValidation{
		Valid:    true,
		Errors:   make(map[string]string),
		Warnings: make(map[string]string),
	}

	// Admin account validation
	if cfg.AdminUsername == "" {
		result.Errors["admin_username"] = "Username is required"
		result.Valid = false
	} else if !regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`).MatchString(cfg.AdminUsername) {
		result.Errors["admin_username"] = "Username must be 3-32 lowercase letters, numbers, underscores, or hyphens"
		result.Valid = false
	}

	if cfg.AdminPassword == "" {
		result.Errors["admin_password"] = "Password is required"
		result.Valid = false
	} else if len(cfg.AdminPassword) < 8 {
		result.Errors["admin_password"] = "Password must be at least 8 characters"
		result.Valid = false
	} else if len(cfg.AdminPassword) < 12 {
		result.Warnings["admin_password"] = "Consider using a longer password (12+ characters recommended)"
	}

	if cfg.AdminEmail != "" && !regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`).MatchString(cfg.AdminEmail) {
		result.Errors["admin_email"] = "Invalid email format"
		result.Valid = false
	}

	// Hostname validation
	if cfg.Hostname == "" {
		result.Errors["hostname"] = "Hostname is required"
		result.Valid = false
	} else if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`).MatchString(cfg.Hostname) {
		result.Errors["hostname"] = "Hostname must be lowercase letters, numbers, and hyphens"
		result.Valid = false
	}

	// WiFi validation
	if cfg.WiFiSSID == "" {
		result.Errors["wifi_ssid"] = "WiFi SSID is required"
		result.Valid = false
	} else if len(cfg.WiFiSSID) > 32 {
		result.Errors["wifi_ssid"] = "SSID must be 32 characters or less"
		result.Valid = false
	}

	if cfg.WiFiPassword != "" && len(cfg.WiFiPassword) < 8 {
		result.Errors["wifi_password"] = "WiFi password must be at least 8 characters"
		result.Valid = false
	}

	// SSL validation
	if cfg.SSLMode == "letsencrypt" {
		if cfg.BaseDomain == "" {
			result.Errors["base_domain"] = "Domain is required for Let's Encrypt"
			result.Valid = false
		}
		if cfg.DNSProvider == "" {
			result.Errors["dns_provider"] = "DNS provider is required for Let's Encrypt"
			result.Valid = false
		}
		if cfg.DNSAPIToken == "" {
			result.Errors["dns_api_token"] = "DNS API token is required"
			result.Valid = false
		}
	}

	return result
}

// ApplySetupConfig applies the complete setup configuration
func (m *SetupManager) ApplySetupConfig(cfg *models.SetupConfig) error {
	// Validate first
	validation := m.ValidateSetupConfig(cfg)
	if !validation.Valid {
		errMsgs := []string{}
		for field, msg := range validation.Errors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %s", field, msg))
		}
		return fmt.Errorf("validation failed: %s", strings.Join(errMsgs, "; "))
	}

	// Start setup
	m.db.Exec(`UPDATE setup_status SET started_at = ? WHERE id = 1`, time.Now().Format(time.RFC3339))

	// Step 1: Create admin user
	if err := m.createAdminUser(cfg.AdminUsername, cfg.AdminPassword, cfg.AdminEmail); err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}
	m.updateStep(1)

	// Step 2: Set hostname
	if err := m.setHostname(cfg.Hostname); err != nil {
		return fmt.Errorf("failed to set hostname: %w", err)
	}
	m.updateStep(2)

	// Step 3: Configure WiFi AP
	if err := m.configureWiFiAP(cfg.WiFiSSID, cfg.WiFiPassword, cfg.WiFiChannel); err != nil {
		return fmt.Errorf("failed to configure WiFi: %w", err)
	}
	m.updateStep(3)

	// Step 4: Set timezone
	if err := m.setTimezone(cfg.Timezone); err != nil {
		return fmt.Errorf("failed to set timezone: %w", err)
	}
	m.updateStep(4)

	// Step 5: Save theme preferences
	if err := m.saveThemePreferences(cfg.Theme, cfg.AccentColor); err != nil {
		return fmt.Errorf("failed to save theme: %w", err)
	}
	m.updateStep(5)

	// Step 6: Set deployment purpose
	if err := m.setDeploymentPurpose(cfg.DeploymentPurpose, cfg.BrandingMode); err != nil {
		return fmt.Errorf("failed to set deployment purpose: %w", err)
	}
	m.updateStep(6)

	// Step 7-8: Configure SSL
	if cfg.SSLMode != "" && cfg.SSLMode != "none" {
		if err := m.configureSSL(cfg.SSLMode, cfg.BaseDomain, cfg.DNSProvider, cfg.DNSAPIToken, cfg.DNSAPISecret); err != nil {
			return fmt.Errorf("failed to configure SSL: %w", err)
		}
	}
	m.updateStep(8)

	// Step 9: Configure NPM
	if cfg.NPMAdminEmail != "" && cfg.NPMAdminPassword != "" {
		if err := m.configureNPM(cfg.NPMAdminEmail, cfg.NPMAdminPassword); err != nil {
			// Log but don't fail - NPM might not be running yet
			fmt.Printf("Warning: Failed to configure NPM: %v\n", err)
		}
	}
	m.updateStep(9)

	// Step 10: Save optional features
	m.saveConfig("enable_analytics", fmt.Sprintf("%v", cfg.EnableAnalytics))
	m.saveConfig("enable_auto_updates", fmt.Sprintf("%v", cfg.EnableAutoUpdates))
	m.saveConfig("enable_remote_access", fmt.Sprintf("%v", cfg.EnableRemoteAccess))
	m.updateStep(10)

	// Save full config as JSON
	configJSON, _ := json.Marshal(cfg)
	m.db.Exec(`UPDATE setup_status SET config_json = ? WHERE id = 1`, string(configJSON))

	// Mark setup complete
	m.db.Exec(`UPDATE setup_status SET is_complete = 1, completed_at = ? WHERE id = 1`, time.Now().Format(time.RFC3339))
	m.setupDone = true

	return nil
}

// updateStep updates current step progress
func (m *SetupManager) updateStep(step int) {
	m.db.Exec(`UPDATE setup_status SET current_step = ? WHERE id = 1`, step)
}

// saveConfig saves a system config value
func (m *SetupManager) saveConfig(key, value string) {
	m.db.Exec(`INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, ?)`,
		key, value, time.Now().Format(time.RFC3339))
}

// GetConfig retrieves a system config value
func (m *SetupManager) GetConfig(key string) string {
	var value string
	m.db.QueryRow(`SELECT value FROM system_config WHERE key = ?`, key).Scan(&value)
	return value
}

// createAdminUser creates the admin user account
func (m *SetupManager) createAdminUser(username, password, email string) error {
	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), config.BcryptCost)
	if err != nil {
		return err
	}

	// Insert user
	_, err = m.db.Exec(`INSERT OR REPLACE INTO users (username, password_hash, email, role, created_at, updated_at) VALUES (?, ?, ?, 'admin', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		username, string(hash), email)
	if err != nil {
		return err
	}

	// Save as default credentials
	m.saveConfig("admin_username", username)
	m.saveConfig("admin_email", email)

	// Generate new JWT secret
	secret := make([]byte, 32)
	rand.Read(secret)
	m.saveConfig("jwt_secret", hex.EncodeToString(secret))

	return nil
}

// setHostname sets the system hostname
func (m *SetupManager) setHostname(hostname string) error {
	// Write to /etc/hostname
	if err := os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0644); err != nil {
		// If we can't write, save for later
		m.saveConfig("hostname", hostname)
		return nil
	}

	// Update /etc/hosts
	hostsPath := "/etc/hosts"
	if data, err := os.ReadFile(hostsPath); err == nil {
		lines := strings.Split(string(data), "\n")
		var newLines []string
		for _, line := range lines {
			if strings.Contains(line, "127.0.1.1") {
				line = fmt.Sprintf("127.0.1.1\t%s", hostname)
			}
			newLines = append(newLines, line)
		}
		os.WriteFile(hostsPath, []byte(strings.Join(newLines, "\n")), 0644)
	}

	// Apply hostname
	exec.Command("hostname", hostname).Run()

	m.saveConfig("hostname", hostname)
	return nil
}

// configureWiFiAP configures the WiFi access point
func (m *SetupManager) configureWiFiAP(ssid, password string, channel int) error {
	if channel == 0 {
		channel = 6
	}

	// Save config values
	m.saveConfig("wifi_ssid", ssid)
	m.saveConfig("wifi_channel", fmt.Sprintf("%d", channel))

	// Generate hostapd config
	hostapdConfig := fmt.Sprintf(`# CubeOS WiFi Access Point Configuration
interface=wlan0
driver=nl80211
ssid=%s
hw_mode=g
channel=%d
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=%s
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
`, ssid, channel, password)

	// Try to write hostapd config
	hostapdPath := "/etc/hostapd/hostapd.conf"
	if err := os.WriteFile(hostapdPath, []byte(hostapdConfig), 0600); err != nil {
		// Save to our config dir instead
		os.WriteFile(filepath.Join(m.configPath, "hostapd.conf"), []byte(hostapdConfig), 0600)
	}

	// Restart hostapd if available
	exec.Command("systemctl", "restart", "hostapd").Run()

	return nil
}

// setTimezone sets the system timezone
func (m *SetupManager) setTimezone(timezone string) error {
	if timezone == "" {
		timezone = "UTC"
	}

	// Try timedatectl first
	if err := exec.Command("timedatectl", "set-timezone", timezone).Run(); err != nil {
		// Fallback: create /etc/localtime symlink
		tzFile := filepath.Join("/usr/share/zoneinfo", timezone)
		if _, err := os.Stat(tzFile); err == nil {
			os.Remove("/etc/localtime")
			os.Symlink(tzFile, "/etc/localtime")
		}
	}

	// Write to /etc/timezone
	os.WriteFile("/etc/timezone", []byte(timezone+"\n"), 0644)

	m.saveConfig("timezone", timezone)
	return nil
}

// saveThemePreferences saves UI theme preferences
func (m *SetupManager) saveThemePreferences(theme, accentColor string) error {
	if theme == "" {
		theme = "dark"
	}
	if accentColor == "" {
		accentColor = "#60a5fa" // Default blue
	}

	m.saveConfig("theme", theme)
	m.saveConfig("accent_color", accentColor)

	// Write to preferences file for frontend
	prefsPath := filepath.Join(m.configPath, "preferences.json")
	prefs := map[string]string{
		"theme":        theme,
		"accent_color": accentColor,
	}
	data, _ := json.MarshalIndent(prefs, "", "  ")
	os.WriteFile(prefsPath, data, 0644)

	return nil
}

// setDeploymentPurpose sets the deployment purpose and branding
func (m *SetupManager) setDeploymentPurpose(purpose, branding string) error {
	if purpose == "" {
		purpose = "generic"
	}
	if branding == "" {
		branding = "cubeos"
	}

	m.saveConfig("deployment_purpose", purpose)
	m.saveConfig("branding_mode", branding)

	// Write branding config
	brandingPath := filepath.Join(m.configPath, "branding.json")
	brandingConfig := map[string]string{
		"purpose":  purpose,
		"branding": branding,
	}
	data, _ := json.MarshalIndent(brandingConfig, "", "  ")
	os.WriteFile(brandingPath, data, 0644)

	return nil
}

// configureSSL sets up SSL/TLS certificates
func (m *SetupManager) configureSSL(mode, domain, dnsProvider, apiToken, apiSecret string) error {
	m.saveConfig("ssl_mode", mode)
	m.saveConfig("base_domain", domain)

	if mode == "self-signed" {
		// Generate self-signed certificate using mkcert pattern
		certDir := "/cubeos/certs"
		os.MkdirAll(certDir, 0755)

		// Try mkcert if available
		if _, err := exec.LookPath("mkcert"); err == nil {
			exec.Command("mkcert", "-install").Run()
			exec.Command("mkcert",
				"-key-file", filepath.Join(certDir, "server.key"),
				"-cert-file", filepath.Join(certDir, "server.crt"),
				m.cfg.Domain, "*."+m.cfg.Domain, "localhost", m.cfg.GatewayIP,
			).Run()
		} else {
			// Fallback to openssl
			exec.Command("openssl", "req", "-x509", "-nodes", "-days", "365",
				"-newkey", "rsa:2048",
				"-keyout", filepath.Join(certDir, "server.key"),
				"-out", filepath.Join(certDir, "server.crt"),
				"-subj", "/CN="+m.cfg.Domain,
			).Run()
		}
	}

	if mode == "letsencrypt" && domain != "" && dnsProvider != "" {
		m.saveConfig("dns_provider", dnsProvider)

		// Write DNS credentials to env file for acme.sh
		envPath := filepath.Join(m.configPath, "acme-dns.env")
		envContent := ""

		switch dnsProvider {
		case "cloudflare":
			envContent = fmt.Sprintf("CF_API_TOKEN=%s\n", apiToken)
		case "duckdns":
			envContent = fmt.Sprintf("DUCKDNS_TOKEN=%s\n", apiToken)
		case "route53":
			envContent = fmt.Sprintf("AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n", apiToken, apiSecret)
		case "digitalocean":
			envContent = fmt.Sprintf("DO_AUTH_TOKEN=%s\n", apiToken)
		}

		os.WriteFile(envPath, []byte(envContent), 0600)

		// Schedule certificate request (will be executed by a service)
		m.saveConfig("acme_pending", "true")
		m.saveConfig("acme_domain", fmt.Sprintf("*.%s", domain))
	}

	return nil
}

// configureNPM configures Nginx Proxy Manager credentials
func (m *SetupManager) configureNPM(email, password string) error {
	// Write NPM env file
	npmEnvPath := "/cubeos/coreapps/npm/.env"
	os.MkdirAll(filepath.Dir(npmEnvPath), 0755)

	envContent := fmt.Sprintf(`# Nginx Proxy Manager - CubeOS Core App
# Generated by Setup Wizard

TZ=%s

NPM_ADMIN_EMAIL=%s
NPM_ADMIN_PASSWORD=%s
`, m.GetConfig("timezone"), email, password)

	if err := os.WriteFile(npmEnvPath, []byte(envContent), 0600); err != nil {
		return err
	}

	m.saveConfig("npm_admin_email", email)

	return nil
}

// GenerateDefaultConfig creates a default setup configuration
func (m *SetupManager) GenerateDefaultConfig() *models.SetupConfig {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "cubeos"
	}

	return &models.SetupConfig{
		AdminUsername:     "admin",
		Hostname:          hostname,
		DeviceName:        "CubeOS Server",
		WiFiSSID:          "CubeOS",
		WiFiPassword:      "",
		WiFiChannel:       6,
		Timezone:          "UTC",
		Language:          "en",
		Theme:             "dark",
		AccentColor:       "#60a5fa",
		DeploymentPurpose: "generic",
		BrandingMode:      "cubeos",
		SSLMode:           "none",
		EnableAnalytics:   false,
		EnableAutoUpdates: true,
	}
}

// ResetSetup resets the setup wizard (for testing/recovery)
func (m *SetupManager) ResetSetup() error {
	m.db.Exec(`UPDATE setup_status SET is_complete = 0, current_step = 0, started_at = NULL, completed_at = NULL, config_json = NULL WHERE id = 1`)
	m.setupDone = false
	return nil
}

// MarkSetupComplete marks the setup as complete without applying full config
// Used when user skips the wizard
func (m *SetupManager) MarkSetupComplete(cfg *models.SetupConfig) error {
	// Save minimal config
	configJSON, _ := json.Marshal(cfg)

	_, err := m.db.Exec(`UPDATE setup_status SET 
		is_complete = 1, 
		completed_at = CURRENT_TIMESTAMP,
		config_json = ?
		WHERE id = 1`, string(configJSON))

	if err != nil {
		return err
	}

	m.setupDone = true
	return nil
}
