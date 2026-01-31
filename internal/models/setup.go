package models

// SetupConfig represents the complete first boot configuration
type SetupConfig struct {
	// Step 1: Admin Account
	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`
	AdminEmail    string `json:"admin_email"`

	// Step 2: Device Identity
	Hostname   string `json:"hostname"`
	DeviceName string `json:"device_name"` // Human-friendly name

	// Step 3: Network - WiFi AP
	WiFiSSID     string `json:"wifi_ssid"`
	WiFiPassword string `json:"wifi_password"`
	WiFiChannel  int    `json:"wifi_channel"` // 1-11, default 6

	// Step 4: Localization
	Timezone string `json:"timezone"`
	Language string `json:"language"` // e.g., "en", "es", "de"
	Locale   string `json:"locale"`   // e.g., "en_US", "es_ES"

	// Step 5: Appearance
	Theme       string `json:"theme"`        // dark, light, system
	AccentColor string `json:"accent_color"` // hex color

	// Step 6: Deployment Purpose
	DeploymentPurpose string `json:"deployment_purpose"` // generic, offline, expedition, marine
	BrandingMode      string `json:"branding_mode"`      // cubeos, custom

	// Step 7: SSL/TLS Configuration
	SSLMode    string `json:"ssl_mode"`    // none, self-signed, letsencrypt
	BaseDomain string `json:"base_domain"` // e.g., home.example.com

	// Step 8: DNS Provider (for Let's Encrypt DNS-01)
	DNSProvider  string `json:"dns_provider"`   // cloudflare, route53, duckdns, etc.
	DNSAPIToken  string `json:"dns_api_token"`  // API token/key
	DNSAPISecret string `json:"dns_api_secret"` // Additional secret if needed

	// Step 9: NPM Credentials (for reverse proxy admin)
	NPMAdminEmail    string `json:"npm_admin_email"`
	NPMAdminPassword string `json:"npm_admin_password"`

	// Step 10: Optional Features
	EnableAnalytics    bool `json:"enable_analytics"`     // Anonymous usage stats
	EnableAutoUpdates  bool `json:"enable_auto_updates"`  // Automatic security updates
	EnableRemoteAccess bool `json:"enable_remote_access"` // WireGuard VPN setup
}

// SetupStatus represents the current setup state
type SetupStatus struct {
	IsComplete     bool     `json:"is_complete"`
	CurrentStep    int      `json:"current_step"`
	TotalSteps     int      `json:"total_steps"`
	CompletedSteps []string `json:"completed_steps"`
	SkippedSteps   []string `json:"skipped_steps"`
	StartedAt      string   `json:"started_at,omitempty"`
	CompletedAt    string   `json:"completed_at,omitempty"`
}

// SetupStep represents a single wizard step
type SetupStep struct {
	ID          string   `json:"id"`
	Number      int      `json:"number"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Icon        string   `json:"icon"`
	Required    bool     `json:"required"`
	Fields      []string `json:"fields"`
}

// SetupValidation represents validation result
type SetupValidation struct {
	Valid    bool              `json:"valid"`
	Errors   map[string]string `json:"errors,omitempty"`
	Warnings map[string]string `json:"warnings,omitempty"`
}

// TimezoneInfo for timezone picker
type TimezoneInfo struct {
	ID     string `json:"id"`     // e.g., "America/New_York"
	Name   string `json:"name"`   // e.g., "Eastern Time"
	Offset string `json:"offset"` // e.g., "-05:00"
	Region string `json:"region"` // e.g., "Americas"
}

// DNSProviderInfo for DNS provider picker
type DNSProviderInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RequiredKeys []string `json:"required_keys"` // What credentials needed
	DocsURL      string   `json:"docs_url"`
}

// DeploymentPurposeInfo for purpose selection
type DeploymentPurposeInfo struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Icon            string   `json:"icon"`
	RecommendedApps []string `json:"recommended_apps"`
	Features        []string `json:"features"`
}

// WiFiScanResult for available networks
type WiFiScanResult struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Signal    int    `json:"signal"`   // dBm
	Security  string `json:"security"` // WPA2, WPA3, Open
	Channel   int    `json:"channel"`
	Frequency string `json:"frequency"` // 2.4GHz, 5GHz
}

// SystemRequirements for showing device capabilities
type SystemRequirements struct {
	TotalRAM     int64  `json:"total_ram_mb"`
	AvailableRAM int64  `json:"available_ram_mb"`
	TotalStorage int64  `json:"total_storage_gb"`
	AvailStorage int64  `json:"available_storage_gb"`
	CPUCores     int    `json:"cpu_cores"`
	Architecture string `json:"architecture"` // arm64, amd64
	HasWiFi      bool   `json:"has_wifi"`
	HasBluetooth bool   `json:"has_bluetooth"`
	HasGPU       bool   `json:"has_gpu"`
	DeviceModel  string `json:"device_model"` // e.g., "Raspberry Pi 5"
}

// SetupWizardSteps defines all wizard steps
var SetupWizardSteps = []SetupStep{
	{
		ID:          "welcome",
		Number:      0,
		Title:       "Welcome to CubeOS",
		Description: "Let's get your device ready",
		Icon:        "Rocket",
		Required:    true,
		Fields:      []string{},
	},
	{
		ID:          "admin",
		Number:      1,
		Title:       "Create Admin Account",
		Description: "Set up your administrator credentials",
		Icon:        "UserCog",
		Required:    true,
		Fields:      []string{"admin_username", "admin_password", "admin_email"},
	},
	{
		ID:          "device",
		Number:      2,
		Title:       "Device Identity",
		Description: "Name your device on the network",
		Icon:        "Server",
		Required:    true,
		Fields:      []string{"hostname", "device_name"},
	},
	{
		ID:          "wifi",
		Number:      3,
		Title:       "WiFi Access Point",
		Description: "Configure the wireless network",
		Icon:        "Wifi",
		Required:    true,
		Fields:      []string{"wifi_ssid", "wifi_password", "wifi_channel"},
	},
	{
		ID:          "locale",
		Number:      4,
		Title:       "Time & Language",
		Description: "Set your timezone and language",
		Icon:        "Globe",
		Required:    true,
		Fields:      []string{"timezone", "language"},
	},
	{
		ID:          "theme",
		Number:      5,
		Title:       "Appearance",
		Description: "Choose your visual style",
		Icon:        "Palette",
		Required:    false,
		Fields:      []string{"theme", "accent_color"},
	},
	{
		ID:          "purpose",
		Number:      6,
		Title:       "Deployment Purpose",
		Description: "What will you use CubeOS for?",
		Icon:        "Target",
		Required:    false,
		Fields:      []string{"deployment_purpose", "branding_mode"},
	},
	{
		ID:          "ssl",
		Number:      7,
		Title:       "Security & SSL",
		Description: "Configure HTTPS certificates",
		Icon:        "Shield",
		Required:    false,
		Fields:      []string{"ssl_mode", "base_domain"},
	},
	{
		ID:          "dns",
		Number:      8,
		Title:       "DNS Provider",
		Description: "For automatic SSL certificates",
		Icon:        "Cloud",
		Required:    false,
		Fields:      []string{"dns_provider", "dns_api_token"},
	},
	{
		ID:          "features",
		Number:      9,
		Title:       "Optional Features",
		Description: "Enable additional capabilities",
		Icon:        "Sparkles",
		Required:    false,
		Fields:      []string{"enable_analytics", "enable_auto_updates", "enable_remote_access"},
	},
	{
		ID:          "complete",
		Number:      10,
		Title:       "Setup Complete",
		Description: "Your CubeOS is ready!",
		Icon:        "CheckCircle",
		Required:    true,
		Fields:      []string{},
	},
}

// DeploymentPurposes available options
var DeploymentPurposes = []DeploymentPurposeInfo{
	{
		ID:              "generic",
		Name:            "General Purpose",
		Description:     "Flexible home server for various applications",
		Icon:            "Server",
		RecommendedApps: []string{"filebrowser", "syncthing", "vaultwarden", "it-tools"},
		Features:        []string{"App Store", "Docker Management", "File Sharing"},
	},
	{
		ID:              "offline",
		Name:            "Offline Knowledge Base",
		Description:     "Self-contained encyclopedia and reference library",
		Icon:            "BookOpen",
		RecommendedApps: []string{"kiwix", "calibre-web", "tileserver", "emergency-ref"},
		Features:        []string{"Offline Wikipedia", "Offline Maps", "E-book Library"},
	},
		Features:        []string{"Mesh Networking", "Offline Collaboration", "Emergency Reference"},
	},
	{
		ID:              "expedition",
		Name:            "Field Team",
		Description:     "Collaboration tools for remote teams",
		Icon:            "Users",
		RecommendedApps: []string{"cryptpad", "excalidraw", "element", "filebrowser", "syncthing"},
		Features:        []string{"Real-time Collaboration", "Secure Messaging", "File Sync"},
	},
	{
		ID:              "marine",
		Name:            "Marine & Sailing",
		Description:     "Navigation and marine data systems",
		Icon:            "Anchor",
		RecommendedApps: []string{"signalk-server", "tileserver", "jellyfin", "meshtastic-web"},
		Features:        []string{"Signal K Integration", "Offline Charts", "Media Server"},
	},
	{
		ID:              "ai",
		Name:            "Local AI Lab",
		Description:     "Privacy-focused AI and machine learning",
		Icon:            "Brain",
		RecommendedApps: []string{"ollama", "open-webui", "libretranslate", "whisper"},
		Features:        []string{"Local LLMs", "Translation", "Speech Recognition"},
	},
}

// DNSProviders supported for Let's Encrypt DNS-01
var DNSProviders = []DNSProviderInfo{
	{
		ID:           "cloudflare",
		Name:         "Cloudflare",
		Description:  "Popular DNS and CDN provider",
		RequiredKeys: []string{"CF_API_TOKEN"},
		DocsURL:      "https://developers.cloudflare.com/api/tokens/",
	},
	{
		ID:           "duckdns",
		Name:         "DuckDNS",
		Description:  "Free dynamic DNS service",
		RequiredKeys: []string{"DUCKDNS_TOKEN"},
		DocsURL:      "https://www.duckdns.org/",
	},
	{
		ID:           "route53",
		Name:         "AWS Route 53",
		Description:  "Amazon Web Services DNS",
		RequiredKeys: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		DocsURL:      "https://docs.aws.amazon.com/Route53/",
	},
	{
		ID:           "digitalocean",
		Name:         "DigitalOcean",
		Description:  "DigitalOcean DNS",
		RequiredKeys: []string{"DO_AUTH_TOKEN"},
		DocsURL:      "https://docs.digitalocean.com/reference/api/",
	},
	{
		ID:           "namecheap",
		Name:         "Namecheap",
		Description:  "Domain registrar with DNS",
		RequiredKeys: []string{"NAMECHEAP_API_USER", "NAMECHEAP_API_KEY"},
		DocsURL:      "https://www.namecheap.com/support/api/",
	},
	{
		ID:           "godaddy",
		Name:         "GoDaddy",
		Description:  "Domain registrar with DNS",
		RequiredKeys: []string{"GODADDY_API_KEY", "GODADDY_API_SECRET"},
		DocsURL:      "https://developer.godaddy.com/",
	},
}
