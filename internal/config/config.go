// Package config provides application configuration from environment variables.
package config

import (
	"fmt"
	"sync"
	"time"

	"github.com/kelseyhightower/envconfig"
)

// Settings holds all application configuration.
type Settings struct {
	// Application metadata
	Version  string `envconfig:"VERSION" default:"0.1.0"`
	LogLevel string `envconfig:"LOG_LEVEL" default:"info"`

	// API server settings
	APIHost string `envconfig:"API_HOST" default:"0.0.0.0"`
	APIPort int    `envconfig:"API_PORT" default:"9008"`

	// Docker settings
	DockerSocket string `envconfig:"DOCKER_SOCKET" default:"/var/run/docker.sock"`

	// Database settings
	DatabasePath string `envconfig:"DATABASE_PATH" default:"/var/lib/cubeos/cubeos.db"`

	// Auth settings
	JWTSecret           string        `envconfig:"JWT_SECRET" default:""`                // Must be set in production!
	AccessTokenExpiry   time.Duration `envconfig:"ACCESS_TOKEN_EXPIRY" default:"15m"`    // Industry standard: 15 min
	RefreshTokenExpiry  time.Duration `envconfig:"REFRESH_TOKEN_EXPIRY" default:"168h"`  // 7 days
	AdminPassword       string        `envconfig:"ADMIN_PASSWORD" default:""`            // Initial admin password

	// State persistence
	StateFile string `envconfig:"STATE_FILE" default:"/var/lib/cubeos/state/services.json"`

	// Service registry
	ServiceRegistryFile string `envconfig:"SERVICE_REGISTRY_FILE" default:"/var/lib/cubeos/data/service_registry.yaml"`

	// Timeouts
	ContainerStopTimeout time.Duration `envconfig:"CONTAINER_STOP_TIMEOUT" default:"30s"`
	HealthCheckTimeout   time.Duration `envconfig:"HEALTH_CHECK_TIMEOUT" default:"60s"`

	// Network settings (WiFi AP)
	APInterface  string `envconfig:"AP_INTERFACE" default:"wlan0"`
	WANInterface string `envconfig:"WAN_INTERFACE" default:"eth0"`
	APIP         string `envconfig:"AP_IP" default:"192.168.42.1"`

	// System config file paths
	HostapdConf   string `envconfig:"HOSTAPD_CONF" default:"/etc/hostapd/hostapd.conf"`
	DnsmasqConf   string `envconfig:"DNSMASQ_CONF" default:"/etc/dnsmasq.d/090_cubeos.conf"`
	DnsmasqLeases string `envconfig:"DNSMASQ_LEASES" default:"/var/lib/misc/dnsmasq.leases"`

	// Data directories
	DataDir   string `envconfig:"DATA_DIR" default:"/var/lib/cubeos"`
	BackupDir string `envconfig:"BACKUP_DIR" default:"/var/lib/cubeos/backups"`

	// Monitoring
	StatsInterval time.Duration `envconfig:"STATS_INTERVAL" default:"2s"`
}

// ListenAddr returns the address string for the HTTP server to bind to.
func (s *Settings) ListenAddr() string {
	return fmt.Sprintf("%s:%d", s.APIHost, s.APIPort)
}

var (
	cfg  *Settings
	once sync.Once
)

// Get returns the singleton Settings instance.
func Get() *Settings {
	once.Do(func() {
		cfg = &Settings{}
		if err := envconfig.Process("CUBEOS", cfg); err != nil {
			panic(fmt.Sprintf("failed to load config: %v", err))
		}
	})
	return cfg
}

// Load creates a new Settings instance from environment variables.
func Load() (*Settings, error) {
	s := &Settings{}
	if err := envconfig.Process("CUBEOS", s); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return s, nil
}
