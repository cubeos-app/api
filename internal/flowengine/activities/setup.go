// Package activities provides FlowEngine activity implementations.
package activities

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// SetupConfigurer defines the subset of SetupManager methods needed by setup activities.
// Satisfied by *managers.SetupManager.
type SetupConfigurer interface {
	ValidateSetupConfig(cfg *models.SetupConfig) *models.SetupValidation
	CreateAdminUser(username, password, email string) error
	SetHostname(hostname string) error
	SaveConfig(key, value string)
	GetConfig(key string) string
	ConfigureWiFiAP(ssid, password string, channel int) error
	SaveCountryCode(code string)
	SetTimezone(timezone string) error
	SaveThemePreferences(theme, accentColor string) error
	SetDeploymentPurpose(purpose, branding string) error
	ConfigureSSL(mode, domain, dnsProvider, apiToken, apiSecret string) error
	ConfigureNPM(email, password string) error
	MarkSetupComplete(cfg *models.SetupConfig) error
	ResetSetup() error
	SyncPasswordsAsync(username, password string)
	ReadHostapdConfig() (string, error)
	WriteHostapdConfig(content string) error
	RestartHostapd() error
}

// RegisterSetupActivities registers all first-boot setup activities
// in the FlowEngine activity registry.
//
// Activities:
//   - setup.validate, setup.create_admin, setup.set_hostname,
//     setup.configure_wifi, setup.restore_wifi, setup.configure_system,
//     setup.sync_passwords, setup.mark_complete, setup.unmark_complete
func RegisterSetupActivities(registry *flowengine.ActivityRegistry, sc SetupConfigurer) {
	registry.MustRegister("setup.validate", makeSetupValidate(sc))
	registry.MustRegister("setup.create_admin", makeSetupCreateAdmin(sc))
	registry.MustRegister("setup.set_hostname", makeSetupSetHostname(sc))
	registry.MustRegister("setup.configure_wifi", makeSetupConfigureWiFi(sc))
	registry.MustRegister("setup.restore_wifi", makeSetupRestoreWiFi(sc))
	registry.MustRegister("setup.configure_system", makeSetupConfigureSystem(sc))
	registry.MustRegister("setup.sync_passwords", makeSetupSyncPasswords(sc))
	registry.MustRegister("setup.mark_complete", makeSetupMarkComplete(sc))
	registry.MustRegister("setup.unmark_complete", makeSetupUnmarkComplete(sc))
}

// =============================================================================
// Fat envelope type — merged JSON of workflow input + all prior step outputs
// =============================================================================

// setupEnvelope is the combined input available to all steps via fat envelope merge.
type setupEnvelope struct {
	// From workflow input (SetupConfig fields)
	AdminUsername      string `json:"admin_username"`
	AdminPassword      string `json:"admin_password"`
	AdminEmail         string `json:"admin_email"`
	Hostname           string `json:"hostname"`
	DeviceName         string `json:"device_name"`
	WiFiSSID           string `json:"wifi_ssid"`
	WiFiPassword       string `json:"wifi_password"`
	WiFiChannel        int    `json:"wifi_channel"`
	CountryCode        string `json:"country_code"`
	Timezone           string `json:"timezone"`
	Language           string `json:"language"`
	Locale             string `json:"locale"`
	Theme              string `json:"theme"`
	AccentColor        string `json:"accent_color"`
	DeploymentPurpose  string `json:"deployment_purpose"`
	BrandingMode       string `json:"branding_mode"`
	SSLMode            string `json:"ssl_mode"`
	BaseDomain         string `json:"base_domain"`
	DNSProvider        string `json:"dns_provider"`
	DNSAPIToken        string `json:"dns_api_token"`
	DNSAPISecret       string `json:"dns_api_secret"`
	NPMAdminEmail      string `json:"npm_admin_email"`
	NPMAdminPassword   string `json:"npm_admin_password"`
	EnableAnalytics    bool   `json:"enable_analytics"`
	EnableAutoUpdates  bool   `json:"enable_auto_updates"`
	EnableRemoteAccess bool   `json:"enable_remote_access"`

	// From configure_wifi step (for compensation)
	OriginalHostapdConfig string `json:"original_hostapd_config,omitempty"`
}

// =============================================================================
// Activity: setup.validate
// =============================================================================

func makeSetupValidate(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env setupEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid setup input: %w", err))
		}

		cfg := envelopeToSetupConfig(&env)
		validation := sc.ValidateSetupConfig(cfg)
		if !validation.Valid {
			errMsgs := []string{}
			for field, msg := range validation.Errors {
				errMsgs = append(errMsgs, fmt.Sprintf("%s: %s", field, msg))
			}
			return nil, flowengine.NewPermanentError(fmt.Errorf("validation failed: %s", strings.Join(errMsgs, "; ")))
		}

		log.Info().Msg("setup.validate: configuration is valid")
		return marshalOutput(map[string]interface{}{
			"valid": true,
		})
	}
}

// =============================================================================
// Activity: setup.create_admin
// =============================================================================

func makeSetupCreateAdmin(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env setupEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid create_admin input: %w", err))
		}

		if err := sc.CreateAdminUser(env.AdminUsername, env.AdminPassword, env.AdminEmail); err != nil {
			return nil, fmt.Errorf("failed to create admin user: %w", err)
		}

		log.Info().Str("username", env.AdminUsername).Msg("setup.create_admin: admin user created")
		return marshalOutput(map[string]interface{}{
			"admin_created": true,
		})
	}
}

// =============================================================================
// Activity: setup.set_hostname
// =============================================================================

func makeSetupSetHostname(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env setupEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid set_hostname input: %w", err))
		}

		if err := sc.SetHostname(env.Hostname); err != nil {
			return nil, fmt.Errorf("failed to set hostname: %w", err)
		}

		log.Info().Str("hostname", env.Hostname).Msg("setup.set_hostname: hostname configured")
		return marshalOutput(map[string]interface{}{
			"hostname_set": true,
		})
	}
}

// =============================================================================
// Activity: setup.configure_wifi
// =============================================================================

func makeSetupConfigureWiFi(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env setupEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid configure_wifi input: %w", err))
		}

		// Guard: skip WiFi rewrite when password is empty.
		// CubeOS always uses WPA2; writing an empty wpa_passphrase breaks hostapd.
		if env.WiFiPassword == "" {
			log.Info().Msg("setup.configure_wifi: no WiFi password provided, keeping current AP settings")
			// Snapshot current config so compensation still has it if needed
			originalConfig, _ := sc.ReadHostapdConfig()
			return marshalOutput(map[string]interface{}{
				"wifi_configured":         false,
				"skipped":                 true,
				"reason":                  "empty_password",
				"original_hostapd_config": originalConfig,
			})
		}

		// Snapshot current hostapd.conf for compensation rollback
		originalConfig, err := sc.ReadHostapdConfig()
		if err != nil {
			log.Warn().Err(err).Msg("setup.configure_wifi: could not snapshot hostapd.conf (new install?)")
			// Non-fatal — compensation will skip restore if empty
		}

		// Save country code before configuring WiFi AP
		if env.CountryCode != "" {
			sc.SaveCountryCode(env.CountryCode)
		} else {
			sc.SaveCountryCode("NL")
		}

		if err := sc.ConfigureWiFiAP(env.WiFiSSID, env.WiFiPassword, env.WiFiChannel); err != nil {
			return nil, fmt.Errorf("failed to configure WiFi AP: %w", err)
		}

		log.Info().Str("ssid", env.WiFiSSID).Msg("setup.configure_wifi: WiFi AP configured")
		return marshalOutput(map[string]interface{}{
			"wifi_configured":         true,
			"original_hostapd_config": originalConfig,
		})
	}
}

// =============================================================================
// Compensation: setup.restore_wifi
// =============================================================================

func makeSetupRestoreWiFi(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env setupEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore_wifi input: %w", err))
		}

		if env.OriginalHostapdConfig == "" {
			log.Info().Msg("setup.restore_wifi: no original config to restore, skipping")
			return marshalOutput(map[string]interface{}{"restored": false, "reason": "no_snapshot"})
		}

		if err := sc.WriteHostapdConfig(env.OriginalHostapdConfig); err != nil {
			log.Error().Err(err).Msg("setup.restore_wifi: failed to write original hostapd.conf")
			return nil, fmt.Errorf("failed to restore hostapd.conf: %w", err)
		}

		if err := sc.RestartHostapd(); err != nil {
			log.Warn().Err(err).Msg("setup.restore_wifi: failed to restart hostapd after restore")
			// Non-fatal — config is written, restart will happen on reboot
		}

		log.Info().Msg("setup.restore_wifi: original WiFi configuration restored")
		return marshalOutput(map[string]interface{}{"restored": true})
	}
}

// =============================================================================
// Activity: setup.configure_system
// =============================================================================

func makeSetupConfigureSystem(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env setupEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid configure_system input: %w", err))
		}

		// Timezone
		if err := sc.SetTimezone(env.Timezone); err != nil {
			return nil, fmt.Errorf("failed to set timezone: %w", err)
		}

		// Theme
		if err := sc.SaveThemePreferences(env.Theme, env.AccentColor); err != nil {
			return nil, fmt.Errorf("failed to save theme: %w", err)
		}

		// Deployment purpose
		if err := sc.SetDeploymentPurpose(env.DeploymentPurpose, env.BrandingMode); err != nil {
			return nil, fmt.Errorf("failed to set deployment purpose: %w", err)
		}

		// SSL (optional — only if mode is set and not "none")
		if env.SSLMode != "" && env.SSLMode != "none" {
			if err := sc.ConfigureSSL(env.SSLMode, env.BaseDomain, env.DNSProvider, env.DNSAPIToken, env.DNSAPISecret); err != nil {
				return nil, fmt.Errorf("failed to configure SSL: %w", err)
			}
		}

		// NPM credentials (optional)
		if env.NPMAdminEmail != "" && env.NPMAdminPassword != "" {
			if err := sc.ConfigureNPM(env.NPMAdminEmail, env.NPMAdminPassword); err != nil {
				// Non-fatal — NPM might not be running yet
				log.Warn().Err(err).Msg("setup.configure_system: NPM configuration failed (non-fatal)")
			}
		}

		// Feature flags
		sc.SaveConfig("enable_analytics", fmt.Sprintf("%v", env.EnableAnalytics))
		sc.SaveConfig("enable_auto_updates", fmt.Sprintf("%v", env.EnableAutoUpdates))
		sc.SaveConfig("enable_remote_access", fmt.Sprintf("%v", env.EnableRemoteAccess))

		log.Info().Msg("setup.configure_system: system configuration applied")
		return marshalOutput(map[string]interface{}{
			"system_configured": true,
		})
	}
}

// =============================================================================
// Activity: setup.sync_passwords
// =============================================================================

func makeSetupSyncPasswords(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env setupEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid sync_passwords input: %w", err))
		}

		// Fire-and-forget goroutines — always succeeds
		sc.SyncPasswordsAsync(env.AdminUsername, env.AdminPassword)

		log.Info().Msg("setup.sync_passwords: password sync initiated (fire-and-forget)")
		return marshalOutput(map[string]interface{}{
			"sync_initiated": true,
		})
	}
}

// =============================================================================
// Activity: setup.mark_complete
// =============================================================================

func makeSetupMarkComplete(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env setupEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid mark_complete input: %w", err))
		}

		cfg := envelopeToSetupConfig(&env)
		if err := sc.MarkSetupComplete(cfg); err != nil {
			return nil, fmt.Errorf("failed to mark setup complete: %w", err)
		}

		log.Info().Msg("setup.mark_complete: setup marked as complete")
		return marshalOutput(map[string]interface{}{
			"setup_complete": true,
		})
	}
}

// =============================================================================
// Compensation: setup.unmark_complete
// =============================================================================

func makeSetupUnmarkComplete(sc SetupConfigurer) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		if err := sc.ResetSetup(); err != nil {
			return nil, fmt.Errorf("failed to reset setup: %w", err)
		}

		log.Info().Msg("setup.unmark_complete: setup flag reset for retry")
		return marshalOutput(map[string]interface{}{"reset": true})
	}
}

// =============================================================================
// Helpers
// =============================================================================

// envelopeToSetupConfig converts the fat envelope back to a SetupConfig struct.
func envelopeToSetupConfig(env *setupEnvelope) *models.SetupConfig {
	return &models.SetupConfig{
		AdminUsername:      env.AdminUsername,
		AdminPassword:      env.AdminPassword,
		AdminEmail:         env.AdminEmail,
		Hostname:           env.Hostname,
		DeviceName:         env.DeviceName,
		WiFiSSID:           env.WiFiSSID,
		WiFiPassword:       env.WiFiPassword,
		WiFiChannel:        env.WiFiChannel,
		CountryCode:        env.CountryCode,
		Timezone:           env.Timezone,
		Language:           env.Language,
		Locale:             env.Locale,
		Theme:              env.Theme,
		AccentColor:        env.AccentColor,
		DeploymentPurpose:  env.DeploymentPurpose,
		BrandingMode:       env.BrandingMode,
		SSLMode:            env.SSLMode,
		BaseDomain:         env.BaseDomain,
		DNSProvider:        env.DNSProvider,
		DNSAPIToken:        env.DNSAPIToken,
		DNSAPISecret:       env.DNSAPISecret,
		NPMAdminEmail:      env.NPMAdminEmail,
		NPMAdminPassword:   env.NPMAdminPassword,
		EnableAnalytics:    env.EnableAnalytics,
		EnableAutoUpdates:  env.EnableAutoUpdates,
		EnableRemoteAccess: env.EnableRemoteAccess,
	}
}
