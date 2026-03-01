package activities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"cubeos-api/internal/clients"
	"cubeos-api/internal/database"
	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// RegisterAccessProfileActivities registers all access profile switch activities.
func RegisterAccessProfileActivities(
	registry *flowengine.ActivityRegistry,
	db *sql.DB,
	dnsMgr DNSManager,
	proxyMgr ProxyManager,
	halClient *hal.Client,
) {
	registry.MustRegister("profile.validate_transition", makeValidateTransition(db, halClient))
	registry.MustRegister("profile.pause_app_updates", makePauseAppUpdates(db))
	registry.MustRegister("profile.resume_app_updates", makeResumeAppUpdates(db))
	registry.MustRegister("profile.teardown_old_access", makeTeardownOldAccess(db, dnsMgr, proxyMgr))
	registry.MustRegister("profile.restore_old_access", makeRestoreOldAccess(db, dnsMgr, proxyMgr))
	registry.MustRegister("profile.update_profile_db", makeUpdateProfileDB(db))
	registry.MustRegister("profile.restore_profile_db", makeRestoreProfileDB(db))
	registry.MustRegister("profile.configure_new_services", makeConfigureNewServices(db, halClient))
	registry.MustRegister("profile.restore_old_services", makeRestoreOldServices())
	registry.MustRegister("profile.migrate_app_entries", makeMigrateAppEntries(db, dnsMgr, proxyMgr))
	registry.MustRegister("profile.rollback_app_entries", makeRollbackAppEntries(db, dnsMgr, proxyMgr))
	registry.MustRegister("profile.verify_access", makeVerifyAccess(db))
}

// --- Input/Output types ---

type profileSwitchEnvelope struct {
	FromProfile   string `json:"from_profile"`
	ToProfile     string `json:"to_profile"`
	ExtNPMURL     string `json:"ext_npm_url"`
	ExtNPMToken   string `json:"ext_npm_token"`
	ExtPiholeURL  string `json:"ext_pihole_url"`
	ExtPiholePass string `json:"ext_pihole_password"`
	GatewayIP     string `json:"gateway_ip"`
}

type removedEntry struct {
	AppName string `json:"app_name"`
	Domain  string `json:"domain"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	ProxyID int64  `json:"proxy_id,omitempty"`
}

type migratedApp struct {
	AppName   string `json:"app_name"`
	AccessURL string `json:"access_url"`
	Domain    string `json:"domain,omitempty"`
	ProxyID   int64  `json:"proxy_id,omitempty"`
}

// --- Activity implementations ---

func makeValidateTransition(db *sql.DB, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env profileSwitchEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		if env.FromProfile == "" || env.ToProfile == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("from_profile and to_profile are required"))
		}
		if !database.ValidAccessProfiles[env.FromProfile] || !database.ValidAccessProfiles[env.ToProfile] {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid profile: from=%q to=%q", env.FromProfile, env.ToProfile))
		}

		switch env.ToProfile {
		case "advanced":
			if env.ExtNPMURL == "" || env.ExtPiholeURL == "" {
				return nil, flowengine.NewPermanentError(fmt.Errorf("advanced profile requires ext_npm_url and ext_pihole_url"))
			}
			// Test NPM connectivity
			npmClient := clients.NewNPMExternalClient(env.ExtNPMURL, env.ExtNPMToken)
			if _, err := npmClient.ListProxyHosts(ctx); err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("cannot reach external NPM: %w", err))
			}
			// Test Pi-hole connectivity
			phClient := clients.NewPiholeExternalClient(env.ExtPiholeURL, env.ExtPiholePass)
			if _, err := phClient.GetVersion(ctx); err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("cannot reach external Pi-hole: %w", err))
			}
			log.Info().Msg("validate_transition: external NPM and Pi-hole reachable")

		case "all_in_one":
			// Verify HAL is reachable (needed for DHCP/DNS/proxy on this device)
			if halClient != nil {
				if err := halClient.Health(ctx); err != nil {
					log.Warn().Err(err).Msg("validate_transition: HAL health check failed (non-fatal)")
				} else {
					log.Info().Msg("validate_transition: HAL reachable for all-in-one profile")
				}
			}

		case "standard":
			// Always valid
		}

		return marshalOutput(map[string]interface{}{
			"validated":    true,
			"from_profile": env.FromProfile,
			"to_profile":   env.ToProfile,
		})
	}
}

func makePauseAppUpdates(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		if err := database.SetSystemConfigFlag(db, "profile_switch_in_progress", true); err != nil {
			return nil, fmt.Errorf("failed to set profile_switch_in_progress: %w", err)
		}
		log.Info().Msg("pause_app_updates: profile switch lock acquired")
		return marshalOutput(map[string]bool{"paused": true})
	}
}

func makeResumeAppUpdates(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		if err := database.SetSystemConfigFlag(db, "profile_switch_in_progress", false); err != nil {
			return nil, fmt.Errorf("failed to clear profile_switch_in_progress: %w", err)
		}
		log.Info().Msg("resume_app_updates: profile switch lock released")
		return marshalOutput(map[string]bool{"resumed": true})
	}
}

func makeTeardownOldAccess(db *sql.DB, dnsMgr DNSManager, proxyMgr ProxyManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env profileSwitchEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		// If coming from standard, nothing to tear down
		if env.FromProfile == "standard" {
			log.Info().Msg("teardown_old_access: no entries to remove (from=standard)")
			return marshalOutput(map[string]interface{}{
				"removed_entries": []removedEntry{},
			})
		}

		apps, err := database.GetInstalledAppsForMigration(db)
		if err != nil {
			return nil, fmt.Errorf("query apps: %w", err)
		}

		var removed []removedEntry
		for _, app := range apps {
			if app.FQDN == "" {
				continue
			}

			entry := removedEntry{
				AppName: app.Name,
				Domain:  app.FQDN,
				Port:    app.Port,
			}

			switch env.FromProfile {
			case "all_in_one":
				// Remove from local DNS and proxy
				if ip, err := dnsMgr.GetEntry(app.FQDN); err == nil && ip != "" {
					entry.IP = ip
					if err := dnsMgr.RemoveEntry(app.FQDN); err != nil {
						log.Warn().Err(err).Str("domain", app.FQDN).Msg("teardown: failed to remove DNS (continuing)")
					}
				}
				if proxyID, err := proxyMgr.FindProxyHostByDomain(app.FQDN); err == nil && proxyID > 0 {
					entry.ProxyID = proxyID
					if err := proxyMgr.DeleteProxyHost(ctx, proxyID); err != nil {
						log.Warn().Err(err).Str("domain", app.FQDN).Msg("teardown: failed to remove proxy (continuing)")
					}
				}

			case "advanced":
				// Remove from external NPM/Pi-hole
				npmClient := clients.NewNPMExternalClient(env.ExtNPMURL, env.ExtNPMToken)
				phClient := clients.NewPiholeExternalClient(env.ExtPiholeURL, env.ExtPiholePass)

				if proxyID, err := npmClient.FindProxyHostByDomain(ctx, app.FQDN); err == nil && proxyID > 0 {
					entry.ProxyID = int64(proxyID)
					if err := npmClient.DeleteProxyHost(ctx, proxyID); err != nil {
						log.Warn().Err(err).Str("domain", app.FQDN).Msg("teardown: failed to remove ext proxy (continuing)")
					}
				}
				if err := phClient.DeleteDNSEntry(ctx, app.FQDN); err != nil {
					log.Warn().Err(err).Str("domain", app.FQDN).Msg("teardown: failed to remove ext DNS (continuing)")
				}
			}

			removed = append(removed, entry)
		}

		log.Info().Int("count", len(removed)).Str("from", env.FromProfile).Msg("teardown_old_access: removed entries")
		return marshalOutput(map[string]interface{}{
			"removed_entries": removed,
		})
	}
}

func makeRestoreOldAccess(db *sql.DB, dnsMgr DNSManager, proxyMgr ProxyManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env struct {
			profileSwitchEnvelope
			RemovedEntries []removedEntry `json:"removed_entries"`
		}
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, fmt.Errorf("invalid compensation input: %w", err)
		}

		for _, entry := range env.RemovedEntries {
			if entry.Domain == "" {
				continue
			}
			ip := entry.IP
			if ip == "" {
				ip = env.GatewayIP
				if ip == "" {
					ip = models.DefaultGatewayIP
				}
			}

			switch env.FromProfile {
			case "all_in_one":
				_ = dnsMgr.AddEntry(entry.Domain, ip)
				if entry.Port > 0 {
					_, _ = proxyMgr.CreateProxyHost(ctx, entry.Domain, ip, entry.Port, "http")
				}
			case "advanced":
				npmClient := clients.NewNPMExternalClient(env.ExtNPMURL, env.ExtNPMToken)
				phClient := clients.NewPiholeExternalClient(env.ExtPiholeURL, env.ExtPiholePass)
				_ = phClient.AddDNSEntry(ctx, entry.Domain, ip)
				if entry.Port > 0 {
					_, _ = npmClient.CreateProxyHost(ctx, entry.Domain, ip, entry.Port)
				}
			}
		}

		log.Info().Int("count", len(env.RemovedEntries)).Msg("restore_old_access: re-created entries")
		return marshalOutput(map[string]bool{"restored": true})
	}
}

func makeUpdateProfileDB(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env profileSwitchEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		cfg := &database.AccessProfileConfig{
			Profile:       env.ToProfile,
			ExtNPMURL:     env.ExtNPMURL,
			ExtNPMToken:   env.ExtNPMToken,
			ExtPiholeURL:  env.ExtPiholeURL,
			ExtPiholePass: env.ExtPiholePass,
		}
		if err := database.SetAccessProfileConfig(db, cfg); err != nil {
			return nil, fmt.Errorf("failed to update profile in DB: %w", err)
		}

		log.Info().Str("profile", env.ToProfile).Msg("update_profile_db: profile updated")
		return marshalOutput(map[string]string{
			"old_profile": env.FromProfile,
			"new_profile": env.ToProfile,
		})
	}
}

func makeRestoreProfileDB(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env profileSwitchEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, fmt.Errorf("invalid compensation input: %w", err)
		}

		// Restore to the original profile
		if err := database.SetAccessProfile(db, env.FromProfile); err != nil {
			return nil, fmt.Errorf("failed to restore profile: %w", err)
		}

		log.Info().Str("restored_to", env.FromProfile).Msg("restore_profile_db: profile restored")
		return marshalOutput(map[string]string{"restored_to": env.FromProfile})
	}
}

func makeConfigureNewServices(db *sql.DB, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env profileSwitchEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		switch env.ToProfile {
		case "all_in_one":
			// Enable local DHCP/DNS/proxy flags
			_ = database.SetSystemConfigFlag(db, "aio_dhcp_enabled", true)
			_ = database.SetSystemConfigFlag(db, "aio_dns_enabled", true)
			_ = database.SetSystemConfigFlag(db, "aio_proxy_enabled", true)
			log.Info().Msg("configure_new_services: enabled all-in-one flags")

		case "advanced":
			// Disable local AIO flags
			_ = database.SetSystemConfigFlag(db, "aio_dhcp_enabled", false)
			_ = database.SetSystemConfigFlag(db, "aio_dns_enabled", false)
			_ = database.SetSystemConfigFlag(db, "aio_proxy_enabled", false)
			log.Info().Msg("configure_new_services: cleared AIO flags for advanced profile")

		case "standard":
			// Disable all infrastructure flags
			_ = database.SetSystemConfigFlag(db, "aio_dhcp_enabled", false)
			_ = database.SetSystemConfigFlag(db, "aio_dns_enabled", false)
			_ = database.SetSystemConfigFlag(db, "aio_proxy_enabled", false)
			log.Info().Msg("configure_new_services: cleared flags for standard profile")
		}

		return marshalOutput(map[string]string{"configured": env.ToProfile})
	}
}

func makeRestoreOldServices() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		// Compensation: no-op — profile DB restore handles flag rollback
		log.Info().Msg("restore_old_services: no-op (profile DB restore handles flags)")
		return marshalOutput(map[string]bool{"restored": true})
	}
}

func makeMigrateAppEntries(db *sql.DB, dnsMgr DNSManager, proxyMgr ProxyManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env profileSwitchEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		gatewayIP := env.GatewayIP
		if gatewayIP == "" {
			gatewayIP = models.DefaultGatewayIP
		}

		apps, err := database.GetInstalledAppsForMigration(db)
		if err != nil {
			return nil, fmt.Errorf("query apps: %w", err)
		}

		var migrated []migratedApp
		for _, app := range apps {
			ma := migratedApp{AppName: app.Name}

			switch env.ToProfile {
			case "standard":
				// IP:port direct access
				accessURL := fmt.Sprintf("http://%s:%d", gatewayIP, app.Port)
				ma.AccessURL = accessURL
				if err := database.UpdateAppAccessURL(db, app.Name, accessURL); err != nil {
					log.Warn().Err(err).Str("app", app.Name).Msg("migrate: failed to update access_url")
				}

			case "all_in_one":
				// Use local DNS/proxy
				domain := app.Name + ".cubeos.cube"
				ma.Domain = domain

				if err := dnsMgr.AddEntry(domain, gatewayIP); err != nil {
					log.Warn().Err(err).Str("app", app.Name).Msg("migrate: failed to add DNS")
				}
				if app.Port > 0 {
					proxyID, err := proxyMgr.CreateProxyHost(ctx, domain, gatewayIP, app.Port, "http")
					if err != nil {
						log.Warn().Err(err).Str("app", app.Name).Msg("migrate: failed to create proxy")
					}
					ma.ProxyID = proxyID
				}

				accessURL := fmt.Sprintf("http://%s", domain)
				ma.AccessURL = accessURL
				if err := database.UpdateAppAccessURL(db, app.Name, accessURL); err != nil {
					log.Warn().Err(err).Str("app", app.Name).Msg("migrate: failed to update access_url")
				}

			case "advanced":
				// Use external NPM/Pi-hole
				domain := app.Name + ".cubeos.cube"
				ma.Domain = domain

				npmClient := clients.NewNPMExternalClient(env.ExtNPMURL, env.ExtNPMToken)
				phClient := clients.NewPiholeExternalClient(env.ExtPiholeURL, env.ExtPiholePass)

				if err := phClient.AddDNSEntry(ctx, domain, gatewayIP); err != nil {
					log.Warn().Err(err).Str("app", app.Name).Msg("migrate: failed to add ext DNS")
				}
				if app.Port > 0 {
					proxyID, err := npmClient.CreateProxyHost(ctx, domain, gatewayIP, app.Port)
					if err != nil {
						log.Warn().Err(err).Str("app", app.Name).Msg("migrate: failed to create ext proxy")
					}
					ma.ProxyID = int64(proxyID)
				}

				accessURL := fmt.Sprintf("http://%s", domain)
				ma.AccessURL = accessURL
				if err := database.UpdateAppAccessURL(db, app.Name, accessURL); err != nil {
					log.Warn().Err(err).Str("app", app.Name).Msg("migrate: failed to update access_url")
				}
			}

			migrated = append(migrated, ma)
		}

		log.Info().Int("count", len(migrated)).Str("to", env.ToProfile).Msg("migrate_app_entries: completed")
		return marshalOutput(map[string]interface{}{
			"migrated_apps": migrated,
			"total":         len(migrated),
		})
	}
}

func makeRollbackAppEntries(db *sql.DB, dnsMgr DNSManager, proxyMgr ProxyManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env struct {
			profileSwitchEnvelope
			MigratedApps []migratedApp `json:"migrated_apps"`
		}
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, fmt.Errorf("invalid compensation input: %w", err)
		}

		for _, app := range env.MigratedApps {
			if app.Domain == "" {
				continue
			}

			switch env.ToProfile {
			case "all_in_one":
				_ = dnsMgr.RemoveEntry(app.Domain)
				if app.ProxyID > 0 {
					_ = proxyMgr.DeleteProxyHost(ctx, app.ProxyID)
				}
			case "advanced":
				npmClient := clients.NewNPMExternalClient(env.ExtNPMURL, env.ExtNPMToken)
				phClient := clients.NewPiholeExternalClient(env.ExtPiholeURL, env.ExtPiholePass)
				_ = phClient.DeleteDNSEntry(ctx, app.Domain)
				if app.ProxyID > 0 {
					_ = npmClient.DeleteProxyHost(ctx, int(app.ProxyID))
				}
			}

			// Reset access URL
			_ = database.UpdateAppAccessURL(db, app.AppName, "")
		}

		log.Info().Int("count", len(env.MigratedApps)).Msg("rollback_app_entries: rolled back")
		return marshalOutput(map[string]bool{"rolled_back": true})
	}
}

func makeVerifyAccess(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env struct {
			MigratedApps []migratedApp `json:"migrated_apps"`
		}
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		if len(env.MigratedApps) == 0 {
			return marshalOutput(map[string]interface{}{
				"verified": 0,
				"results":  []interface{}{},
			})
		}

		// Pick up to 3 random apps
		sample := env.MigratedApps
		if len(sample) > 3 {
			rand.Shuffle(len(sample), func(i, j int) { sample[i], sample[j] = sample[j], sample[i] })
			sample = sample[:3]
		}

		type verifyResult struct {
			AppName   string `json:"app_name"`
			URL       string `json:"url"`
			Reachable bool   `json:"reachable"`
			Error     string `json:"error,omitempty"`
		}

		client := &http.Client{Timeout: 5 * time.Second}
		var results []verifyResult
		for _, app := range sample {
			if app.AccessURL == "" {
				continue
			}
			vr := verifyResult{AppName: app.AppName, URL: app.AccessURL}
			req, err := http.NewRequestWithContext(ctx, "GET", app.AccessURL, nil)
			if err != nil {
				vr.Error = err.Error()
			} else {
				resp, err := client.Do(req)
				if err != nil {
					vr.Error = err.Error()
				} else {
					resp.Body.Close()
					vr.Reachable = resp.StatusCode < 500
				}
			}
			results = append(results, vr)
		}

		log.Info().Int("verified", len(results)).Msg("verify_access: spot-check complete")
		return marshalOutput(map[string]interface{}{
			"verified": len(results),
			"results":  results,
		})
	}
}
