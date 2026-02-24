// Package activities provides FlowEngine activity implementations.
package activities

import (
	"context"
	"encoding/json"
	"fmt"

	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// RegisterWifiClientActivities registers all wifi_client switch activities
// in the FlowEngine activity registry.
func RegisterWifiClientActivities(registry *flowengine.ActivityRegistry, nm NetworkModeSwitcher, halClient *hal.Client) {
	registry.MustRegister("wc.validate", makeWCValidate(nm, halClient))
	registry.MustRegister("wc.snapshot_state", makeWCSnapshotState(nm))
	registry.MustRegister("wc.stop_ap", makeWCStopAP(halClient))
	registry.MustRegister("wc.connect_station", makeWCConnectStation(halClient))
	registry.MustRegister("wc.verify_station", makeWCVerifyStation(halClient))
	registry.MustRegister("wc.configure_dns", makeWCConfigureDNS(nm))
	registry.MustRegister("wc.persist", makeWCPersist(nm, halClient))
	registry.MustRegister("wc.revert_ap", makeWCRevertAP(nm, halClient))
}

// wcEnvelope is the combined input available to all wifi_client steps via fat envelope merge.
type wcEnvelope struct {
	SSID        string                `json:"ssid"`
	Password    string                `json:"password"`
	StaticIP    models.StaticIPConfig `json:"static_ip"`
	CurrentMode string                `json:"current_mode"`
	APInterface string                `json:"ap_interface"`
	GatewayIP   string                `json:"gateway_ip"`
	Subnet      string                `json:"subnet"`
	FallbackIP  string                `json:"fallback_ip"`
	FallbackGW  string                `json:"fallback_gw"`

	// From snapshot step
	PreviousMode string `json:"previous_mode"`
	APWasRunning bool   `json:"ap_was_running"`

	// From connect step
	StationIP      string `json:"station_ip"`
	StationGateway string `json:"station_gateway"`
}

// =============================================================================
// Activity: wc.validate
// =============================================================================

func makeWCValidate(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env wcEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		if env.SSID == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("wifi_client requires SSID"))
		}

		iface := env.APInterface
		if iface == "" {
			iface = nm.GetAPInterface()
		}

		// Check interface exists
		if _, err := halClient.GetInterface(ctx, iface); err != nil {
			return nil, fmt.Errorf("interface %s not available: %w", iface, err)
		}

		log.Info().Str("ssid", env.SSID).Str("iface", iface).
			Msg("wc.validate: wifi_client switch validated")

		return marshalOutput(map[string]interface{}{
			"valid":        true,
			"ap_interface": iface,
		})
	}
}

// =============================================================================
// Activity: wc.snapshot_state
// =============================================================================

func makeWCSnapshotState(nm NetworkModeSwitcher) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		currentMode := nm.GetCurrentMode()

		return marshalOutput(map[string]interface{}{
			"previous_mode":  string(currentMode),
			"ap_was_running": currentMode != models.NetworkModeEthClient && currentMode != models.NetworkModeWifiClient,
		})
	}
}

// =============================================================================
// Activity: wc.stop_ap
// =============================================================================

func makeWCStopAP(halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		log.Info().Msg("wc.stop_ap: stopping hostapd for station mode")

		if err := halClient.StopHostapd(ctx); err != nil {
			log.Warn().Err(err).Msg("wc.stop_ap: StopHostapd failed (may already be stopped)")
		}

		// Disable NAT (we're a plain client)
		_ = halClient.DisableNAT(ctx)
		_ = halClient.DisableIPForward(ctx)

		return marshalOutput(map[string]interface{}{
			"ap_stopped": true,
		})
	}
}

// =============================================================================
// Activity: wc.connect_station
// =============================================================================

func makeWCConnectStation(halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env wcEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		iface := env.APInterface
		log.Info().Str("ssid", env.SSID).Str("iface", iface).
			Msg("wc.connect_station: connecting wlan0 as WiFi client")

		connected, err := halClient.ConnectStation(ctx, iface, env.SSID, env.Password, 30)
		if err != nil {
			return nil, fmt.Errorf("station connection failed: %w", err)
		}
		if !connected {
			return nil, flowengine.NewPermanentError(fmt.Errorf("station connection timed out after 30s"))
		}

		log.Info().Msg("wc.connect_station: station connected successfully")

		return marshalOutput(map[string]interface{}{
			"station_connected": true,
		})
	}
}

// =============================================================================
// Activity: wc.verify_station
// =============================================================================

func makeWCVerifyStation(halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env wcEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		iface := env.APInterface
		connected, err := halClient.VerifyStation(ctx, iface)
		if err != nil {
			return nil, fmt.Errorf("station verify failed: %w", err)
		}
		if !connected {
			return nil, fmt.Errorf("station not connected (no IP or gateway unreachable)")
		}

		log.Info().Msg("wc.verify_station: station connectivity verified")

		return marshalOutput(map[string]interface{}{
			"station_verified": true,
		})
	}
}

// =============================================================================
// Activity: wc.configure_dns
// =============================================================================

func makeWCConfigureDNS(nm NetworkModeSwitcher) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		log.Info().Msg("wc.configure_dns: disabling Pi-hole DHCP for wifi_client")

		nm.ConfigurePiholeDHCPForMode(ctx, models.NetworkModeWifiClient)

		return marshalOutput(map[string]interface{}{
			"dns_configured": true,
		})
	}
}

// =============================================================================
// Activity: wc.persist
// =============================================================================

func makeWCPersist(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env wcEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}

		// Update in-memory mode
		nm.SetCurrentMode(models.NetworkModeWifiClient)

		// Write netplan for reboot persistence
		nm.WriteAndApplyNetplan(ctx, models.NetworkModeWifiClient, env.SSID, env.Password, env.APInterface, env.StaticIP)

		// Save to DB
		nm.SaveConfigToDB(models.NetworkModeWifiClient, nm.GetCurrentVPNMode(), env.SSID, env.Password, env.StaticIP)

		// Fire mode change callback
		if cb := nm.GetOnModeChange(); cb != nil {
			cb(models.NetworkModeWifiClient)
		}

		log.Info().Msg("wc.persist: wifi_client mode persisted")

		return marshalOutput(map[string]interface{}{
			"persisted": true,
		})
	}
}

// =============================================================================
// Compensation: wc.revert_ap — shared compensation for all steps
// =============================================================================

func makeWCRevertAP(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		log.Warn().Msg("wc.revert_ap: reverting to offline_hotspot (wifi_client failed)")

		// Call HAL to restore AP mode
		if err := halClient.RevertToAP(ctx); err != nil {
			log.Error().Err(err).Msg("wc.revert_ap: HAL RevertToAP failed")
			// Best effort — continue to restore in-memory state
		}

		// Restore in-memory mode
		nm.SetCurrentMode(models.NetworkModeOfflineHotspot)

		// Restore Pi-hole DHCP for AP mode
		nm.ConfigurePiholeDHCPForMode(ctx, models.NetworkModeOfflineHotspot)

		// Persist the revert to DB
		nm.SaveConfigToDB(models.NetworkModeOfflineHotspot, nm.GetCurrentVPNMode(), "", "", models.StaticIPConfig{})

		log.Warn().Msg("wc.revert_ap: reverted to offline_hotspot")

		return marshalOutput(map[string]interface{}{
			"reverted": true,
			"mode":     "offline_hotspot",
		})
	}
}
