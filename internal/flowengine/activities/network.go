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

// NetworkModeSwitcher defines the subset of NetworkManager methods needed by
// network activities. Satisfied by *managers.NetworkManager.
// Using the full manager preserves all battle-tested bug fixes (B88, B92, B94,
// B96b, B118, B126) without rewriting the logic.
type NetworkModeSwitcher interface {
	// Mode switching internals (exported by NetworkManager)
	SetOfflineHotspotModeInline(ctx context.Context) error
	SetWifiRouterModeInline(ctx context.Context, staticIP models.StaticIPConfig) error
	SetWifiBridgeModeInline(ctx context.Context, ssid, password string, staticIP models.StaticIPConfig) error
	SetAndroidTetherModeInline(ctx context.Context) error
	SetEthClientModeInline(ctx context.Context, staticIP models.StaticIPConfig) error
	SetWifiClientModeInline(ctx context.Context, ssid, password string, staticIP models.StaticIPConfig) error

	// Netplan + persistence helpers
	GenerateNetplanYAML(mode models.NetworkMode, wifiSSID, wifiPassword string, staticIP models.StaticIPConfig) string
	WriteAndApplyNetplan(ctx context.Context, mode models.NetworkMode, wifiSSID, wifiPassword, reconfigureIface string, staticIP models.StaticIPConfig)
	PollForIP(ctx context.Context, iface string, timeoutSeconds int) error
	ConfigurePiholeDHCPForMode(ctx context.Context, mode models.NetworkMode)
	SaveConfigToDB(mode models.NetworkMode, vpnMode models.VPNMode, wifiSSID, wifiPassword string, staticIP models.StaticIPConfig)

	// Accessors
	GetCurrentMode() models.NetworkMode
	GetCurrentVPNMode() models.VPNMode
	SetCurrentMode(mode models.NetworkMode)
	IsServerMode() bool
	HasInternet() bool
	ResolveWiFiClientInterface(ctx context.Context) string
	DetectWiFiClientInterface(ctx context.Context) (string, error)
	GetOnModeChange() func(models.NetworkMode)

	// Config accessors
	GetAPInterface() string
	GetWANInterface() string
	GetFallbackIP() string
	GetFallbackGateway() string
	GetSubnet() string
	GetGatewayIP() string
}

// RegisterNetworkActivities registers all network mode switching activities
// in the FlowEngine activity registry.
//
// Activities:
//   - net.validate, net.snapshot_state, net.teardown_previous, net.restore_teardown,
//     net.configure_upstream, net.restore_upstream, net.configure_services,
//     net.restore_services, net.configure_dns, net.restore_dns, net.persist,
//     net.restore_persist
func RegisterNetworkActivities(registry *flowengine.ActivityRegistry, nm NetworkModeSwitcher, halClient *hal.Client) {
	registry.MustRegister("net.validate", makeNetValidate(nm, halClient))
	registry.MustRegister("net.snapshot_state", makeNetSnapshotState(nm, halClient))
	registry.MustRegister("net.teardown_previous", makeNetTeardownPrevious(nm, halClient))
	registry.MustRegister("net.restore_teardown", makeNetRestoreTeardown(nm, halClient))
	registry.MustRegister("net.configure_upstream", makeNetConfigureUpstream(nm, halClient))
	registry.MustRegister("net.restore_upstream", makeNetRestoreUpstream(nm, halClient))
	registry.MustRegister("net.configure_services", makeNetConfigureServices(nm, halClient))
	registry.MustRegister("net.restore_services", makeNetRestoreServices(nm, halClient))
	registry.MustRegister("net.configure_dns", makeNetConfigureDNS(nm))
	registry.MustRegister("net.restore_dns", makeNetRestoreDNS(nm))
	registry.MustRegister("net.persist", makeNetPersist(nm, halClient))
	registry.MustRegister("net.restore_persist", makeNetRestorePersist(nm))
}

// =============================================================================
// Input/Output types for the fat envelope
// =============================================================================

// netEnvelope is the combined input available to all steps via fat envelope merge.
type netEnvelope struct {
	TargetMode   string                `json:"target_mode"`
	CurrentMode  string                `json:"current_mode"`
	SSID         string                `json:"ssid"`
	Password     string                `json:"password"`
	StaticIP     models.StaticIPConfig `json:"static_ip"`
	GatewayIP    string                `json:"gateway_ip"`
	Subnet       string                `json:"subnet"`
	APInterface  string                `json:"ap_interface"`
	WANInterface string                `json:"wan_interface"`
	FallbackIP   string                `json:"fallback_ip"`
	FallbackGW   string                `json:"fallback_gw"`

	// From validate step
	Valid             bool   `json:"valid"`
	UpstreamInterface string `json:"upstream_interface"`

	// From snapshot step
	PreviousMode         string `json:"previous_mode"`
	APWasRunning         bool   `json:"ap_was_running"`
	NATWasEnabled        bool   `json:"nat_was_enabled"`
	ForwardingWasEnabled bool   `json:"forwarding_was_enabled"`
	PreviousVPNMode      string `json:"previous_vpn_mode"`
}

// =============================================================================
// Activity: net.validate
// =============================================================================

func makeNetValidate(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid validate input: %w", err))
		}

		targetMode := models.NetworkMode(env.TargetMode)

		// Validate mode is one of the 6 valid modes
		switch targetMode {
		case models.NetworkModeOfflineHotspot, models.NetworkModeWifiRouter, models.NetworkModeWifiBridge,
			models.NetworkModeAndroidTether, models.NetworkModeEthClient, models.NetworkModeWifiClient:
			// valid
		default:
			return nil, flowengine.NewPermanentError(fmt.Errorf("unknown network mode: %s", env.TargetMode))
		}

		// Check SSID required for wifi modes
		if (targetMode == models.NetworkModeWifiBridge || targetMode == models.NetworkModeWifiClient) && env.SSID == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("wifi SSID required for %s mode", env.TargetMode))
		}

		// Resolve upstream interface for the target mode
		var upstreamIface string
		switch targetMode {
		case models.NetworkModeWifiRouter, models.NetworkModeEthClient:
			upstreamIface = env.WANInterface
			// Check eth0 exists via HAL
			iface, err := halClient.GetInterface(ctx, upstreamIface)
			if err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("ethernet interface %s not available: %w", upstreamIface, err))
			}
			log.Info().Str("iface", iface.Name).Bool("up", iface.IsUp).Msg("net.validate: ethernet interface found")

		case models.NetworkModeWifiBridge:
			// Detect USB WiFi dongle (wlan1/wlx*)
			detected, err := nm.DetectWiFiClientInterface(ctx)
			if err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("no USB WiFi dongle detected: %w", err))
			}
			upstreamIface = detected
			log.Info().Str("iface", upstreamIface).Msg("net.validate: WiFi client interface detected")

		case models.NetworkModeAndroidTether:
			// Check Android tethering device
			tetherStatus, err := halClient.GetAndroidTetheringStatus(ctx)
			if err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("failed to check Android tethering: %w", err))
			}
			if !tetherStatus.Connected {
				return nil, flowengine.NewPermanentError(fmt.Errorf("no Android tethering device detected — connect a phone with USB tethering enabled"))
			}
			upstreamIface = tetherStatus.Interface
			log.Info().Str("iface", upstreamIface).Msg("net.validate: tethering interface detected")

		case models.NetworkModeWifiClient:
			// wlan0 will be freed from AP — just validate it exists
			upstreamIface = env.APInterface
			_, err := halClient.GetInterface(ctx, upstreamIface)
			if err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("WiFi interface %s not available: %w", upstreamIface, err))
			}

		case models.NetworkModeOfflineHotspot:
			// No upstream interface needed
			upstreamIface = ""
		}

		return marshalOutput(map[string]interface{}{
			"valid":              true,
			"upstream_interface": upstreamIface,
		})
	}
}

// =============================================================================
// Activity: net.snapshot_state
// =============================================================================

func makeNetSnapshotState(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid snapshot input: %w", err))
		}

		previousMode := nm.GetCurrentMode()
		previousVPN := nm.GetCurrentVPNMode()

		// Check AP status
		apRunning := false
		if halClient != nil {
			apStatus, err := halClient.GetAPStatus(ctx)
			if err == nil && apStatus != nil && apStatus.SSID != "" {
				apRunning = true
			}
		}

		// Check NAT/forwarding status
		natEnabled := false
		forwardingEnabled := false
		if halClient != nil {
			fwStatus, err := halClient.GetHALFirewallStatus(ctx)
			if err == nil && fwStatus != nil {
				natEnabled = fwStatus.NAT
				forwardingEnabled = fwStatus.Forwarding
			}
		}

		snapshot := map[string]interface{}{
			"previous_mode":          string(previousMode),
			"previous_vpn_mode":      string(previousVPN),
			"ap_was_running":         apRunning,
			"nat_was_enabled":        natEnabled,
			"forwarding_was_enabled": forwardingEnabled,
			"gateway_ip":             nm.GetGatewayIP(),
			"subnet":                 nm.GetSubnet(),
		}

		log.Info().
			Str("previous_mode", string(previousMode)).
			Bool("ap_running", apRunning).
			Bool("nat", natEnabled).
			Bool("forwarding", forwardingEnabled).
			Msg("net.snapshot_state: captured current state")

		return marshalOutput(snapshot)
	}
}

// =============================================================================
// Activity: net.teardown_previous
// =============================================================================

func makeNetTeardownPrevious(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid teardown input: %w", err))
		}

		currentMode := models.NetworkMode(env.CurrentMode)

		// Disable NAT and IP forwarding — non-fatal (may already be disabled)
		switch currentMode {
		case models.NetworkModeWifiRouter, models.NetworkModeWifiBridge, models.NetworkModeAndroidTether:
			if err := halClient.DisableNAT(ctx); err != nil {
				log.Warn().Err(err).Msg("net.teardown_previous: DisableNAT failed (non-fatal)")
			}
			if err := halClient.DisableIPForward(ctx); err != nil {
				log.Warn().Err(err).Msg("net.teardown_previous: DisableIPForward failed (non-fatal)")
			}
		}

		// Disconnect upstream WiFi if coming from a WiFi mode
		switch currentMode {
		case models.NetworkModeWifiBridge:
			iface := nm.ResolveWiFiClientInterface(ctx)
			if err := halClient.DisconnectWiFi(ctx, iface); err != nil {
				log.Warn().Err(err).Str("iface", iface).Msg("net.teardown_previous: DisconnectWiFi failed (non-fatal)")
			}
		case models.NetworkModeWifiClient:
			if err := halClient.DisconnectWiFi(ctx, env.APInterface); err != nil {
				log.Warn().Err(err).Msg("net.teardown_previous: DisconnectWiFi wlan0 failed (non-fatal)")
			}
		}

		log.Info().Str("from_mode", env.CurrentMode).Msg("net.teardown_previous: completed")

		return marshalOutput(map[string]interface{}{
			"teardown_complete": true,
		})
	}
}

// =============================================================================
// Compensation: net.restore_teardown
// =============================================================================

func makeNetRestoreTeardown(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore_teardown input: %w", err))
		}

		// Re-enable what was disabled, based on snapshot
		if env.NATWasEnabled {
			if err := halClient.EnableNAT(ctx, env.Subnet, env.WANInterface); err != nil {
				log.Warn().Err(err).Msg("net.restore_teardown: EnableNAT failed")
			}
		}
		if env.ForwardingWasEnabled {
			if err := halClient.EnableIPForward(ctx); err != nil {
				log.Warn().Err(err).Msg("net.restore_teardown: EnableIPForward failed")
			}
		}

		log.Info().Msg("net.restore_teardown: restored previous NAT/forwarding state")
		return marshalOutput(map[string]interface{}{"restored": true})
	}
}

// =============================================================================
// Activity: net.configure_upstream
// =============================================================================

func makeNetConfigureUpstream(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid configure_upstream input: %w", err))
		}

		targetMode := models.NetworkMode(env.TargetMode)

		switch targetMode {
		case models.NetworkModeOfflineHotspot:
			// No upstream to configure
			log.Info().Msg("net.configure_upstream: offline_hotspot mode, no upstream needed")
			return marshalOutput(map[string]interface{}{
				"upstream_configured": true,
				"ip_acquired":         false,
			})

		case models.NetworkModeWifiRouter:
			return configureUpstreamETH(ctx, nm, halClient, env)

		case models.NetworkModeWifiBridge:
			return configureUpstreamWiFi(ctx, nm, halClient, env)

		case models.NetworkModeAndroidTether:
			return configureUpstreamTether(ctx, nm, halClient, env)

		case models.NetworkModeEthClient:
			return configureUpstreamServerETH(ctx, nm, halClient, env)

		case models.NetworkModeWifiClient:
			return configureUpstreamServerWiFi(ctx, nm, halClient, env)

		default:
			return nil, flowengine.NewPermanentError(fmt.Errorf("unknown mode for upstream config: %s", env.TargetMode))
		}
	}
}

// configureUpstreamETH handles wifi_router upstream configuration.
// B88: Netplan-first DHCP. B94: Non-fatal DHCP timeout.
func configureUpstreamETH(ctx context.Context, nm NetworkModeSwitcher, halClient *hal.Client, env netEnvelope) (json.RawMessage, error) {
	iface, err := halClient.GetInterface(ctx, env.WANInterface)
	if err != nil {
		return nil, fmt.Errorf("ethernet interface not available: %w", err)
	}
	if !iface.IsUp {
		if err := halClient.BringInterfaceUp(ctx, env.WANInterface); err != nil {
			return nil, fmt.Errorf("failed to bring up ethernet: %w", err)
		}
	}

	ipAcquired := true
	if env.StaticIP.IsConfigured() {
		log.Info().Str("ip", env.StaticIP.StaticIPAddress).Str("gw", env.StaticIP.StaticIPGateway).
			Msg("net.configure_upstream: setting static IP on ethernet")
		if err := halClient.SetStaticIP(ctx, env.WANInterface, env.StaticIP.StaticIPAddress, env.StaticIP.StaticIPGateway); err != nil {
			return nil, fmt.Errorf("failed to set static IP on %s: %w", env.WANInterface, err)
		}
	} else if len(iface.IPv4Addresses) == 0 {
		// B88: Write netplan with dhcp4:true → netplan apply → networkd handles DHCP
		yaml := nm.GenerateNetplanYAML(models.NetworkModeWifiRouter, "", "", env.StaticIP)
		if err := halClient.WriteNetplan(ctx, yaml, env.WANInterface); err != nil {
			return nil, fmt.Errorf("failed to write/apply DHCP netplan on %s: %w", env.WANInterface, err)
		}
		// B94: DHCP timeout is non-fatal — networkd continues retrying
		if err := nm.PollForIP(ctx, env.WANInterface, 30); err != nil {
			log.Warn().Err(err).Str("iface", env.WANInterface).
				Msg("net.configure_upstream: ethernet DHCP timeout — networkd retrying in background")
			ipAcquired = false
		}
	}

	return marshalOutput(map[string]interface{}{
		"upstream_configured": true,
		"ip_acquired":         ipAcquired,
	})
}

// configureUpstreamWiFi handles wifi_bridge upstream configuration.
// B126: Netplan-first flow — write netplan with WiFi creds, let networkd start wpa_supplicant.
func configureUpstreamWiFi(ctx context.Context, nm NetworkModeSwitcher, halClient *hal.Client, env netEnvelope) (json.RawMessage, error) {
	iface := env.UpstreamInterface
	if iface == "" {
		// Fallback to dynamic detection
		detected, err := nm.DetectWiFiClientInterface(ctx)
		if err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("no USB WiFi dongle detected: %w", err))
		}
		iface = detected
	}

	ifaceInfo, err := halClient.GetInterface(ctx, iface)
	if err != nil {
		return nil, fmt.Errorf("WiFi client interface not available: %w", err)
	}
	if !ifaceInfo.IsUp {
		if err := halClient.BringInterfaceUp(ctx, iface); err != nil {
			return nil, fmt.Errorf("failed to bring up WiFi client interface: %w", err)
		}
	}

	// B126: Write netplan FIRST with WiFi creds → networkd starts wpa_supplicant
	log.Info().Str("iface", iface).Str("ssid", env.SSID).
		Msg("net.configure_upstream: writing netplan with WiFi credentials (B126)")
	yaml := nm.GenerateNetplanYAML(models.NetworkModeWifiBridge, env.SSID, env.Password, env.StaticIP)
	if err := halClient.WriteNetplan(ctx, yaml, iface); err != nil {
		return nil, fmt.Errorf("failed to write WiFi netplan: %w", err)
	}

	ipAcquired := true
	if err := nm.PollForIP(ctx, iface, 30); err != nil {
		log.Warn().Err(err).Str("iface", iface).
			Msg("net.configure_upstream: WiFi connection timeout")
		ipAcquired = false
	}

	return marshalOutput(map[string]interface{}{
		"upstream_configured": true,
		"ip_acquired":         ipAcquired,
		"upstream_interface":  iface,
	})
}

// configureUpstreamTether handles android_tether upstream configuration.
// B96b: EnableAndroidTethering includes ip link set up.
func configureUpstreamTether(ctx context.Context, nm NetworkModeSwitcher, halClient *hal.Client, env netEnvelope) (json.RawMessage, error) {
	tetherIface := env.UpstreamInterface

	// Write offline_hotspot-style netplan (wlan0 AP only, tether managed manually)
	yaml := nm.GenerateNetplanYAML(models.NetworkModeAndroidTether, "", "", models.StaticIPConfig{})
	if err := halClient.WriteNetplan(ctx, yaml, ""); err != nil {
		log.Warn().Err(err).Msg("net.configure_upstream: tether netplan write failed (non-fatal)")
	}

	// B96b: HAL brings interface UP + runs DHCP
	if err := halClient.EnableAndroidTethering(ctx); err != nil {
		return nil, fmt.Errorf("failed to enable Android tethering on %s: %w", tetherIface, err)
	}

	ipAcquired := true
	if err := nm.PollForIP(ctx, tetherIface, 15); err != nil {
		log.Warn().Err(err).Str("iface", tetherIface).
			Msg("net.configure_upstream: tether DHCP timeout")
		ipAcquired = false
	}

	return marshalOutput(map[string]interface{}{
		"upstream_configured": true,
		"ip_acquired":         ipAcquired,
	})
}

// configureUpstreamServerETH handles eth_client upstream configuration.
// B88: Netplan-first DHCP with fallback to static IP.
func configureUpstreamServerETH(ctx context.Context, nm NetworkModeSwitcher, halClient *hal.Client, env netEnvelope) (json.RawMessage, error) {
	if err := halClient.BringInterfaceUp(ctx, env.WANInterface); err != nil {
		return nil, fmt.Errorf("failed to bring up ethernet: %w", err)
	}

	if env.StaticIP.IsConfigured() {
		if err := halClient.SetStaticIP(ctx, env.WANInterface, env.StaticIP.StaticIPAddress, env.StaticIP.StaticIPGateway); err != nil {
			return nil, fmt.Errorf("failed to set static IP: %w", err)
		}
	} else {
		// B88: netplan write+apply+poll with fallback to static
		yaml := nm.GenerateNetplanYAML(models.NetworkModeEthClient, "", "", env.StaticIP)
		if err := halClient.WriteNetplan(ctx, yaml, env.WANInterface); err != nil {
			log.Warn().Err(err).Str("fallbackIP", env.FallbackIP).
				Msg("net.configure_upstream: netplan write failed, using fallback static IP")
			if err := halClient.SetStaticIP(ctx, env.WANInterface, env.FallbackIP, env.FallbackGW); err != nil {
				return nil, fmt.Errorf("failed to set fallback IP: %w", err)
			}
		} else if err := nm.PollForIP(ctx, env.WANInterface, 15); err != nil {
			log.Warn().Err(err).Str("fallbackIP", env.FallbackIP).
				Msg("net.configure_upstream: DHCP timeout, using fallback static IP")
			if err := halClient.SetStaticIP(ctx, env.WANInterface, env.FallbackIP, env.FallbackGW); err != nil {
				return nil, fmt.Errorf("failed to set fallback IP: %w", err)
			}
		}
	}

	return marshalOutput(map[string]interface{}{
		"upstream_configured": true,
		"ip_acquired":         true,
	})
}

// configureUpstreamServerWiFi handles wifi_client upstream configuration.
// B88: Netplan-first DHCP with fallback to static IP.
func configureUpstreamServerWiFi(ctx context.Context, nm NetworkModeSwitcher, halClient *hal.Client, env netEnvelope) (json.RawMessage, error) {
	// Wait for hostapd to release wlan0 (teardown step stopped AP if needed)
	// ConnectWiFi on wlan0 — not the USB dongle
	if err := halClient.ConnectWiFi(ctx, env.APInterface, env.SSID, env.Password); err != nil {
		return nil, fmt.Errorf("failed to connect to WiFi: %w", err)
	}

	if env.StaticIP.IsConfigured() {
		if err := halClient.SetStaticIP(ctx, env.APInterface, env.StaticIP.StaticIPAddress, env.StaticIP.StaticIPGateway); err != nil {
			log.Warn().Err(err).Msg("net.configure_upstream: static IP on wlan0 failed")
		}
	} else {
		// B88: netplan write+apply+poll with fallback to static
		yaml := nm.GenerateNetplanYAML(models.NetworkModeWifiClient, env.SSID, env.Password, env.StaticIP)
		if err := halClient.WriteNetplan(ctx, yaml, env.APInterface); err != nil {
			log.Warn().Err(err).Msg("net.configure_upstream: server WiFi netplan write failed")
		}
		if err := nm.PollForIP(ctx, env.APInterface, 15); err != nil {
			log.Warn().Str("fallbackIP", env.FallbackIP).
				Msg("net.configure_upstream: no IP assigned, using fallback")
			if err := halClient.SetStaticIP(ctx, env.APInterface, env.FallbackIP, env.FallbackGW); err != nil {
				return nil, fmt.Errorf("failed to set fallback IP: %w", err)
			}
		}
	}

	return marshalOutput(map[string]interface{}{
		"upstream_configured": true,
		"ip_acquired":         true,
	})
}

// =============================================================================
// Compensation: net.restore_upstream
// =============================================================================

func makeNetRestoreUpstream(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore_upstream input: %w", err))
		}

		// Restore previous mode's netplan
		previousMode := models.NetworkMode(env.PreviousMode)
		yaml := nm.GenerateNetplanYAML(previousMode, env.SSID, env.Password, env.StaticIP)
		if err := halClient.WriteNetplan(ctx, yaml, ""); err != nil {
			log.Warn().Err(err).Msg("net.restore_upstream: failed to restore netplan")
		}

		log.Info().Str("previous_mode", env.PreviousMode).Msg("net.restore_upstream: restored previous netplan")
		return marshalOutput(map[string]interface{}{"restored": true})
	}
}

// =============================================================================
// Activity: net.configure_services
// =============================================================================

func makeNetConfigureServices(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid configure_services input: %w", err))
		}

		targetMode := models.NetworkMode(env.TargetMode)
		previousMode := models.NetworkMode(env.PreviousMode)
		apRunning := false
		natEnabled := false

		switch targetMode {
		case models.NetworkModeOfflineHotspot, models.NetworkModeWifiRouter, models.NetworkModeWifiBridge, models.NetworkModeAndroidTether:
			// AP modes: ensure AP is running
			// If coming from server mode, AP was stopped — restart it
			if previousMode == models.NetworkModeEthClient || previousMode == models.NetworkModeWifiClient {
				if err := halClient.StartAP(ctx, env.APInterface); err != nil {
					log.Error().Err(err).Msg("net.configure_services: failed to start AP")
				}
			}
			apRunning = true

			// Online modes need NAT + forwarding
			if targetMode != models.NetworkModeOfflineHotspot {
				if err := halClient.EnableIPForward(ctx); err != nil {
					return nil, fmt.Errorf("failed to enable IP forwarding: %w", err)
				}

				// B118: NAT uses subnet CIDR, not AP interface
				upstreamIface := env.UpstreamInterface
				if upstreamIface == "" {
					upstreamIface = env.WANInterface
				}
				if err := halClient.EnableNAT(ctx, env.Subnet, upstreamIface); err != nil {
					return nil, fmt.Errorf("failed to enable NAT: %w", err)
				}
				natEnabled = true
			}

		case models.NetworkModeEthClient, models.NetworkModeWifiClient:
			// Server modes: stop AP (if was running from an AP mode)
			if previousMode != models.NetworkModeEthClient && previousMode != models.NetworkModeWifiClient {
				if err := halClient.StopAP(ctx, env.APInterface); err != nil {
					log.Warn().Err(err).Msg("net.configure_services: failed to stop AP (may not be running)")
				}
			}
			// NAT/forwarding already disabled in teardown
			apRunning = false
			natEnabled = false
		}

		log.Info().
			Str("target_mode", env.TargetMode).
			Bool("ap_running", apRunning).
			Bool("nat_enabled", natEnabled).
			Msg("net.configure_services: completed")

		return marshalOutput(map[string]interface{}{
			"ap_running":  apRunning,
			"nat_enabled": natEnabled,
		})
	}
}

// =============================================================================
// Compensation: net.restore_services
// =============================================================================

func makeNetRestoreServices(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore_services input: %w", err))
		}

		// Restore AP state from snapshot
		if env.APWasRunning {
			if err := halClient.StartAP(ctx, env.APInterface); err != nil {
				log.Warn().Err(err).Msg("net.restore_services: failed to restart AP")
			}
		} else {
			if err := halClient.StopAP(ctx, env.APInterface); err != nil {
				log.Warn().Err(err).Msg("net.restore_services: failed to stop AP")
			}
		}

		// Restore NAT/forwarding from snapshot
		if env.NATWasEnabled {
			_ = halClient.EnableIPForward(ctx)
			_ = halClient.EnableNAT(ctx, env.Subnet, env.WANInterface)
		} else {
			_ = halClient.DisableNAT(ctx)
			_ = halClient.DisableIPForward(ctx)
		}

		log.Info().Msg("net.restore_services: restored previous AP/NAT state")
		return marshalOutput(map[string]interface{}{"restored": true})
	}
}

// =============================================================================
// Activity: net.configure_dns
// =============================================================================

func makeNetConfigureDNS(nm NetworkModeSwitcher) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid configure_dns input: %w", err))
		}

		targetMode := models.NetworkMode(env.TargetMode)
		nm.ConfigurePiholeDHCPForMode(ctx, targetMode)

		log.Info().Str("mode", env.TargetMode).Msg("net.configure_dns: Pi-hole DHCP configured")
		return marshalOutput(map[string]interface{}{
			"dns_configured": true,
		})
	}
}

// =============================================================================
// Compensation: net.restore_dns
// =============================================================================

func makeNetRestoreDNS(nm NetworkModeSwitcher) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore_dns input: %w", err))
		}

		previousMode := models.NetworkMode(env.PreviousMode)
		nm.ConfigurePiholeDHCPForMode(ctx, previousMode)

		log.Info().Str("mode", env.PreviousMode).Msg("net.restore_dns: restored Pi-hole DHCP config")
		return marshalOutput(map[string]interface{}{"restored": true})
	}
}

// =============================================================================
// Activity: net.persist
// =============================================================================

func makeNetPersist(nm NetworkModeSwitcher, halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid persist input: %w", err))
		}

		targetMode := models.NetworkMode(env.TargetMode)

		// Write final netplan for reboot persistence
		reconfigureIface := ""
		switch targetMode {
		case models.NetworkModeWifiRouter, models.NetworkModeEthClient:
			reconfigureIface = env.WANInterface
		case models.NetworkModeWifiBridge:
			reconfigureIface = env.UpstreamInterface
		case models.NetworkModeWifiClient:
			reconfigureIface = env.APInterface
		}
		nm.WriteAndApplyNetplan(ctx, targetMode, env.SSID, env.Password, reconfigureIface, env.StaticIP)

		// Save to database
		nm.SaveConfigToDB(targetMode, models.VPNMode(env.PreviousVPNMode), env.SSID, env.Password, env.StaticIP)

		// Update in-memory mode
		nm.SetCurrentMode(targetMode)

		// If switching to mode without internet, VPN is handled by the caller (SetMode wrapper)
		// Fire onModeChange callback (triggers app store sync when going online)
		if cb := nm.GetOnModeChange(); cb != nil {
			cb(targetMode)
		}

		log.Info().Str("mode", env.TargetMode).Msg("net.persist: mode persisted and activated")
		return marshalOutput(map[string]interface{}{
			"persisted": true,
			"mode":      env.TargetMode,
		})
	}
}

// =============================================================================
// Compensation: net.restore_persist
// =============================================================================

func makeNetRestorePersist(nm NetworkModeSwitcher) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var env netEnvelope
		if err := json.Unmarshal(input, &env); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore_persist input: %w", err))
		}

		previousMode := models.NetworkMode(env.PreviousMode)

		// Restore old mode in DB and memory
		nm.SaveConfigToDB(previousMode, models.VPNMode(env.PreviousVPNMode), env.SSID, env.Password, env.StaticIP)
		nm.SetCurrentMode(previousMode)

		log.Info().Str("mode", env.PreviousMode).Msg("net.restore_persist: restored previous mode in DB")
		return marshalOutput(map[string]interface{}{"restored": true})
	}
}
