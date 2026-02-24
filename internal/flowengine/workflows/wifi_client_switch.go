// Package workflows defines workflow types for the FlowEngine.
package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

// WifiClientSwitchType is the registered type string for wifi_client switch workflows.
const WifiClientSwitchType = "wifi_client_switch"

// WifiClientSwitchWorkflow defines the steps for switching to wifi_client mode
// with connectivity verification and automatic fallback to offline_hotspot.
//
// Step sequence:
//
//  0. validate          — check SSID provided, interface available
//  1. snapshot_state    — capture current mode + AP state for rollback
//  2. stop_ap           — stop hostapd, flush wlan0
//  3. connect_station   — connect wlan0 to SSID with 30s timeout
//  4. verify_station    — ping gateway/internet
//  5. configure_dns     — disable Pi-hole DHCP
//  6. persist           — save mode to DB + write netplan
//
// Compensation chain:
//   - Any failure after stop_ap → revert to offline_hotspot via HAL /network/ap/revert
//   - The compensation for stop_ap restores hostapd
//   - The compensation for connect_station reverts netplan + restarts AP
type WifiClientSwitchWorkflow struct{}

// NewWifiClientSwitchWorkflow creates a new wifi_client switch workflow definition.
func NewWifiClientSwitchWorkflow() *WifiClientSwitchWorkflow {
	return &WifiClientSwitchWorkflow{}
}

// Type returns the workflow type identifier.
func (w *WifiClientSwitchWorkflow) Type() string {
	return WifiClientSwitchType
}

// Version returns the workflow definition version.
func (w *WifiClientSwitchWorkflow) Version() int {
	return 1
}

// Steps returns the ordered step definitions for wifi_client switching.
func (w *WifiClientSwitchWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			Name:   "validate",
			Action: "wc.validate",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1,
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 10 * time.Second,
		},
		{
			Name:   "snapshot_state",
			Action: "wc.snapshot_state",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1,
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 10 * time.Second,
		},
		{
			Name:       "stop_ap",
			Action:     "wc.stop_ap",
			Compensate: "wc.revert_ap",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1,
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 15 * time.Second,
		},
		{
			Name:       "connect_station",
			Action:     "wc.connect_station",
			Compensate: "wc.revert_ap",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1,
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 45 * time.Second, // 30s connect timeout + overhead
		},
		{
			Name:       "verify_station",
			Action:     "wc.verify_station",
			Compensate: "wc.revert_ap",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 3 * time.Second,
				MaxInterval:     5 * time.Second,
			},
			Timeout: 15 * time.Second,
		},
		{
			Name:       "configure_dns",
			Action:     "wc.configure_dns",
			Compensate: "wc.revert_ap",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 2 * time.Second,
				MaxInterval:     5 * time.Second,
			},
			Timeout: 15 * time.Second,
		},
		{
			Name:       "persist",
			Action:     "wc.persist",
			Compensate: "wc.revert_ap",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 1 * time.Second,
				MaxInterval:     2 * time.Second,
			},
			Timeout: 10 * time.Second,
		},
	}
}

// WifiClientSwitchInput is the JSON input for the wifi_client_switch workflow.
type WifiClientSwitchInput struct {
	SSID        string      `json:"ssid"`
	Password    string      `json:"password,omitempty"`
	StaticIP    interface{} `json:"static_ip,omitempty"`
	CurrentMode string      `json:"current_mode"`
	APInterface string      `json:"ap_interface"`
	GatewayIP   string      `json:"gateway_ip"`
	Subnet      string      `json:"subnet"`
	FallbackIP  string      `json:"fallback_ip,omitempty"`
	FallbackGW  string      `json:"fallback_gw,omitempty"`
}
