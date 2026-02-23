// Package workflows defines workflow types for the FlowEngine.
// Each workflow is a sequence of steps with forward and compensation activities.
package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

// NetworkModeSwitchType is the registered type string for network mode switch workflows.
const NetworkModeSwitchType = "network_mode_switch"

// NetworkModeSwitchWorkflow defines the steps for switching network modes.
//
// Step sequence:
//  0. validate           — check target mode, required params, interface availability
//  1. snapshot_state     — capture current mode + AP + NAT + netplan state for rollback
//  2. teardown_previous  — disable NAT, IP forward, disconnect WiFi based on FROM-mode
//  3. configure_upstream — bring up interface, write netplan, set static/DHCP, poll for IP
//  4. configure_services — start/stop AP, enable/disable NAT + IP forward based on TO-mode
//  5. configure_dns      — set Pi-hole DHCP config for the target mode
//  6. persist            — write final netplan for reboot + save mode to database
//
// Compensation chain (reverse order):
//   - persist comp → restore old mode in DB
//   - configure_dns comp → restore old Pi-hole config
//   - configure_services comp → restore old AP + NAT state
//   - configure_upstream comp → restore old netplan via snapshot
//   - teardown_previous comp → re-apply old mode's services from snapshot
//   - snapshot_state — no compensation (read-only)
//   - validate — no compensation (read-only)
//
// Why this order:
//   - Validate first: fail fast on bad input (no side effects)
//   - Snapshot before teardown: capture current state for rollback
//   - Teardown before configure: clean up old mode resources before setting up new ones
//   - Upstream before services: IP must be available before NAT can reference it
//   - Services before DNS: routing must work before DHCP config changes
//   - Persist last: only after all runtime config succeeds
type NetworkModeSwitchWorkflow struct{}

// NewNetworkModeSwitchWorkflow creates a new network mode switch workflow definition.
func NewNetworkModeSwitchWorkflow() *NetworkModeSwitchWorkflow {
	return &NetworkModeSwitchWorkflow{}
}

// Type returns the workflow type identifier.
func (w *NetworkModeSwitchWorkflow) Type() string {
	return NetworkModeSwitchType
}

// Version returns the workflow definition version. Bump when step sequence changes.
func (w *NetworkModeSwitchWorkflow) Version() int {
	return 1
}

// Steps returns the ordered step definitions for network mode switching.
func (w *NetworkModeSwitchWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			Name:   "validate",
			Action: "net.validate",
			// No compensation — validation is read-only
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1, // Validation failures are permanent
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 10 * time.Second,
		},
		{
			Name:   "snapshot_state",
			Action: "net.snapshot_state",
			// No compensation — snapshot is read-only
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 1 * time.Second,
				MaxInterval:     2 * time.Second,
			},
			Timeout: 10 * time.Second,
		},
		{
			Name:       "teardown_previous",
			Action:     "net.teardown_previous",
			Compensate: "net.restore_teardown",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 1 * time.Second,
				MaxInterval:     5 * time.Second,
			},
			Timeout: 15 * time.Second,
		},
		{
			Name:       "configure_upstream",
			Action:     "net.configure_upstream",
			Compensate: "net.restore_upstream",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1, // Netplan changes are not safely retryable
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 45 * time.Second, // DHCP polling can take 30s
		},
		{
			Name:       "configure_services",
			Action:     "net.configure_services",
			Compensate: "net.restore_services",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 1 * time.Second,
				MaxInterval:     5 * time.Second,
			},
			Timeout: 20 * time.Second,
		},
		{
			Name:       "configure_dns",
			Action:     "net.configure_dns",
			Compensate: "net.restore_dns",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     3, // Pi-hole API is flaky
				InitialInterval: 2 * time.Second,
				MaxInterval:     5 * time.Second,
			},
			Timeout: 15 * time.Second,
		},
		{
			Name:       "persist",
			Action:     "net.persist",
			Compensate: "net.restore_persist",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 1 * time.Second,
				MaxInterval:     2 * time.Second,
			},
			Timeout: 10 * time.Second,
		},
	}
}

// NetworkModeSwitchInput is the JSON input for the network_mode_switch workflow.
// Passed as the workflow's Input field and forwarded to the validate step.
type NetworkModeSwitchInput struct {
	TargetMode   string      `json:"target_mode"`
	CurrentMode  string      `json:"current_mode"`
	SSID         string      `json:"ssid,omitempty"`
	Password     string      `json:"password,omitempty"`
	StaticIP     interface{} `json:"static_ip,omitempty"`
	GatewayIP    string      `json:"gateway_ip"`
	Subnet       string      `json:"subnet"`
	APInterface  string      `json:"ap_interface"`
	WANInterface string      `json:"wan_interface"`
	FallbackIP   string      `json:"fallback_ip,omitempty"`
	FallbackGW   string      `json:"fallback_gw,omitempty"`
}
