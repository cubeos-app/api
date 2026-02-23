// Package workflows defines workflow types for the FlowEngine.
// Each workflow is a sequence of steps with forward and compensation activities.
package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

// FirstBootSetupType is the registered type string for first-boot setup workflows.
const FirstBootSetupType = "first_boot_setup"

// FirstBootSetupWorkflow defines the steps for initial device setup.
//
// Step sequence:
//
//  0. validate          — validate SetupConfig (read-only, fail fast)
//  1. create_admin      — create admin user, bcrypt hash, JWT secret, save to DB
//  2. set_hostname      — write /host-root/etc/hostname + /etc/hosts, HAL SetHostname
//  3. configure_wifi    — snapshot hostapd.conf, save country_code, write hostapd, restart via HAL
//  4. configure_system  — timezone, theme, purpose, SSL, NPM creds, features (all DB/file)
//  5. sync_passwords    — fire-and-forget goroutines to FileBrowser/Pi-hole/NPM (NON-FATAL)
//  6. mark_complete     — set DB flag, save config JSON, create .setup_complete file
//
// Compensation chain (reverse order):
//   - mark_complete comp → unmark_complete: reset DB flag so wizard can retry
//   - configure_wifi comp → restore_wifi: restore original hostapd.conf and restart
//   - All other steps: no compensation (idempotent on retry, safe to leave in place)
//
// Why this order:
//   - Validate first: fail fast on bad input (no side effects)
//   - Admin user early: DB write, low risk, needed for auth context
//   - Hostname before WiFi: safe, doesn't disconnect user
//   - WiFi is DANGEROUS: restarts hostapd → disconnects user — after safe steps
//   - System config after WiFi: DB/file writes only, no external services
//   - Password sync is fire-and-forget: non-fatal, after main config
//   - Mark complete LAST: only if all prior steps succeeded
type FirstBootSetupWorkflow struct{}

// NewFirstBootSetupWorkflow creates a new first-boot setup workflow definition.
func NewFirstBootSetupWorkflow() *FirstBootSetupWorkflow {
	return &FirstBootSetupWorkflow{}
}

// Type returns the workflow type identifier.
func (w *FirstBootSetupWorkflow) Type() string {
	return FirstBootSetupType
}

// Version returns the workflow definition version. Bump when step sequence changes.
func (w *FirstBootSetupWorkflow) Version() int {
	return 1
}

// Steps returns the ordered step definitions for first-boot setup.
func (w *FirstBootSetupWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			Name:   "validate",
			Action: "setup.validate",
			// No compensation — validation is read-only
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1, // Validation failures are permanent
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 10 * time.Second,
		},
		{
			Name:   "create_admin",
			Action: "setup.create_admin",
			// No compensation — idempotent INSERT OR REPLACE, safe to leave
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 1 * time.Second,
				MaxInterval:     2 * time.Second,
			},
			Timeout: 10 * time.Second, // bcrypt can be slow on Pi
		},
		{
			Name:   "set_hostname",
			Action: "setup.set_hostname",
			// No compensation — idempotent file write, safe to leave
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 1 * time.Second,
				MaxInterval:     2 * time.Second,
			},
			Timeout: 15 * time.Second, // HAL call
		},
		{
			Name:       "configure_wifi",
			Action:     "setup.configure_wifi",
			Compensate: "setup.restore_wifi",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1, // NOT safely retryable — hostapd state could be inconsistent
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 30 * time.Second, // hostapd restart can be slow
		},
		{
			Name:   "configure_system",
			Action: "setup.configure_system",
			// No compensation — DB/file writes, idempotent on retry
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     2,
				InitialInterval: 1 * time.Second,
				MaxInterval:     5 * time.Second,
			},
			Timeout: 30 * time.Second, // SSL cert generation if self-signed
		},
		{
			Name:   "sync_passwords",
			Action: "setup.sync_passwords",
			// No compensation — fire-and-forget, always succeeds
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1,
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 5 * time.Second, // Just fires goroutines, doesn't wait
		},
		{
			Name:       "mark_complete",
			Action:     "setup.mark_complete",
			Compensate: "setup.unmark_complete",
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     3,
				InitialInterval: 1 * time.Second,
				MaxInterval:     3 * time.Second,
			},
			Timeout: 10 * time.Second,
		},
	}
}
