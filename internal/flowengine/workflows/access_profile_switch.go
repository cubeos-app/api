package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

const (
	// AccessProfileSwitchType is the workflow type for access profile migration.
	AccessProfileSwitchType = "access_profile_switch"
	// AccessProfileSwitchVersion is the current version of the workflow definition.
	AccessProfileSwitchVersion = 2
)

// AccessProfileSwitchWorkflow defines the step sequence for migrating all installed
// apps' DNS/proxy entries between access profiles (standard, advanced, all_in_one).
//
// Step order:
//  0. validate_transition — check target profile feasibility (external service reachability)
//  1. pause_app_updates — set profile_switch_in_progress flag
//  2. teardown_old_access — remove DNS/proxy from old system
//  3. update_profile_db — write new profile to system_config
//  4. configure_new_services — enable/disable DHCP/DNS/proxy flags
//  5. migrate_app_entries — bulk create DNS/proxy in new system, update access_urls
//  6. verify_access — spot-check random apps (warn-only)
//  7. resume_app_updates — clear profile_switch_in_progress flag
//  8. reboot — initiate system reboot so boot scripts apply new profile infrastructure
type AccessProfileSwitchWorkflow struct{}

func (w *AccessProfileSwitchWorkflow) Type() string { return AccessProfileSwitchType }
func (w *AccessProfileSwitchWorkflow) Version() int { return AccessProfileSwitchVersion }

func (w *AccessProfileSwitchWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			Name:       "validate_transition",
			Action:     "profile.validate_transition",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    15 * time.Second,
		},
		{
			Name:       "pause_app_updates",
			Action:     "profile.pause_app_updates",
			Compensate: "profile.resume_app_updates",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 500 * time.Millisecond},
			Timeout:    5 * time.Second,
		},
		{
			Name:       "teardown_old_access",
			Action:     "profile.teardown_old_access",
			Compensate: "profile.restore_old_access",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 1 * time.Second},
			Timeout:    60 * time.Second,
		},
		{
			Name:       "update_profile_db",
			Action:     "profile.update_profile_db",
			Compensate: "profile.restore_profile_db",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 500 * time.Millisecond},
			Timeout:    10 * time.Second,
		},
		{
			Name:       "configure_new_services",
			Action:     "profile.configure_new_services",
			Compensate: "profile.restore_old_services",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 1 * time.Second},
			Timeout:    30 * time.Second,
		},
		{
			Name:       "migrate_app_entries",
			Action:     "profile.migrate_app_entries",
			Compensate: "profile.rollback_app_entries",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 2 * time.Second},
			Timeout:    300 * time.Second,
		},
		{
			Name:       "verify_access",
			Action:     "profile.verify_access",
			Compensate: "", // informational only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    30 * time.Second,
		},
		{
			Name:       "resume_app_updates",
			Action:     "profile.resume_app_updates",
			Compensate: "", // always succeeds
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 500 * time.Millisecond},
			Timeout:    5 * time.Second,
		},
		{
			Name:       "reboot",
			Action:     "hal.reboot",
			Compensate: "", // reboot is irreversible
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 1 * time.Second},
			Timeout:    15 * time.Second,
		},
	}
}

// NewAccessProfileSwitchWorkflow creates a new workflow definition.
func NewAccessProfileSwitchWorkflow() *AccessProfileSwitchWorkflow {
	return &AccessProfileSwitchWorkflow{}
}
