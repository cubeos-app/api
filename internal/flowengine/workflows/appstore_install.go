package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

const (
	// AppStoreInstallType is the workflow type for app store installation.
	AppStoreInstallType = "appstore_install"
	// AppStoreInstallVersion is the current version of the workflow definition.
	AppStoreInstallVersion = 1
)

// AppStoreInstallWorkflow defines the step sequence for installing an app from the CasaOS store.
// Replaces AppStoreManager.InstallAppWithProgress() with tracked, compensating steps.
//
// Step order maps 1:1 to the current 10-step SSE progress flow:
//
//	Current SSE step     → FlowEngine step
//	setup (10%)          → validate, read_manifest
//	port (20-25%)        → allocate_port
//	manifest (30%)       → process_manifest
//	compose (35%)        → create_dirs, remap_volumes, write_compose
//	deploy (50-70%)      → deploy_stack, wait_convergence
//	dns (80%)            → add_dns
//	proxy (90%)          → create_proxy
//	database (95%)       → insert_db
//	complete (100%)      → (workflow completion)
//
// The SSE bridge in Batch 2.5 translates step status changes back to ProgressEvent
// format, preserving the dashboard's SSE contract with zero frontend changes.
//
// Key improvements over InstallAppWithProgress():
//   - Port allocation has explicit compensation (db.release_port) — fixes existing
//     port leak bug at appstore_progress.go:55-59.
//   - Crash between any steps → resume on restart with proper compensation.
//   - Each step retried independently instead of all-or-nothing.
type AppStoreInstallWorkflow struct{}

func (w *AppStoreInstallWorkflow) Type() string { return AppStoreInstallType }
func (w *AppStoreInstallWorkflow) Version() int { return AppStoreInstallVersion }

func (w *AppStoreInstallWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			// Step 0: Validate store ID, app name, no conflicts
			Name:       "validate",
			Action:     "appstore.validate",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 1: Fetch app manifest from store (cached or remote)
			Name:       "read_manifest",
			Action:     "appstore.read_manifest",
			Compensate: "", // read-only, no side effects
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    30 * time.Second,
		},
		{
			// Step 2: Allocate a port from the 6100-6999 range
			Name:       "allocate_port",
			Action:     "db.allocate_port",
			Compensate: "db.release_port", // FIXES PORT LEAK BUG
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 500 * time.Millisecond},
			Timeout:    10 * time.Second,
		},
		{
			// Step 3: Transform raw manifest into Swarm-ready compose config
			Name:       "process_manifest",
			Action:     "appstore.process_manifest",
			Compensate: "", // pure transformation, no side effects
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    15 * time.Second,
		},
		{
			// Step 4: Create app directories (/cubeos/apps/{name}/appconfig, appdata)
			Name:       "create_dirs",
			Action:     "app.create_dirs",
			Compensate: "app.remove_dirs",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 5: Remap volume paths to CubeOS conventions
			Name:       "remap_volumes",
			Action:     "appstore.remap_volumes",
			Compensate: "", // pure transformation
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 6: Write the final docker-compose.yml
			Name:       "write_compose",
			Action:     "app.write_compose",
			Compensate: "app.remove_dirs",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 7: Deploy to Docker Swarm
			// docker stack deploy -c <path> --resolve-image=never <name>
			Name:       "deploy_stack",
			Action:     "docker.deploy_stack",
			Compensate: "docker.remove_stack",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    60 * time.Second,
		},
		{
			// Step 8: Wait for Swarm services to converge
			// Linear 2s polling, not exponential backoff
			Name:       "wait_convergence",
			Action:     "docker.wait_convergence",
			Compensate: "", // observation-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 5 * time.Second},
			Timeout:    120 * time.Second,
		},
		{
			// Step 9: Add Pi-hole DNS entry (domain → gateway IP)
			Name:       "add_dns",
			Action:     "infra.add_dns",
			Compensate: "infra.remove_dns",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    15 * time.Second,
		},
		{
			// Step 10: Create NPM reverse proxy host
			Name:       "create_proxy",
			Action:     "infra.create_proxy",
			Compensate: "infra.remove_proxy",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    15 * time.Second,
		},
		{
			// Step 11: Insert app record into database
			// AFTER deploy succeeds — if deploy fails, no db cleanup needed
			Name:       "insert_db",
			Action:     "db.insert_app",
			Compensate: "db.delete_app",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    10 * time.Second,
		},
		{
			// Step 12: Health check (verify app is accessible)
			// Uses HAL health check — optional, failure doesn't block completion
			Name:       "health_check",
			Action:     "hal.health_check",
			Compensate: "", // observation-only
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     3,
				InitialInterval: 5 * time.Second,
				MaxInterval:     15 * time.Second,
			},
			Timeout: 30 * time.Second,
		},
	}
}

// NewAppStoreInstallWorkflow creates a new AppStoreInstallWorkflow definition.
func NewAppStoreInstallWorkflow() *AppStoreInstallWorkflow {
	return &AppStoreInstallWorkflow{}
}
