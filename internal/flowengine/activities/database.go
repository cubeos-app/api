package activities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/flowengine"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// AppDatabase defines the database operations needed by DB activities.
// Satisfied by *sql.DB (with appropriate query methods).
type AppDatabase interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// PortAllocator defines the port allocation operations needed by DB activities.
// Satisfied by *managers.PortManager.
type PortAllocator interface {
	AllocateUserPort() (int, error)
	ReleasePort(port int) error
}

// --- Input/Output Schemas ---

// InsertAppInput is the input for the db.insert_app activity.
// Fields map to the fat envelope keys produced by prior workflow steps.
type InsertAppInput struct {
	AppName     string `json:"app_name"`              // from validate/allocate_port output
	Port        int    `json:"port"`                  // from allocate_port output
	Domain      string `json:"domain,omitempty"`      // FQDN from add_dns output (e.g. "prowlarr.cubeos.cube")
	Subdomain   string `json:"subdomain,omitempty"`   // from add_dns output
	NPMProxyID  int64  `json:"host_id,omitempty"`     // from create_proxy output
	Source      string `json:"source"`                // "casaos", "registry", "custom"
	Image       string `json:"image,omitempty"`       // from process_manifest output
	ComposePath string `json:"compose_path"`          // from write_compose output
	DataPath    string `json:"data_path"`             // from create_dirs output
	StoreID     string `json:"store_id,omitempty"`    // from validate output
	Title       string `json:"title,omitempty"`       // from process_manifest output (display name)
	Description string `json:"description,omitempty"` // from process_manifest output
	WebUIType   string `json:"webui_type,omitempty"`  // from process_manifest output
}

// InsertAppOutput is the output of the db.insert_app activity.
type InsertAppOutput struct {
	AppID   int64  `json:"app_id"`
	Name    string `json:"name"`
	Created bool   `json:"created"`
	Skipped bool   `json:"skipped"` // true if app already existed
}

// DeleteAppInput is the input for the db.delete_app activity.
type DeleteAppInput struct {
	AppID   int64  `json:"app_id,omitempty"`
	AppName string `json:"app_name,omitempty"` // fallback if ID not known
}

// DeleteAppOutput is the output of the db.delete_app activity.
type DeleteAppOutput struct {
	AppName string `json:"app_name"`
	Deleted bool   `json:"deleted"`
}

// AllocatePortInput is the input for the db.allocate_port activity.
type AllocatePortInput struct {
	AppName string `json:"app_name"`
	Port    int    `json:"port,omitempty"` // if non-zero, use this specific port
}

// AllocatePortOutput is the output of the db.allocate_port activity.
type AllocatePortOutput struct {
	AppName string `json:"app_name"`
	Port    int    `json:"port"`
	Skipped bool   `json:"skipped"` // true if port was already allocated for this app
}

// ReleasePortInput is the input for the db.release_port activity.
type ReleasePortInput struct {
	Port    int    `json:"port"`
	AppName string `json:"app_name,omitempty"` // informational
}

// ReleasePortOutput is the output of the db.release_port activity.
type ReleasePortOutput struct {
	Port     int  `json:"port"`
	Released bool `json:"released"`
}

// CleanupFilesInput is the input for the db.cleanup_files activity.
type CleanupFilesInput struct {
	AppName  string `json:"app_name"`
	DataPath string `json:"data_path"`
	KeepData bool   `json:"keep_data"`
}

// CleanupFilesOutput is the output of the db.cleanup_files activity.
type CleanupFilesOutput struct {
	AppName  string `json:"app_name"`
	Cleaned  bool   `json:"cleaned"`
	KeepData bool   `json:"keep_data"`
}

// StoreVolumesInput is the input for the db.store_volumes activity.
type StoreVolumesInput struct {
	AppName     string `json:"app_name"`
	ComposeYAML string `json:"compose_yaml"` // final compose to parse for volumes
}

// StoreVolumesOutput is the output of the db.store_volumes activity.
type StoreVolumesOutput struct {
	AppName string `json:"app_name"`
	Count   int    `json:"count"` // number of volume mappings stored
}

// DetectWebUIInput is the input for the app.detect_webui activity.
type DetectWebUIInput struct {
	AppName   string `json:"app_name"`
	Port      int    `json:"port"`
	GatewayIP string `json:"gateway_ip,omitempty"` // defaults to "10.42.24.1"
}

// DetectWebUIOutput is the output of the app.detect_webui activity.
type DetectWebUIOutput struct {
	AppName   string `json:"app_name"`
	WebUIType string `json:"webui_type"` // "browser" or "api"
	Updated   bool   `json:"updated"`
}

// RegisterDatabaseActivities registers all database-related activities in the registry.
// Activities: db.insert_app, db.delete_app, db.allocate_port, db.release_port,
// db.cleanup_files, db.store_volumes, app.detect_webui.
func RegisterDatabaseActivities(registry *flowengine.ActivityRegistry, db AppDatabase, portMgr PortAllocator) {
	registry.MustRegister("db.insert_app", makeInsertApp(db))
	registry.MustRegister("db.delete_app", makeDeleteApp(db))
	registry.MustRegister("db.allocate_port", makeAllocatePort(db, portMgr))
	registry.MustRegister("db.release_port", makeReleasePort(db, portMgr))
	registry.MustRegister("db.cleanup_files", makeCleanupFiles())
	registry.MustRegister("db.store_volumes", makeStoreVolumes(db))
	registry.MustRegister("app.detect_webui", makeDetectWebUI(db))
}

// makeInsertApp creates the db.insert_app activity.
// Idempotent: if an app with the same name already exists, returns skipped=true.
// Inserts into apps table + port_allocations + fqdns (matching actual schema).
func makeInsertApp(db AppDatabase) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in InsertAppInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid insert_app input: %w", err))
		}
		if in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_name is required"))
		}

		// Idempotency check: does an app with this name already exist?
		var existingID int64
		err := db.QueryRowContext(ctx, "SELECT id FROM apps WHERE name = ?", in.AppName).Scan(&existingID)
		if err == nil && existingID > 0 {
			log.Info().Str("app", in.AppName).Int64("id", existingID).Msg("insert_app: app already exists, skipping")
			return marshalOutput(InsertAppOutput{AppID: existingID, Name: in.AppName, Created: true, Skipped: true})
		}

		now := time.Now().UTC()

		// Derive display name from title or app name
		displayName := in.Title
		if displayName == "" {
			displayName = in.AppName
		}
		webUIType := in.WebUIType
		if webUIType == "" {
			webUIType = "browser"
		}

		result, err := db.ExecContext(ctx, `
			INSERT INTO apps (name, display_name, description, type, source, store_id,
				compose_path, data_path, enabled, deploy_mode, webui_type,
				created_at, updated_at)
			VALUES (?, ?, ?, 'user', ?, ?, ?, ?, 1, 'stack', ?, ?, ?)
		`, in.AppName, displayName, in.Description, in.Source, in.StoreID,
			in.ComposePath, in.DataPath, webUIType, now, now)
		if err != nil {
			// Unique constraint violation → permanent (duplicate)
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				return nil, flowengine.NewPermanentError(fmt.Errorf("app %s already exists: %w", in.AppName, err))
			}
			return nil, flowengine.ClassifyError(err)
		}

		appID, _ := result.LastInsertId()
		log.Info().Str("app", in.AppName).Int64("id", appID).Msg("insert_app: app record created")

		// Create FQDN record (domain from add_dns output)
		if in.Domain != "" {
			subdomain := in.Subdomain
			if subdomain == "" {
				subdomain = strings.Split(in.Domain, ".")[0]
			}
			backendPort := in.Port
			_, err = db.ExecContext(ctx, `
				INSERT OR IGNORE INTO fqdns (app_id, fqdn, subdomain, backend_port, npm_proxy_id, created_at)
				VALUES (?, ?, ?, ?, ?, ?)
			`, appID, in.Domain, subdomain, backendPort, nullableInt64(in.NPMProxyID), now)
			if err != nil {
				log.Warn().Err(err).Str("fqdn", in.Domain).Msg("insert_app: failed to create FQDN record (non-fatal)")
			}
		}

		// Create port allocation record
		if in.Port > 0 {
			_, err = db.ExecContext(ctx, `
				INSERT OR IGNORE INTO port_allocations (app_id, port, is_primary, created_at)
				VALUES (?, ?, 1, ?)
			`, appID, in.Port, now)
			if err != nil {
				log.Warn().Err(err).Int("port", in.Port).Msg("insert_app: failed to create port allocation record (non-fatal)")
			}
		}

		return marshalOutput(InsertAppOutput{AppID: appID, Name: in.AppName, Created: true, Skipped: false})
	}
}

// makeDeleteApp creates the db.delete_app activity.
// Idempotent: if the app doesn't exist, returns success with deleted=false.
// FK cascades delete port_allocations and fqdns records.
func makeDeleteApp(db AppDatabase) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DeleteAppInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid delete_app input: %w", err))
		}
		if in.AppID == 0 && in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_id or app_name is required"))
		}

		var result sql.Result
		var err error
		var name string

		if in.AppID > 0 {
			// Get name for logging before deletion
			_ = db.QueryRowContext(ctx, "SELECT name FROM apps WHERE id = ?", in.AppID).Scan(&name)
			result, err = db.ExecContext(ctx, "DELETE FROM apps WHERE id = ?", in.AppID)
		} else {
			name = in.AppName
			result, err = db.ExecContext(ctx, "DELETE FROM apps WHERE name = ?", in.AppName)
		}

		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		rows, _ := result.RowsAffected()
		if rows == 0 {
			log.Info().Str("app", name).Msg("delete_app: app not found, nothing to delete")
			return marshalOutput(DeleteAppOutput{AppName: name, Deleted: false})
		}

		log.Info().Str("app", name).Msg("delete_app: app record deleted (cascaded to ports/fqdns)")
		return marshalOutput(DeleteAppOutput{AppName: name, Deleted: true})
	}
}

// makeAllocatePort creates the db.allocate_port activity.
// Idempotent: if a port is already allocated for this app, returns the existing port.
func makeAllocatePort(db AppDatabase, portMgr PortAllocator) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in AllocatePortInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid allocate_port input: %w", err))
		}
		if in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_name is required"))
		}

		// Idempotency check: is there already a port allocated for this app?
		// Check by looking at port_allocations joined with apps
		var existingPort int
		err := db.QueryRowContext(ctx,
			"SELECT pa.port FROM port_allocations pa JOIN apps a ON pa.app_id = a.id WHERE a.name = ?",
			in.AppName,
		).Scan(&existingPort)
		if err == nil && existingPort > 0 {
			log.Info().Str("app", in.AppName).Int("port", existingPort).Msg("allocate_port: port already allocated, skipping")
			return marshalOutput(AllocatePortOutput{AppName: in.AppName, Port: existingPort, Skipped: true})
		}

		// Allocate a new port
		var port int
		if in.Port > 0 {
			port = in.Port
		} else {
			port, err = portMgr.AllocateUserPort()
			if err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("no available ports: %w", err))
			}
		}

		log.Info().Str("app", in.AppName).Int("port", port).Msg("allocate_port: port allocated")
		return marshalOutput(AllocatePortOutput{AppName: in.AppName, Port: port, Skipped: false})
	}
}

// makeReleasePort creates the db.release_port activity.
// This is the explicit compensation for db.allocate_port — fixes the existing port leak bug.
// Idempotent: if the port isn't allocated, returns success with released=false.
func makeReleasePort(db AppDatabase, portMgr PortAllocator) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ReleasePortInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid release_port input: %w", err))
		}
		if in.Port == 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("port is required"))
		}

		log.Info().Int("port", in.Port).Str("app", in.AppName).Msg("release_port: releasing port")

		if err := portMgr.ReleasePort(in.Port); err != nil {
			if isNotFoundError(err) {
				return marshalOutput(ReleasePortOutput{Port: in.Port, Released: false})
			}
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(ReleasePortOutput{Port: in.Port, Released: true})
	}
}

// makeCleanupFiles creates the db.cleanup_files activity.
// Removes app directories. Not idempotent in reverse (no compensation).
// Best-effort: failure doesn't block workflow completion.
func makeCleanupFiles() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in CleanupFilesInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid cleanup_files input: %w", err))
		}

		if in.KeepData {
			log.Info().Str("app", in.AppName).Msg("cleanup_files: keep_data=true, skipping file cleanup")
			return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: false, KeepData: true})
		}

		if in.DataPath == "" {
			return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: false})
		}

		// Safety check: only remove paths under /cubeos/apps/
		absPath, err := filepath.Abs(in.DataPath)
		if err != nil || !strings.HasPrefix(absPath, "/cubeos/apps/") {
			log.Warn().Str("path", in.DataPath).Msg("cleanup_files: refusing to remove path outside /cubeos/apps/")
			return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: false})
		}

		log.Info().Str("app", in.AppName).Str("path", absPath).Msg("cleanup_files: removing app directory")
		if err := os.RemoveAll(absPath); err != nil {
			log.Warn().Err(err).Str("path", absPath).Msg("cleanup_files: failed to remove directory (non-fatal)")
			// Non-fatal: return success anyway — files can be cleaned up manually
			return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: false})
		}

		return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: true})
	}
}

// makeStoreVolumes creates the db.store_volumes activity.
// Parses compose YAML, extracts bind mounts, stores in volume_mappings table.
// Idempotent: uses ON CONFLICT DO UPDATE.
func makeStoreVolumes(db AppDatabase) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in StoreVolumesInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid store_volumes input: %w", err))
		}
		if in.AppName == "" || in.ComposeYAML == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_name and compose_yaml are required"))
		}

		// Look up app_id
		var appID int64
		err := db.QueryRowContext(ctx, "SELECT id FROM apps WHERE name = ?", in.AppName).Scan(&appID)
		if err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app %s not found: %w", in.AppName, err))
		}

		mounts := extractBindMounts(in.ComposeYAML)
		if len(mounts) == 0 {
			log.Info().Str("app", in.AppName).Msg("store_volumes: no bind mounts found")
			return marshalOutput(StoreVolumesOutput{AppName: in.AppName, Count: 0})
		}

		now := time.Now().UTC()
		count := 0
		for _, m := range mounts {
			isConfig := 0
			if isConfigPath(m.containerPath) {
				isConfig = 1
			}
			readOnly := 0
			if m.readOnly {
				readOnly = 1
			}

			_, err := db.ExecContext(ctx, `
				INSERT INTO volume_mappings (app_id, container_path, original_host_path, current_host_path, is_config, read_only, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(app_id, container_path) DO UPDATE SET
					current_host_path = excluded.current_host_path,
					is_config = excluded.is_config,
					read_only = excluded.read_only
			`, appID, m.containerPath, m.hostPath, m.hostPath, isConfig, readOnly, now)
			if err != nil {
				log.Warn().Err(err).Str("container_path", m.containerPath).Msg("store_volumes: failed to upsert volume mapping")
				continue
			}
			count++
		}

		log.Info().Str("app", in.AppName).Int("count", count).Msg("store_volumes: volume mappings stored")
		return marshalOutput(StoreVolumesOutput{AppName: in.AppName, Count: count})
	}
}

// makeDetectWebUI creates the app.detect_webui activity.
// Probes the running app to determine if it serves HTML (browser) or JSON (API).
// Updates apps.webui_type in the database.
func makeDetectWebUI(db AppDatabase) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DetectWebUIInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid detect_webui input: %w", err))
		}
		if in.AppName == "" || in.Port == 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_name and port are required"))
		}

		gateway := in.GatewayIP
		if gateway == "" {
			gateway = "10.42.24.1"
		}

		url := fmt.Sprintf("http://%s:%d/", gateway, in.Port)
		webUIType := probeWebUIType(url)

		_, err := db.ExecContext(ctx,
			"UPDATE apps SET webui_type = ?, updated_at = ? WHERE name = ?",
			webUIType, time.Now().UTC(), in.AppName,
		)
		if err != nil {
			log.Warn().Err(err).Str("app", in.AppName).Msg("detect_webui: failed to update webui_type (non-fatal)")
			return marshalOutput(DetectWebUIOutput{AppName: in.AppName, WebUIType: webUIType, Updated: false})
		}

		log.Info().Str("app", in.AppName).Str("type", webUIType).Msg("detect_webui: webui type detected")
		return marshalOutput(DetectWebUIOutput{AppName: in.AppName, WebUIType: webUIType, Updated: true})
	}
}

// --- Helper types and functions ---

// bindMount represents a parsed bind mount from a compose file.
type bindMount struct {
	hostPath      string
	containerPath string
	readOnly      bool
}

// extractBindMounts parses a docker-compose YAML and returns all bind mount definitions.
// Handles both short-form ("host:container") and long-form (type/source/target map) volumes.
func extractBindMounts(composeYAML string) []bindMount {
	var compose struct {
		Services map[string]struct {
			Volumes []interface{} `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(composeYAML), &compose); err != nil {
		log.Warn().Err(err).Msg("extractBindMounts: failed to parse compose YAML")
		return nil
	}

	var mounts []bindMount
	for _, svc := range compose.Services {
		for _, v := range svc.Volumes {
			m := parseVolumeEntry(v)
			if m != nil {
				mounts = append(mounts, *m)
			}
		}
	}
	return mounts
}

// parseVolumeEntry parses a single volume entry (short-form string or long-form map)
// and returns a bindMount if it's a bind mount, or nil otherwise.
func parseVolumeEntry(v interface{}) *bindMount {
	switch vol := v.(type) {
	case string:
		parts := strings.SplitN(vol, ":", 3)
		if len(parts) < 2 {
			return nil
		}
		hostPath := parts[0]
		containerPath := parts[1]
		if !strings.HasPrefix(hostPath, "/") {
			return nil // named volume
		}
		ro := false
		if len(parts) == 3 && strings.Contains(parts[2], "ro") {
			ro = true
		}
		return &bindMount{hostPath: hostPath, containerPath: containerPath, readOnly: ro}
	case map[string]interface{}:
		volType, _ := vol["type"].(string)
		if volType != "" && volType != "bind" {
			return nil
		}
		source, _ := vol["source"].(string)
		target, _ := vol["target"].(string)
		if source == "" || !strings.HasPrefix(source, "/") || target == "" {
			return nil
		}
		ro := false
		if readOnly, ok := vol["read_only"].(bool); ok {
			ro = readOnly
		}
		return &bindMount{hostPath: source, containerPath: target, readOnly: ro}
	default:
		return nil
	}
}

// isConfigPath returns true if the container path looks like a config location.
func isConfigPath(containerPath string) bool {
	configIndicators := []string{"/config", "/etc/", "/.conf", "/settings"}
	lower := strings.ToLower(containerPath)
	for _, ind := range configIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// probeWebUIType probes a URL and returns "browser" or "api" based on Content-Type.
func probeWebUIType(url string) string {
	client := &http.Client{Timeout: 5 * time.Second}

	// Try HEAD first
	resp, err := client.Head(url)
	if err != nil {
		// If HEAD fails, try GET
		resp, err = client.Get(url)
		if err != nil {
			return "browser" // default to browser on failure
		}
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	ct = strings.ToLower(ct)

	if strings.Contains(ct, "application/json") || strings.Contains(ct, "text/plain") {
		return "api"
	}
	return "browser"
}

// nullableInt64 returns a sql.NullInt64 — valid only when val > 0.
func nullableInt64(val int64) sql.NullInt64 {
	if val > 0 {
		return sql.NullInt64{Int64: val, Valid: true}
	}
	return sql.NullInt64{Valid: false}
}
