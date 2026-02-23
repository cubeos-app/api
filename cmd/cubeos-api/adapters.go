package main

// adapters.go provides thin adapter types that satisfy flowengine/activities interfaces
// using the concrete manager types in the managers package.
//
// These adapters live in package main (no import cycle risk) and bridge the gap between
// the idealized activity interfaces and the concrete manager method signatures.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"cubeos-api/internal/flowengine/activities"
	"cubeos-api/internal/managers"
)

// --- dnsAdapter: activities.DNSManager via *managers.PiholeManager ---

type dnsAdapter struct{ mgr *managers.PiholeManager }

func (a *dnsAdapter) AddEntry(domain, ip string) error {
	return a.mgr.AddEntry(domain, ip)
}

func (a *dnsAdapter) RemoveEntry(domain string) error {
	return a.mgr.RemoveEntry(domain)
}

func (a *dnsAdapter) GetEntry(domain string) (string, error) {
	entry, err := a.mgr.GetEntry(domain)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", nil
	}
	return entry.IP, nil
}

// --- proxyAdapter: activities.ProxyManager via *managers.NPMManager ---

type proxyAdapter struct{ mgr *managers.NPMManager }

func (a *proxyAdapter) CreateProxyHost(ctx context.Context, domain string, forwardHost string, forwardPort int, forwardScheme string) (int64, error) {
	host := &managers.NPMProxyHostExtended{
		DomainNames:           []string{domain},
		ForwardScheme:         forwardScheme,
		ForwardHost:           forwardHost,
		ForwardPort:           forwardPort,
		AllowWebsocketUpgrade: true,
	}
	result, err := a.mgr.CreateProxyHost(host)
	if err != nil {
		return 0, err
	}
	return int64(result.ID), nil
}

func (a *proxyAdapter) FindProxyHostByDomain(domain string) (int64, error) {
	host, err := a.mgr.FindProxyHostByDomain(domain)
	if err != nil {
		return 0, err
	}
	if host == nil {
		return 0, nil
	}
	return int64(host.ID), nil
}

func (a *proxyAdapter) DeleteProxyHost(ctx context.Context, id int64) error {
	return a.mgr.DeleteProxyHost(int(id))
}

// --- appConflictAdapter: activities.AppConflictChecker via *managers.Orchestrator ---

type appConflictAdapter struct{ orch *managers.Orchestrator }

func (a *appConflictAdapter) AppExists(ctx context.Context, name string) (bool, error) {
	return a.orch.AppExists(ctx, name)
}

// --- appStoreManifestAdapter: activities.AppStoreManifestReader via *managers.AppStoreManager ---
//
// ReadManifest reads the manifest YAML from disk and returns a JSON blob containing
// the manifest content (manifest_yaml), app metadata, and store-specific hints.
// This bypasses the json:"-" tag on StoreApp.ManifestPath.
//
// ProcessManifest applies CasaOS variable substitution, Swarm sanitization, and
// port remapping using the allocated port from the fat envelope.
//
// RemapVolumes remaps external bind-mount paths to safe defaults under /cubeos/apps/.
//
// DetectWebUIType is a stub — the actual detection is performed by the app.detect_webui
// activity (database.go) via HTTP probe. This method is never called.

type appStoreManifestAdapter struct{ mgr *managers.AppStoreManager }

// manifestPayload is the JSON structure embedded in ReadManifestOutput.Manifest.
// All fields are consumed by ProcessManifest and RemapVolumes via the fat envelope.
type manifestPayload struct {
	AppName      string `json:"app_name"`
	DataPath     string `json:"data_path"`
	ManifestYAML string `json:"manifest_yaml"`
	PortMap      string `json:"port_map,omitempty"` // CasaOS x-casaos port hint
}

func (a *appStoreManifestAdapter) ReadManifest(ctx context.Context, storeID, appName string) (json.RawMessage, error) {
	app := a.mgr.GetApp(storeID, appName)
	if app == nil {
		return nil, fmt.Errorf("app %s/%s not found in catalog", storeID, appName)
	}
	if app.ManifestPath == "" {
		return nil, fmt.Errorf("manifest path not set for %s/%s", storeID, appName)
	}

	// Read the raw YAML from disk (ManifestPath has json:"-" so it's not in catalog JSON).
	raw, err := os.ReadFile(app.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest for %s/%s: %w", storeID, appName, err)
	}

	payload := manifestPayload{
		AppName:      appName,
		DataPath:     filepath.Join("/cubeos/apps", appName, "appdata"),
		ManifestYAML: string(raw),
		PortMap:      app.PortMap,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest payload for %s/%s: %w", storeID, appName, err)
	}
	return json.RawMessage(data), nil
}

func (a *appStoreManifestAdapter) ProcessManifest(ctx context.Context, manifest json.RawMessage, port int) (*activities.ProcessedManifest, error) {
	var payload manifestPayload
	if err := json.Unmarshal(manifest, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest payload: %w", err)
	}
	if payload.ManifestYAML == "" {
		return nil, fmt.Errorf("manifest_yaml is empty")
	}
	if payload.AppName == "" {
		return nil, fmt.Errorf("app_name is missing from manifest payload")
	}
	if payload.DataPath == "" {
		payload.DataPath = filepath.Join("/cubeos/apps", payload.AppName, "appdata")
	}

	// Apply CasaOS variable substitution + Swarm sanitization.
	processed := a.mgr.ProcessManifestYAML(payload.ManifestYAML, payload.AppName, payload.DataPath)

	// Remap the published host port to the CubeOS-allocated port.
	if port > 0 {
		remapped, err := managers.RemapPorts(processed, port, payload.PortMap)
		if err == nil {
			processed = remapped
		}
		// non-fatal: if remapping fails the original is used
	}

	return &activities.ProcessedManifest{
		ComposeYAML: processed,
	}, nil
}

func (a *appStoreManifestAdapter) RemapVolumes(ctx context.Context, compose string, appName string) (string, error) {
	dataPath := filepath.Join("/cubeos/apps", appName, "appdata")
	remapped, _, err := managers.RemapExternalVolumes(compose, appName, dataPath, map[string]string{})
	if err != nil {
		// non-fatal: return original compose if remapping fails
		return compose, nil
	}
	return remapped, nil
}

func (a *appStoreManifestAdapter) DetectWebUIType(ctx context.Context, manifest json.RawMessage) (string, error) {
	// Detection is performed by the app.detect_webui activity (database.go) via HTTP probe.
	// This method satisfies the interface but is never called by any registered activity.
	return "browser", nil
}
