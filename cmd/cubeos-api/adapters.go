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
// Session 1: ReadManifest is functional. ProcessManifest, RemapVolumes, and DetectWebUIType
// are stubs that return errors — the active install path still uses InstallAppWithProgress.
// Full implementations land in Session 3 when AppStoreManager is gutted.

type appStoreManifestAdapter struct{ mgr *managers.AppStoreManager }

func (a *appStoreManifestAdapter) ReadManifest(ctx context.Context, storeID, appName string) (json.RawMessage, error) {
	app := a.mgr.GetApp(storeID, appName)
	if app == nil {
		return nil, fmt.Errorf("app %s/%s not found in catalog", storeID, appName)
	}
	data, err := json.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest for %s/%s: %w", storeID, appName, err)
	}
	return json.RawMessage(data), nil
}

func (a *appStoreManifestAdapter) ProcessManifest(ctx context.Context, manifest json.RawMessage) (*activities.ProcessedManifest, error) {
	// Session 1 stub: full implementation in Session 3.
	return nil, fmt.Errorf("ProcessManifest: not yet implemented (Session 3)")
}

func (a *appStoreManifestAdapter) RemapVolumes(ctx context.Context, compose string, appName string) (string, error) {
	// Session 1 stub: return compose unchanged; full implementation in Session 3.
	return compose, nil
}

func (a *appStoreManifestAdapter) DetectWebUIType(ctx context.Context, manifest json.RawMessage) (string, error) {
	// Session 1 stub: default to "http".
	return "http", nil
}
