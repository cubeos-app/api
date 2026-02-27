package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const externalTestTimeout = 5 * time.Second

// testExternalNPM tests connectivity to an external Nginx Proxy Manager instance.
// It authenticates via the NPM API and checks proxy host listing.
func testExternalNPM(ctx context.Context, npmURL, npmToken string) (ok bool, version string, errMsg string) {
	client := &http.Client{Timeout: externalTestTimeout}
	baseURL := strings.TrimRight(npmURL, "/")

	// If a token is provided, try to use it directly to list proxy hosts
	if npmToken != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/nginx/proxy-hosts", nil)
		if err != nil {
			return false, "", fmt.Sprintf("invalid URL: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+npmToken)

		resp, err := client.Do(req)
		if err != nil {
			return false, "", fmt.Sprintf("connection failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			// Try to get version from /api/ endpoint
			ver := getNPMVersion(ctx, client, baseURL, npmToken)
			return true, ver, ""
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return false, "", "authentication failed: invalid token"
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return false, "", fmt.Sprintf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// No token — just check if NPM is reachable at all
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/", nil)
	if err != nil {
		return false, "", fmt.Sprintf("invalid URL: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Sprintf("connection failed: %v", err)
	}
	defer resp.Body.Close()
	// 401 means NPM is running but needs auth — still counts as reachable
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		return true, "", ""
	}
	return false, "", fmt.Sprintf("unexpected status %d", resp.StatusCode)
}

// getNPMVersion attempts to retrieve the NPM version string.
func getNPMVersion(ctx context.Context, client *http.Client, baseURL, token string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/settings", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()

	var settings map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&settings); err != nil {
		return ""
	}
	if v, ok := settings["version"].(string); ok {
		return v
	}
	return ""
}

// testExternalPihole tests connectivity to an external Pi-hole instance.
// Uses Pi-hole v6 API with password authentication.
func testExternalPihole(ctx context.Context, piholeURL, password string) (ok bool, version string, errMsg string) {
	client := &http.Client{Timeout: externalTestTimeout}
	baseURL := strings.TrimRight(piholeURL, "/")

	// Pi-hole v6 API: GET /api/info/version
	versionURL := baseURL + "/api/info/version"
	req, err := http.NewRequestWithContext(ctx, "GET", versionURL, nil)
	if err != nil {
		return false, "", fmt.Sprintf("invalid URL: %v", err)
	}
	if password != "" {
		req.Header.Set("X-Pi-Hole-Password", password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Sprintf("connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var versionResp map[string]interface{}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&versionResp); err == nil {
			if v, ok := versionResp["version"].(string); ok {
				return true, v, ""
			}
			// Try nested structure
			if core, ok := versionResp["core"].(map[string]interface{}); ok {
				if v, ok := core["version"].(string); ok {
					return true, v, ""
				}
			}
		}
		return true, "", ""
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, "", "authentication failed: invalid password"
	}

	// Try simpler endpoint for older Pi-hole versions
	adminURL := baseURL + "/admin/api.php?version"
	req2, err := http.NewRequestWithContext(ctx, "GET", adminURL, nil)
	if err != nil {
		return false, "", fmt.Sprintf("status %d from version endpoint", resp.StatusCode)
	}
	resp2, err := client.Do(req2)
	if err != nil {
		return false, "", fmt.Sprintf("status %d from version endpoint", resp.StatusCode)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		var legacy map[string]interface{}
		if err := json.NewDecoder(io.LimitReader(resp2.Body, 4096)).Decode(&legacy); err == nil {
			if v, ok := legacy["version"].(float64); ok {
				return true, fmt.Sprintf("%.0f", v), ""
			}
		}
		return true, "", ""
	}

	return false, "", fmt.Sprintf("unreachable (status %d)", resp.StatusCode)
}
