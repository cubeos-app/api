package managers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cubeos-api/internal/circuitbreaker"
	"cubeos-api/internal/config"
)

// newTestPiholeManager creates a PiholeManager pointed at a test server.
func newTestPiholeManager(serverURL string) *PiholeManager {
	return &PiholeManager{
		baseURL:  serverURL,
		password: "test-password",
		cubeosIP: "10.42.24.1",
		domain:   "cubeos.cube",
		httpClient: &http.Client{
			Timeout: 5 * 1e9, // 5s
		},
		cb: circuitbreaker.New("pihole-test", circuitbreaker.Config{
			Threshold:        3,
			Timeout:          1 * 1e9, // 1s for fast tests
			SuccessThreshold: 1,
		}),
	}
}

// mockAuthHandler returns a handler that responds to POST /api/auth.
func mockAuthHandler(password string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)

		if body["password"] != password {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"session": map[string]interface{}{"valid": false},
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"session": map[string]interface{}{
				"valid":    true,
				"sid":      "test-sid-12345",
				"validity": 300,
			},
		})
	}
}

// mockDNSHostsResponse builds a standard Pi-hole v6 dns/hosts response.
func mockDNSHostsResponse(hosts []string) map[string]interface{} {
	return map[string]interface{}{
		"config": map[string]interface{}{
			"dns": map[string]interface{}{
				"hosts": hosts,
			},
		},
	}
}

func TestNewPiholeManager(t *testing.T) {
	cfg := &config.Config{
		GatewayIP:      "10.42.24.1",
		PiholePort:     6001,
		PiholePassword: "test-pass",
		Domain:         "cubeos.cube",
	}

	mgr := NewPiholeManager(cfg)

	if mgr.baseURL != "http://10.42.24.1:6001" {
		t.Errorf("expected baseURL http://10.42.24.1:6001, got %s", mgr.baseURL)
	}
	if mgr.password != "test-pass" {
		t.Errorf("expected password test-pass, got %s", mgr.password)
	}
	if mgr.cubeosIP != "10.42.24.1" {
		t.Errorf("expected cubeosIP 10.42.24.1, got %s", mgr.cubeosIP)
	}
	if mgr.domain != "cubeos.cube" {
		t.Errorf("expected domain cubeos.cube, got %s", mgr.domain)
	}
	if mgr.cb == nil {
		t.Fatal("circuit breaker not initialized")
	}
	if mgr.CircuitState() != circuitbreaker.StateClosed {
		t.Errorf("expected circuit closed, got %s", mgr.CircuitState())
	}
}

func TestAuthenticate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	entries, err := mgr.ReadCustomList()
	// Will fail because /api/config/dns/hosts isn't mocked, but auth should succeed
	_ = entries
	// The error should NOT be an auth error
	if err != nil && strings.Contains(err.Error(), "auth failed") {
		t.Errorf("authentication should have succeeded: %v", err)
	}
}

func TestReadCustomList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-FTL-SID") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(mockDNSHostsResponse([]string{
				"10.42.24.1 cubeos.cube",
				"10.42.24.1 pihole.cubeos.cube",
				"10.42.24.1 npm.cubeos.cube",
			}))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	entries, err := mgr.ReadCustomList()
	if err != nil {
		t.Fatalf("ReadCustomList failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	if entries[0].IP != "10.42.24.1" || entries[0].Domain != "cubeos.cube" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].Domain != "pihole.cubeos.cube" {
		t.Errorf("unexpected second entry: %+v", entries[1])
	}
}

func TestAddEntry(t *testing.T) {
	var putPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-FTL-SID") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// GET for GetEntry check
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(mockDNSHostsResponse([]string{}))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/api/config/dns/hosts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-FTL-SID") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPut {
			putPath = r.URL.Path
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	err := mgr.AddEntry("test.cubeos.cube", "")
	if err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	// Verify the PUT path contains the URL-encoded "IP HOSTNAME" format
	if !strings.Contains(putPath, "10.42.24.1") || !strings.Contains(putPath, "test.cubeos.cube") {
		t.Errorf("unexpected PUT path: %s", putPath)
	}
}

func TestAddEntryWithExplicitIP(t *testing.T) {
	var putPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(mockDNSHostsResponse([]string{}))
			return
		}
	})
	mux.HandleFunc("/api/config/dns/hosts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			putPath = r.URL.Path
			w.WriteHeader(http.StatusCreated)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)
	err := mgr.AddEntry("custom.cubeos.cube", "192.168.1.100")
	if err != nil {
		t.Fatalf("AddEntry with explicit IP failed: %v", err)
	}

	if !strings.Contains(putPath, "192.168.1.100") {
		t.Errorf("PUT path should contain explicit IP, got: %s", putPath)
	}
}

func TestRemoveEntryFastPath(t *testing.T) {
	var deletePath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-FTL-SID") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodDelete {
			deletePath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	err := mgr.RemoveEntry("test.cubeos.cube")
	if err != nil {
		t.Fatalf("RemoveEntry failed: %v", err)
	}

	// Fast path should use cubeosIP
	if !strings.Contains(deletePath, "10.42.24.1") || !strings.Contains(deletePath, "test.cubeos.cube") {
		t.Errorf("unexpected DELETE path: %s", deletePath)
	}
}

func TestRemoveEntrySlowPath(t *testing.T) {
	var deletePaths []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(mockDNSHostsResponse([]string{
				"192.168.1.50 test.cubeos.cube",
			}))
			return
		}
	})
	mux.HandleFunc("/api/config/dns/hosts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletePaths = append(deletePaths, r.URL.Path)
			// First call (fast path with cubeosIP) returns 404
			if strings.Contains(r.URL.Path, "10.42.24.1") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// Second call (slow path with correct IP) returns 204
			w.WriteHeader(http.StatusNoContent)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	err := mgr.RemoveEntry("test.cubeos.cube")
	if err != nil {
		t.Fatalf("RemoveEntry slow path failed: %v", err)
	}

	if len(deletePaths) < 2 {
		t.Fatalf("expected at least 2 DELETE calls (fast + slow path), got %d", len(deletePaths))
	}

	// Second call should use the IP found via ReadCustomList
	if !strings.Contains(deletePaths[1], "192.168.1.50") {
		t.Errorf("slow path should use discovered IP, got: %s", deletePaths[1])
	}
}

func TestRemoveEntryNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(mockDNSHostsResponse([]string{}))
			return
		}
	})
	mux.HandleFunc("/api/config/dns/hosts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	// Removing a non-existent entry should not error
	err := mgr.RemoveEntry("nonexistent.cubeos.cube")
	if err != nil {
		t.Errorf("removing non-existent entry should not error, got: %v", err)
	}
}

func TestGetEntry(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockDNSHostsResponse([]string{
			"10.42.24.1 cubeos.cube",
			"10.42.24.1 app.cubeos.cube",
		}))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	entry, err := mgr.GetEntry("app.cubeos.cube")
	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.IP != "10.42.24.1" || entry.Domain != "app.cubeos.cube" {
		t.Errorf("unexpected entry: %+v", entry)
	}

	// Not found
	entry, err = mgr.GetEntry("nonexistent.cubeos.cube")
	if err != nil {
		t.Fatalf("GetEntry for missing should not error: %v", err)
	}
	if entry != nil {
		t.Errorf("expected nil for missing entry, got: %+v", entry)
	}
}

func TestGetCubeOSDomains(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockDNSHostsResponse([]string{
			"10.42.24.1 cubeos.cube",
			"10.42.24.1 pihole.cubeos.cube",
			"192.168.1.1 router.local",
		}))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	entries, err := mgr.GetCubeOSDomains()
	if err != nil {
		t.Fatalf("GetCubeOSDomains failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 CubeOS entries, got %d", len(entries))
	}
}

func TestWriteCustomList(t *testing.T) {
	var patchBody []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			json.NewDecoder(r.Body).Decode(&patchBody)
			w.WriteHeader(http.StatusOK)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	err := mgr.WriteCustomList([]DNSEntry{
		{IP: "10.42.24.1", Domain: "cubeos.cube"},
		{IP: "10.42.24.1", Domain: "app.cubeos.cube"},
	})
	if err != nil {
		t.Fatalf("WriteCustomList failed: %v", err)
	}

	if len(patchBody) != 2 {
		t.Fatalf("expected 2 entries in PATCH body, got %d", len(patchBody))
	}
	if patchBody[0] != "10.42.24.1 cubeos.cube" {
		t.Errorf("unexpected PATCH body[0]: %s", patchBody[0])
	}
}

func TestSessionReauthOn401(t *testing.T) {
	var authCount int32

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&authCount, 1)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"session": map[string]interface{}{
				"valid":    true,
				"sid":      "new-sid",
				"validity": 300,
			},
		})
	})

	callCount := 0
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			// First request with old SID → 401, retry with new SID → 200
			if callCount == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(mockDNSHostsResponse([]string{}))
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)
	// Pre-cache an expired SID
	mgr.sid = "expired-sid"
	mgr.sidExpiry = mgr.sidExpiry.Add(1e18) // far future so it's "valid" per cache

	entries, err := mgr.ReadCustomList()
	if err != nil {
		t.Fatalf("ReadCustomList should succeed after re-auth: %v", err)
	}

	// Empty hosts array → nil slice is idiomatic Go; len check is correct
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from empty hosts, got %d", len(entries))
	}

	// Should have re-authenticated after 401 on first request
	if atomic.LoadInt32(&authCount) < 1 {
		t.Errorf("expected at least 1 re-auth call, got %d", atomic.LoadInt32(&authCount))
	}
}

func TestCircuitBreakerTrips(t *testing.T) {
	failCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		failCount++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	// Trip the breaker (threshold=3 in test config)
	for i := 0; i < 3; i++ {
		_, err := mgr.ReadCustomList()
		if err == nil {
			t.Fatalf("call %d should have failed (5xx)", i+1)
		}
	}

	// Next call should be rejected by circuit breaker
	_, err := mgr.ReadCustomList()
	if err == nil {
		t.Fatal("expected ErrCircuitOpen after breaker trips")
	}
	if !strings.Contains(err.Error(), "circuit breaker is open") {
		t.Errorf("expected circuit breaker error, got: %v", err)
	}

	if mgr.CircuitState() != circuitbreaker.StateOpen {
		t.Errorf("expected circuit open, got %s", mgr.CircuitState())
	}
}

func TestIsHealthyBypassesBreaker(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", mockAuthHandler("test-password"))
	mux.HandleFunc("/api/info/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"dns": "UP"})
	})
	mux.HandleFunc("/api/config/dns/hosts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	mgr := newTestPiholeManager(srv.URL)

	// Trip the breaker
	for i := 0; i < 3; i++ {
		mgr.ReadCustomList()
	}

	if mgr.CircuitState() != circuitbreaker.StateOpen {
		t.Fatalf("expected circuit open, got %s", mgr.CircuitState())
	}

	// IsHealthy should still work even with circuit open
	ctx := t.Context()
	if !mgr.IsHealthy(ctx) {
		t.Error("IsHealthy should return true even when circuit is open")
	}
}

func TestValidateDomain(t *testing.T) {
	mgr := &PiholeManager{domain: "cubeos.cube"}

	tests := []struct {
		domain    string
		expectErr bool
	}{
		{"cubeos.cube", false},
		{"app.cubeos.cube", false},
		{"my-app.cubeos.cube", false},
		{"sub.app.cubeos.cube", false},
		{"", true},
		{"example.com", true},
		{"-invalid.cubeos.cube", true},
		{"invalid-.cubeos.cube", true},
	}

	for _, tt := range tests {
		err := mgr.ValidateDomain(tt.domain)
		if tt.expectErr && err == nil {
			t.Errorf("ValidateDomain(%q) expected error, got nil", tt.domain)
		}
		if !tt.expectErr && err != nil {
			t.Errorf("ValidateDomain(%q) unexpected error: %v", tt.domain, err)
		}
	}
}

func TestParseDNSHostsResponse(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "normal entries",
			body:      `{"config":{"dns":{"hosts":["10.42.24.1 cubeos.cube","10.42.24.1 app.cubeos.cube"]}}}`,
			wantCount: 2,
		},
		{
			name:      "empty list",
			body:      `{"config":{"dns":{"hosts":[]}}}`,
			wantCount: 0,
		},
		{
			name:      "malformed entry skipped",
			body:      `{"config":{"dns":{"hosts":["10.42.24.1 cubeos.cube","badentry","10.42.24.1 app.cubeos.cube"]}}}`,
			wantCount: 2,
		},
		{
			name:    "invalid JSON",
			body:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := parseDNSHostsResponse([]byte(tt.body))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(entries) != tt.wantCount {
				t.Errorf("expected %d entries, got %d", tt.wantCount, len(entries))
			}
		})
	}
}
