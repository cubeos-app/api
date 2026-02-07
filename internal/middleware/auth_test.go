package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"cubeos-api/internal/config"
)

// testConfig returns a minimal config for auth testing.
func testConfig() *config.Config {
	return &config.Config{
		JWTSecret:          "test-secret-key-for-unit-tests",
		JWTExpirationHours: 24,
	}
}

// =============================================================================
// Token Generation Tests
// =============================================================================

func TestGenerateToken(t *testing.T) {
	cfg := testConfig()

	token, err := GenerateToken("admin", "admin", cfg)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned empty token")
	}

	// Parse and verify claims
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	if err != nil {
		t.Fatalf("failed to parse generated token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("generated token is not valid")
	}
	if claims.Username != "admin" {
		t.Errorf("Username = %q, want %q", claims.Username, "admin")
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q, want %q", claims.Role, "admin")
	}
	if claims.Subject != "admin" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "admin")
	}
}

func TestGenerateTokenExpiry(t *testing.T) {
	cfg := testConfig()
	cfg.JWTExpirationHours = 1

	token, err := GenerateToken("user1", "user", cfg)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims := &Claims{}
	jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})

	// Expiry should be ~1 hour from now
	if claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil")
	}
	diff := time.Until(claims.ExpiresAt.Time)
	if diff < 59*time.Minute || diff > 61*time.Minute {
		t.Errorf("token expiry is %v from now, expected ~1 hour", diff)
	}
}

// =============================================================================
// JWTAuth Middleware Tests
// =============================================================================

func TestJWTAuthMissingHeader(t *testing.T) {
	cfg := testConfig()
	handler := JWTAuth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuthInvalidFormat(t *testing.T) {
	cfg := testConfig()
	handler := JWTAuth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		header string
	}{
		{"no bearer prefix", "just-a-token"},
		{"wrong prefix", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"bearer only", "Bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/test", nil)
			req.Header.Set("Authorization", tt.header)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestJWTAuthValidToken(t *testing.T) {
	cfg := testConfig()

	token, err := GenerateToken("admin", "admin", cfg)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	var gotClaims *Claims
	handler := JWTAuth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if gotClaims == nil {
		t.Fatal("claims not set in context")
	}
	if gotClaims.Username != "admin" {
		t.Errorf("Username = %q, want %q", gotClaims.Username, "admin")
	}
}

func TestJWTAuthExpiredToken(t *testing.T) {
	cfg := testConfig()

	// Create a token that's already expired
	claims := &Claims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Subject:   "admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	handler := JWTAuth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for expired token", rr.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuthWrongSecret(t *testing.T) {
	cfg := testConfig()

	// Generate token with different secret
	otherCfg := &config.Config{JWTSecret: "different-secret", JWTExpirationHours: 24}
	token, err := GenerateToken("admin", "admin", otherCfg)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	handler := JWTAuth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for wrong secret", rr.Code, http.StatusUnauthorized)
	}
}

// =============================================================================
// Token Refresh Tests
// =============================================================================

func TestParseTokenAllowExpiredValid(t *testing.T) {
	cfg := testConfig()

	token, err := GenerateToken("admin", "admin", cfg)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims, err := ParseTokenAllowExpired(token, cfg)
	if err != nil {
		t.Fatalf("ParseTokenAllowExpired() error = %v", err)
	}
	if claims.Username != "admin" {
		t.Errorf("Username = %q, want %q", claims.Username, "admin")
	}
}

func TestParseTokenAllowExpiredRecentlyExpired(t *testing.T) {
	cfg := testConfig()

	// Token expired 1 hour ago — within 7-day refresh window
	claims := &Claims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-25 * time.Hour)),
			Subject:   "admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	parsed, err := ParseTokenAllowExpired(tokenStr, cfg)
	if err != nil {
		t.Fatalf("ParseTokenAllowExpired() should accept recently expired token, got error: %v", err)
	}
	if parsed.Username != "admin" {
		t.Errorf("Username = %q, want %q", parsed.Username, "admin")
	}
}

func TestParseTokenAllowExpiredBeyondWindow(t *testing.T) {
	cfg := testConfig()

	// Token expired 8 days ago — beyond 7-day refresh window
	claims := &Claims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-8 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-9 * 24 * time.Hour)),
			Subject:   "admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = ParseTokenAllowExpired(tokenStr, cfg)
	if err == nil {
		t.Fatal("ParseTokenAllowExpired() should reject token expired beyond refresh window")
	}
}

func TestParseTokenAllowExpiredWrongSecret(t *testing.T) {
	cfg := testConfig()

	otherCfg := &config.Config{JWTSecret: "wrong-secret", JWTExpirationHours: 24}
	token, err := GenerateToken("admin", "admin", otherCfg)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = ParseTokenAllowExpired(token, cfg)
	if err == nil {
		t.Fatal("ParseTokenAllowExpired() should reject token with wrong secret")
	}
}

// =============================================================================
// JWTAuthAllowExpired Middleware Tests
// =============================================================================

func TestJWTAuthAllowExpiredMiddleware(t *testing.T) {
	cfg := testConfig()

	// Recently expired token (within refresh window)
	claims := &Claims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-25 * time.Hour)),
			Subject:   "admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString([]byte(cfg.JWTSecret))

	var gotClaims *Claims
	handler := JWTAuthAllowExpired(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for recently expired token on refresh endpoint", rr.Code, http.StatusOK)
	}
	if gotClaims != nil && gotClaims.Username != "admin" {
		t.Errorf("Username = %q, want %q", gotClaims.Username, "admin")
	}
}

// =============================================================================
// RequireRole Tests
// =============================================================================

func TestRequireRoleAdmin(t *testing.T) {
	cfg := testConfig()

	token, _ := GenerateToken("admin", "admin", cfg)

	var reached bool
	handler := JWTAuth(cfg)(RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/api/v1/admin/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !reached {
		t.Error("handler was not reached")
	}
}

func TestRequireRoleInsufficientPermissions(t *testing.T) {
	cfg := testConfig()

	// Generate token for "user" role, but require "admin"
	token, _ := GenerateToken("user1", "user", cfg)

	handler := JWTAuth(cfg)(RequireRole("superadmin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/api/v1/admin/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d for insufficient role", rr.Code, http.StatusForbidden)
	}
}

func TestRequireRoleAdminBypassesOtherRoles(t *testing.T) {
	cfg := testConfig()

	// Admin should access any role-restricted endpoint
	token, _ := GenerateToken("admin", "admin", cfg)

	handler := JWTAuth(cfg)(RequireRole("operator")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (admin should bypass role check)", rr.Code, http.StatusOK)
	}
}

// =============================================================================
// GetUserFromContext Tests
// =============================================================================

func TestGetUserFromContextNil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	claims := GetUserFromContext(req.Context())
	if claims != nil {
		t.Error("GetUserFromContext() should return nil for empty context")
	}
}

// =============================================================================
// MaxBodySize Tests
// =============================================================================

func TestMaxBodySize(t *testing.T) {
	handler := MaxBodySize(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			t.Error("Body should not be nil")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}
