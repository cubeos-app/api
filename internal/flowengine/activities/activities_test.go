package activities

import (
	"context"
	"database/sql"

	"encoding/json"
	"fmt"
	_ "modernc.org/sqlite"
	"testing"
	"time"
)

// --- Mock implementations ---

type mockSwarmManager struct {
	stacks    map[string]bool
	deployErr error
	removeErr error
}

func newMockSwarm() *mockSwarmManager {
	return &mockSwarmManager{stacks: make(map[string]bool)}
}

func (m *mockSwarmManager) DeployStack(name, composePath string) error {
	if m.deployErr != nil {
		return m.deployErr
	}
	m.stacks[name] = true
	return nil
}

func (m *mockSwarmManager) RemoveStack(name string) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	delete(m.stacks, name)
	return nil
}

func (m *mockSwarmManager) GetStackServices(name string) ([]interface{}, error) {
	if m.stacks[name] {
		return []interface{}{"svc1"}, nil
	}
	return nil, nil
}

func (m *mockSwarmManager) ListStacks() ([]interface{}, error) {
	var result []interface{}
	for name := range m.stacks {
		result = append(result, name)
	}
	return result, nil
}

type mockDockerManager struct {
	images      map[string]bool
	pullErr     error
	convergeErr error
}

func newMockDocker() *mockDockerManager {
	return &mockDockerManager{images: make(map[string]bool)}
}

func (m *mockDockerManager) ImageExists(ctx context.Context, imageRef string) (bool, error) {
	return m.images[imageRef], nil
}

func (m *mockDockerManager) PullImage(ctx context.Context, imageRef string) error {
	if m.pullErr != nil {
		return m.pullErr
	}
	m.images[imageRef] = true
	return nil
}

func (m *mockDockerManager) WaitForServiceConvergence(ctx context.Context, stackName string, timeout time.Duration) error {
	return m.convergeErr
}

type mockDNSManager struct {
	entries   map[string]string // domain → IP
	addErr    error
	removeErr error
}

func newMockDNS() *mockDNSManager {
	return &mockDNSManager{entries: make(map[string]string)}
}

func (m *mockDNSManager) AddEntry(domain, ip string) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.entries[domain] = ip
	return nil
}

func (m *mockDNSManager) RemoveEntry(domain string) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	if _, ok := m.entries[domain]; !ok {
		return fmt.Errorf("entry not found: %s", domain)
	}
	delete(m.entries, domain)
	return nil
}

func (m *mockDNSManager) GetEntry(domain string) (string, error) {
	if ip, ok := m.entries[domain]; ok {
		return ip, nil
	}
	return "", nil
}

type mockProxyManager struct {
	hosts     map[string]int64 // domain → host ID
	nextID    int64
	createErr error
	deleteErr error
}

func newMockProxy() *mockProxyManager {
	return &mockProxyManager{hosts: make(map[string]int64), nextID: 1}
}

func (m *mockProxyManager) CreateProxyHost(ctx context.Context, domain string, forwardHost string, forwardPort int, forwardScheme string) (int64, error) {
	if m.createErr != nil {
		return 0, m.createErr
	}
	id := m.nextID
	m.nextID++
	m.hosts[domain] = id
	return id, nil
}

func (m *mockProxyManager) FindProxyHostByDomain(domain string) (int64, error) {
	if id, ok := m.hosts[domain]; ok {
		return id, nil
	}
	return 0, nil
}

func (m *mockProxyManager) DeleteProxyHost(ctx context.Context, id int64) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	for domain, hid := range m.hosts {
		if hid == id {
			delete(m.hosts, domain)
			return nil
		}
	}
	return fmt.Errorf("proxy host not found: %d", id)
}

type mockPortAllocator struct {
	nextPort int
	ports    map[int]bool
}

func newMockPortAllocator() *mockPortAllocator {
	return &mockPortAllocator{nextPort: 6100, ports: make(map[int]bool)}
}

func (m *mockPortAllocator) AllocateUserPort() (int, error) {
	port := m.nextPort
	m.nextPort++
	m.ports[port] = true
	return port, nil
}

func (m *mockPortAllocator) ReleasePort(port int) error {
	if !m.ports[port] {
		return fmt.Errorf("port %d not found", port)
	}
	delete(m.ports, port)
	return nil
}

type mockConflictChecker struct {
	existingApps map[string]bool
}

func newMockConflictChecker() *mockConflictChecker {
	return &mockConflictChecker{existingApps: make(map[string]bool)}
}

func (m *mockConflictChecker) AppExists(ctx context.Context, name string) (bool, error) {
	return m.existingApps[name], nil
}

// --- Docker Activity Tests ---

func TestDeployStackNew(t *testing.T) {
	swarm := newMockSwarm()
	activity := makeDeployStack(swarm)

	input, _ := json.Marshal(DeployStackInput{StackName: "nextcloud", ComposePath: "/cubeos/apps/nextcloud/appconfig/docker-compose.yml"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out DeployStackOutput
	json.Unmarshal(output, &out)
	if !out.Deployed || out.Skipped {
		t.Errorf("expected deployed=true, skipped=false, got deployed=%v, skipped=%v", out.Deployed, out.Skipped)
	}
	if !swarm.stacks["nextcloud"] {
		t.Error("stack not deployed in mock")
	}
}

func TestDeployStackIdempotent(t *testing.T) {
	swarm := newMockSwarm()
	swarm.stacks["nextcloud"] = true // already exists
	activity := makeDeployStack(swarm)

	input, _ := json.Marshal(DeployStackInput{StackName: "nextcloud", ComposePath: "/some/path"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out DeployStackOutput
	json.Unmarshal(output, &out)
	if !out.Deployed || !out.Skipped {
		t.Errorf("expected deployed=true, skipped=true, got deployed=%v, skipped=%v", out.Deployed, out.Skipped)
	}
}

func TestDeployStackError(t *testing.T) {
	swarm := newMockSwarm()
	swarm.deployErr = fmt.Errorf("connection refused")
	activity := makeDeployStack(swarm)

	input, _ := json.Marshal(DeployStackInput{StackName: "test", ComposePath: "/path"})
	_, err := activity(context.Background(), input)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDeployStackInvalidInput(t *testing.T) {
	swarm := newMockSwarm()
	activity := makeDeployStack(swarm)

	input, _ := json.Marshal(DeployStackInput{StackName: "", ComposePath: ""})
	_, err := activity(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRemoveStackIdempotent(t *testing.T) {
	swarm := newMockSwarm()
	activity := makeRemoveStack(swarm)

	// Stack doesn't exist — should succeed
	input, _ := json.Marshal(RemoveStackInput{StackName: "ghost"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out RemoveStackOutput
	json.Unmarshal(output, &out)
	if out.Removed {
		t.Error("expected removed=false for non-existent stack")
	}
}

func TestPullImageNew(t *testing.T) {
	docker := newMockDocker()
	activity := makePullImage(docker)

	input, _ := json.Marshal(PullImageInput{Image: "nginx:latest"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out PullImageOutput
	json.Unmarshal(output, &out)
	if !out.Pulled || out.Skipped {
		t.Errorf("expected pulled=true, skipped=false")
	}
}

func TestPullImageIdempotent(t *testing.T) {
	docker := newMockDocker()
	docker.images["nginx:latest"] = true
	activity := makePullImage(docker)

	input, _ := json.Marshal(PullImageInput{Image: "nginx:latest"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out PullImageOutput
	json.Unmarshal(output, &out)
	if !out.Pulled || !out.Skipped {
		t.Errorf("expected pulled=true, skipped=true for existing image")
	}
}

func TestPullImageNotFound(t *testing.T) {
	docker := newMockDocker()
	docker.pullErr = fmt.Errorf("manifest unknown: not found")
	activity := makePullImage(docker)

	input, _ := json.Marshal(PullImageInput{Image: "nonexistent:v1"})
	_, err := activity(context.Background(), input)
	if err == nil {
		t.Fatal("expected permanent error for missing image")
	}
}

func TestWaitConvergence(t *testing.T) {
	docker := newMockDocker()
	activity := makeWaitConvergence(docker)

	input, _ := json.Marshal(WaitConvergenceInput{StackName: "nextcloud"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out WaitConvergenceOutput
	json.Unmarshal(output, &out)
	if !out.Converged {
		t.Error("expected converged=true")
	}
}

func TestWaitConvergenceTimeout(t *testing.T) {
	docker := newMockDocker()
	docker.convergeErr = fmt.Errorf("timeout waiting for convergence")
	activity := makeWaitConvergence(docker)

	input, _ := json.Marshal(WaitConvergenceInput{StackName: "slow-app", Timeout: 5 * time.Second})
	_, err := activity(context.Background(), input)
	if err == nil {
		t.Fatal("expected transient error on timeout")
	}
}

// --- Infra Activity Tests ---

func TestAddDNSNew(t *testing.T) {
	dns := newMockDNS()
	activity := makeAddDNS(dns)

	input, _ := json.Marshal(AddDNSInput{Domain: "test.cubeos.cube", IP: "10.42.24.1"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out AddDNSOutput
	json.Unmarshal(output, &out)
	if !out.Created || out.Skipped {
		t.Errorf("expected created=true, skipped=false")
	}
	if dns.entries["test.cubeos.cube"] != "10.42.24.1" {
		t.Error("DNS entry not created in mock")
	}
}

func TestAddDNSIdempotent(t *testing.T) {
	dns := newMockDNS()
	dns.entries["test.cubeos.cube"] = "10.42.24.1"
	activity := makeAddDNS(dns)

	input, _ := json.Marshal(AddDNSInput{Domain: "test.cubeos.cube"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out AddDNSOutput
	json.Unmarshal(output, &out)
	if !out.Created || !out.Skipped {
		t.Errorf("expected created=true, skipped=true for existing entry")
	}
}

func TestAddDNSDefaultIP(t *testing.T) {
	dns := newMockDNS()
	activity := makeAddDNS(dns)

	input, _ := json.Marshal(AddDNSInput{Domain: "test.cubeos.cube"}) // no IP
	_, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dns.entries["test.cubeos.cube"] != "10.42.24.1" {
		t.Errorf("expected default gateway IP, got %s", dns.entries["test.cubeos.cube"])
	}
}

func TestRemoveDNSIdempotent(t *testing.T) {
	dns := newMockDNS()
	activity := makeRemoveDNS(dns)

	// Domain doesn't exist — should return removed=false
	input, _ := json.Marshal(RemoveDNSInput{Domain: "ghost.cubeos.cube"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out RemoveDNSOutput
	json.Unmarshal(output, &out)
	if out.Removed {
		t.Error("expected removed=false for non-existent entry")
	}
}

func TestCreateProxyNew(t *testing.T) {
	proxy := newMockProxy()
	activity := makeCreateProxy(proxy)

	input, _ := json.Marshal(CreateProxyInput{Domain: "test.cubeos.cube", ForwardPort: 6100})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out CreateProxyOutput
	json.Unmarshal(output, &out)
	if !out.Created || out.Skipped || out.HostID == 0 {
		t.Errorf("expected created=true, skipped=false, non-zero host_id")
	}
}

func TestCreateProxyIdempotent(t *testing.T) {
	proxy := newMockProxy()
	proxy.hosts["test.cubeos.cube"] = 42
	activity := makeCreateProxy(proxy)

	input, _ := json.Marshal(CreateProxyInput{Domain: "test.cubeos.cube", ForwardPort: 6100})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out CreateProxyOutput
	json.Unmarshal(output, &out)
	if !out.Created || !out.Skipped {
		t.Errorf("expected created=true, skipped=true for existing proxy")
	}
	if out.HostID != 42 {
		t.Errorf("expected host_id=42, got %d", out.HostID)
	}
}

func TestRemoveProxyIdempotent(t *testing.T) {
	proxy := newMockProxy()
	activity := makeRemoveProxy(proxy)

	input, _ := json.Marshal(RemoveProxyInput{Domain: "ghost.cubeos.cube"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out RemoveProxyOutput
	json.Unmarshal(output, &out)
	if out.Removed {
		t.Error("expected removed=false for non-existent proxy")
	}
}

// --- Validation Tests ---

func TestAppInstallValidateSuccess(t *testing.T) {
	checker := newMockConflictChecker()
	activity := makeAppInstallValidate(checker)

	input, _ := json.Marshal(AppInstallValidateInput{Name: "nextcloud", Source: "registry", Image: "nextcloud:latest"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out AppInstallValidateOutput
	json.Unmarshal(output, &out)
	if !out.Valid {
		t.Error("expected valid=true")
	}
}

func TestAppInstallValidateConflict(t *testing.T) {
	checker := newMockConflictChecker()
	checker.existingApps["nextcloud"] = true
	activity := makeAppInstallValidate(checker)

	input, _ := json.Marshal(AppInstallValidateInput{Name: "nextcloud", Source: "registry", Image: "nextcloud:latest"})
	_, err := activity(context.Background(), input)
	if err == nil {
		t.Fatal("expected permanent error for existing app")
	}
}

func TestAppInstallValidateInvalidSource(t *testing.T) {
	checker := newMockConflictChecker()
	activity := makeAppInstallValidate(checker)

	input, _ := json.Marshal(AppInstallValidateInput{Name: "test", Source: "invalid"})
	_, err := activity(context.Background(), input)
	if err == nil {
		t.Fatal("expected permanent error for invalid source")
	}
}

func TestAppInstallValidateEmptyName(t *testing.T) {
	checker := newMockConflictChecker()
	activity := makeAppInstallValidate(checker)

	input, _ := json.Marshal(AppInstallValidateInput{Name: "", Source: "registry"})
	_, err := activity(context.Background(), input)
	if err == nil {
		t.Fatal("expected permanent error for empty name")
	}
}

// --- Port Allocation Tests ---

func TestAllocatePortNew(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec("CREATE TABLE apps (id INTEGER PRIMARY KEY, name TEXT)")
	db.Exec("CREATE TABLE port_allocations (id INTEGER PRIMARY KEY, app_id INTEGER, port INTEGER)")

	portMgr := newMockPortAllocator()
	activity := makeAllocatePort(db, portMgr)

	input, _ := json.Marshal(AllocatePortInput{AppName: "test"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out AllocatePortOutput
	json.Unmarshal(output, &out)
	if out.Port < 6100 {
		t.Errorf("expected port >= 6100, got %d", out.Port)
	}
	if out.Skipped {
		t.Error("expected skipped=false for new allocation")
	}
}

func TestReleasePort(t *testing.T) {
	portMgr := newMockPortAllocator()
	portMgr.ports[6100] = true
	activity := makeReleasePort(nil, portMgr)

	input, _ := json.Marshal(ReleasePortInput{Port: 6100, AppName: "test"})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out ReleasePortOutput
	json.Unmarshal(output, &out)
	if !out.Released {
		t.Error("expected released=true")
	}
	if portMgr.ports[6100] {
		t.Error("port still allocated in mock")
	}
}

func TestReleasePortIdempotent(t *testing.T) {
	portMgr := newMockPortAllocator()
	activity := makeReleasePort(nil, portMgr)

	input, _ := json.Marshal(ReleasePortInput{Port: 6100})
	output, err := activity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out ReleasePortOutput
	json.Unmarshal(output, &out)
	if out.Released {
		t.Error("expected released=false for non-allocated port")
	}
}

// --- isNotFoundError Tests ---

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{nil, false},
		{fmt.Errorf("not found"), true},
		{fmt.Errorf("No Such entry"), true},
		{fmt.Errorf("resource does not exist"), true},
		{fmt.Errorf("status 404"), true},
		{fmt.Errorf("connection refused"), false},
		{fmt.Errorf("timeout"), false},
	}

	for _, tt := range tests {
		result := isNotFoundError(tt.err)
		if result != tt.expected {
			errStr := "<nil>"
			if tt.err != nil {
				errStr = tt.err.Error()
			}
			t.Errorf("isNotFoundError(%q) = %v, want %v", errStr, result, tt.expected)
		}
	}
}

// Suppress unused import warning for sql in tests
var _ = (*sql.DB)(nil)
