package flowengine

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

// noop is a minimal activity for testing registration.
var noop ActivityFunc = func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	return nil, nil
}

func TestActivityRegistry_Register(t *testing.T) {
	reg := NewActivityRegistry()

	if err := reg.Register("docker.deploy_stack", noop); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if reg.Len() != 1 {
		t.Fatalf("expected 1 activity, got %d", reg.Len())
	}
}

func TestActivityRegistry_RegisterDuplicate(t *testing.T) {
	reg := NewActivityRegistry()

	if err := reg.Register("docker.deploy_stack", noop); err != nil {
		t.Fatalf("first Register failed: %v", err)
	}

	err := reg.Register("docker.deploy_stack", noop)
	if err == nil {
		t.Fatal("expected error on duplicate registration")
	}
	if !errors.Is(err, ErrDuplicateActivity) {
		t.Fatalf("expected ErrDuplicateActivity, got: %v", err)
	}
}

func TestActivityRegistry_RegisterEmptyName(t *testing.T) {
	reg := NewActivityRegistry()
	err := reg.Register("", noop)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestActivityRegistry_RegisterNilFunc(t *testing.T) {
	reg := NewActivityRegistry()
	err := reg.Register("test", nil)
	if err == nil {
		t.Fatal("expected error for nil function")
	}
}

func TestActivityRegistry_MustRegisterPanics(t *testing.T) {
	reg := NewActivityRegistry()
	reg.MustRegister("docker.deploy_stack", noop)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate MustRegister")
		}
	}()

	reg.MustRegister("docker.deploy_stack", noop) // should panic
}

func TestActivityRegistry_Get(t *testing.T) {
	reg := NewActivityRegistry()
	reg.MustRegister("docker.deploy_stack", noop)

	fn, err := reg.Get("docker.deploy_stack")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if fn == nil {
		t.Fatal("expected non-nil function")
	}
}

func TestActivityRegistry_GetNotFound(t *testing.T) {
	reg := NewActivityRegistry()

	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown activity")
	}
	if !errors.Is(err, ErrActivityNotFound) {
		t.Fatalf("expected ErrActivityNotFound, got: %v", err)
	}
}

func TestActivityRegistry_List(t *testing.T) {
	reg := NewActivityRegistry()
	reg.MustRegister("infra.add_dns", noop)
	reg.MustRegister("docker.deploy_stack", noop)
	reg.MustRegister("db.insert_app", noop)

	names := reg.List()
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d", len(names))
	}

	// List returns sorted names
	expected := []string{"db.insert_app", "docker.deploy_stack", "infra.add_dns"}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("index %d: expected %q, got %q", i, expected[i], name)
		}
	}
}

func TestActivityRegistry_CrossPackageCoexistence(t *testing.T) {
	reg := NewActivityRegistry()

	// Simulate activities from different packages
	reg.MustRegister("docker.deploy_stack", noop)
	reg.MustRegister("docker.remove_stack", noop)
	reg.MustRegister("infra.add_dns", noop)
	reg.MustRegister("infra.remove_dns", noop)
	reg.MustRegister("db.insert_app", noop)
	reg.MustRegister("hal.health_check", noop)

	if reg.Len() != 6 {
		t.Fatalf("expected 6 activities, got %d", reg.Len())
	}

	// All should be retrievable
	for _, name := range []string{
		"docker.deploy_stack", "docker.remove_stack",
		"infra.add_dns", "infra.remove_dns",
		"db.insert_app", "hal.health_check",
	} {
		if _, err := reg.Get(name); err != nil {
			t.Errorf("Get(%q) failed: %v", name, err)
		}
	}
}

func TestActivityRegistry_ConcurrentAccess(t *testing.T) {
	reg := NewActivityRegistry()

	// Pre-register some activities
	for i := 0; i < 10; i++ {
		name := "activity." + string(rune('a'+i))
		reg.MustRegister(name, noop)
	}

	// Concurrent reads should not race
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "activity." + string(rune('a'+(idx%10)))
			_, _ = reg.Get(name)
			_ = reg.List()
			_ = reg.Len()
		}(i)
	}
	wg.Wait()
}

func TestActivityRegistry_GetReturnsCallableFunc(t *testing.T) {
	called := false
	reg := NewActivityRegistry()
	reg.MustRegister("test.action", func(_ context.Context, input json.RawMessage) (json.RawMessage, error) {
		called = true
		return json.RawMessage(`{"ok":true}`), nil
	})

	fn, err := reg.Get("test.action")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	out, err := fn(context.Background(), nil)
	if err != nil {
		t.Fatalf("activity call failed: %v", err)
	}
	if !called {
		t.Fatal("activity was not called")
	}
	if string(out) != `{"ok":true}` {
		t.Fatalf("unexpected output: %s", out)
	}
}
