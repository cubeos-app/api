package flowengine

import (
	"fmt"
	"sort"
	"sync"
)

// ActivityRegistry maps activity names to their implementations.
// Activities are registered at startup by each domain package (docker, infra, db, hal).
// The step executor resolves activities by name at runtime.
//
// Thread-safety: uses sync.RWMutex. Registration (write) happens at startup,
// lookup (read) happens at runtime. Read-heavy pattern.
type ActivityRegistry struct {
	mu         sync.RWMutex
	activities map[string]ActivityFunc
}

// NewActivityRegistry creates an empty activity registry.
func NewActivityRegistry() *ActivityRegistry {
	return &ActivityRegistry{
		activities: make(map[string]ActivityFunc),
	}
}

// Register adds a named activity to the registry. Returns ErrDuplicateActivity
// if an activity with the same name is already registered.
func (r *ActivityRegistry) Register(name string, fn ActivityFunc) error {
	if name == "" {
		return fmt.Errorf("activity name cannot be empty")
	}
	if fn == nil {
		return fmt.Errorf("activity function cannot be nil for %q", name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.activities[name]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateActivity, name)
	}

	r.activities[name] = fn
	return nil
}

// MustRegister adds a named activity to the registry. Panics if registration fails
// (duplicate name or invalid arguments). Use this at startup where registration
// failures are programming errors that should prevent boot.
func (r *ActivityRegistry) MustRegister(name string, fn ActivityFunc) {
	if err := r.Register(name, fn); err != nil {
		panic(fmt.Sprintf("flowengine: failed to register activity %q: %v", name, err))
	}
}

// Get retrieves an activity by name. Returns ErrActivityNotFound if the name
// is not registered.
func (r *ActivityRegistry) Get(name string) (ActivityFunc, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fn, ok := r.activities[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrActivityNotFound, name)
	}
	return fn, nil
}

// List returns the names of all registered activities, sorted alphabetically.
func (r *ActivityRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.activities))
	for name := range r.activities {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Len returns the number of registered activities.
func (r *ActivityRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.activities)
}
