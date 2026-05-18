# Requirements — Port allocation (spec/004 — RETROSPECTIVE)

Source: CGC-verified `internal/managers/ports_new.go:91` (PortManager type) + parent CubeOS Article V.

> Retrospective. ID convention: 400-block.

REQ-400: The system shall expose `PortManager` type at `internal/managers/ports_new.go:91` with fields db, swarm, hal, mu sync.RWMutex.
REQ-401: The system shall provide `NewPortManager(db *sql.DB, swarm *SwarmManager, hal *hal.Client) *PortManager` constructor (CGC-verified at :101).
REQ-402: The system shall expose `AllocateUserPort() (int, error)` returning the lowest free port in `6100-6999` (user-app range).
REQ-403: The system shall expose `AllocateUserPortWithContext(ctx) (int, error)` — context-aware variant preferred for new code.
REQ-404: The system shall expose `AllocatePort(appID, port, protocol, description string, isPrimary bool) error` for explicit allocation with auto-fill (port=0).
REQ-405: The system shall expose `ReleasePort(port int) error` aliasing `DeallocatePort(port, "tcp")`.
REQ-406: The system shall expose `DeallocatePort(port int, protocol string) error`.
REQ-407: The system shall expose `DeallocateAppPorts(appID int64) error` removing all allocations for an app.
REQ-408: The system shall expose `IsPortAllocated(port int, protocol string) (bool, error)`.
REQ-409: The system shall expose `IsPortReserved(port int) bool` checking the ReservedSystemPorts map (22, 53, 80, 443, 6010, etc.).
REQ-410: While allocating, the system shall perform TRIPLE-SOURCE VALIDATION — a port is considered FREE only when (a) DB shows no row, AND (b) Swarm shows no published port, AND (c) HAL reports no listening host process.
REQ-411: If SwarmManager OR HAL Client is nil at constructor, then the system shall fall back to DB-only validation.
REQ-412: The system shall expose `getSwarmPorts(ctx) map[int]string` returning Swarm-published ports across all stacks.
REQ-413: The system shall expose `getHostPorts(ctx) []int` returning host listening ports via HAL `/network/ports/listening`.
REQ-414: While the port pool is exhausted (all 900 user-app ports in use), the system shall return an error from AllocateUserPort.
REQ-415: The system shall use a sync.RWMutex to serialize allocation + release operations across goroutines.
REQ-416: When AllocatePort is called for a reserved port AND the app type is NOT "system" or "platform", the system shall reject with "port N is reserved for system use".
