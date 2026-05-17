# Steering — Database conventions

SQLite via `modernc.org/sqlite` (pure-Go per project Article XI + component Article C-VI). Lives at `/cubeos/data/cubeos.db` (default; overridable via `CUBEOS_DB_PATH`).

## Schema version

**Current: v27.** Tracked via `CurrentSchemaVersion` const in `internal/database/schema.go`. On startup, `internal/database/migrations.go` walks from the persisted version up to `CurrentSchemaVersion` applying each migration sequentially.

## Migration rules

1. **Append-only** per CubeOS Article XIII. Existing migrations are NEVER edited.
2. New migration = new entry at the end of the migrations array with monotonically-increasing version.
3. Migration body uses idempotent SQL (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ... ADD COLUMN` guarded by introspection).
4. Migration is RUN ONCE per device; the runner persists the last-applied version in `schema_migrations` table.
5. A migration that breaks a previously-shipped one is a NEW migration that fixes it — the broken one stays in place because deployed Pi devices already ran it.

## Key tables

| Table                | Purpose                                                        | Schema version added |
|----------------------|----------------------------------------------------------------|---------------------:|
| `apps`               | Installed apps (unified single-source-of-truth)                | v1                   |
| `port_allocations`   | Per-app port allocations in 6100-6999                          | v3                   |
| `fqdns`              | `<app>.cubeos.cube` → service mapping                          | v5                   |
| `profiles`           | Three access profiles + active selection                       | v21 (`access_profiles` per docs/spec/004) |
| `network_config`     | Active network mode + per-mode persisted settings              | v6 + v23 (managed iface) |
| `system_config`      | OS-level config (timezone, hostname, etc.)                     | v1                   |
| `flowengine_runs`    | Saga run history + progress events                             | v22                  |
| `users`              | Operator accounts (single-user typical; multi-user supported)  | v1                   |
| `audit_log`          | Mirror of audit events written to /cubeos/data/audit.log       | v8                   |

## WAL mode

Enabled in `internal/database/database.go` on open: `PRAGMA journal_mode = WAL;`. Improves single-writer / multi-reader concurrency, which is api's exact access pattern.

## Backup

`sqlite3 cubeos.db ".backup /cubeos/data/backups/cubeos.db.last-known-good"` runs as a cron job (configurable; default daily at 04:00 local). The backup file is what spec/001 boot-sequence REQ-117 restores from on detected corruption.

## Query rules

1. **Always use parameterised binds** — `db.Exec("INSERT INTO apps (name, port) VALUES (?, ?)", name, port)` — NEVER string concatenation.
2. **Wrap multi-statement operations in transactions** — `db.BeginTx(ctx, nil)` → `tx.Commit()` or `tx.Rollback()`.
3. **Use `context.Context`** — `db.QueryContext(ctx, ...)` so requests can be cancelled via middleware Timeout(60s).
4. **Use `*sql.NullString` / `*sql.NullInt64`** for nullable columns; never naked pointers.

## Schema-migration test pattern

Every migration has a test in `internal/database/migrations_test.go`:

```go
func TestMigration_v27_adds_ap_interface_role(t *testing.T) {
  db := setupTestDB(t, atVersion(26))
  assert.NoError(t, runMigrations(db, 27))
  rows, _ := db.Query("SELECT name FROM pragma_table_info('network_config') WHERE name = 'ap_interface_role'")
  assert.True(t, rows.Next())
}
```

This pattern catches migration regressions early.
