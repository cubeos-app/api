# Session 2 Handover — Database Migration (`installed_apps` → `apps`)

**Date:** February 8, 2026  
**Session:** 2 of 5 (Session-Balanced Fix Plan)  
**Status:** Complete — ready for CI  
**Branch:** `main`

---

## Objective

Migrate all `installed_apps` table references to the unified `apps` table, add the `app_catalog` table for store caching, and provide a data migration path for existing installations.

---

## Changes Made

### 1. `internal/database/schema.go` (4 changes)

| Change | Detail |
|--------|--------|
| `CurrentSchemaVersion` bumped | 9 → 10 (line 12) |
| `store_app_id` column added | To `apps` table, after `store_id` (line 37) |
| `installed_apps` table removed | Lines 339–358 replaced with `app_catalog` table |
| Seed data updated | `schema_version` in `system_state` defaults to `'10'` |

**`app_catalog` table** replaces `installed_apps` in the schema definition:
- `id` (TEXT PK) — composite store_id/app_name
- `store_id`, `name`, `title`, `description`, `icon_url`, `category`, `version`
- `architectures` (JSON array), `manifest_path`, `cached_at`
- FK to `app_stores(id) ON DELETE CASCADE`

### 2. `internal/database/migrations.go` (2 changes)

| Change | Detail |
|--------|--------|
| Migration 10 added | ~125 lines — full data migration + table operations |
| `DropAllTables` updated | `installed_apps` → `app_catalog` |

**Migration 10 steps:**
1. Add `store_app_id` column to `apps` (idempotent via `isDuplicateColumnError`)
2. Check if `installed_apps` table exists
3. Copy rows from `installed_apps` → `apps` with column mapping (see below)
4. Migrate `npm_proxy_id` values to `fqdns` table
5. Drop `installed_apps` table
6. Create `app_catalog` table + index

**Column mapping used in migration:**

| installed_apps | apps | Notes |
|---|---|---|
| name | name | Natural key |
| title | display_name | Rename |
| description | description | Direct |
| icon | icon_url | Rename |
| category | category | Direct |
| version | version | Direct |
| compose_file | compose_path | Rename |
| data_path | data_path | Direct |
| store_id | store_id | Direct |
| store_app_id | store_app_id | Direct (new column) |
| webui | homepage | Rename |
| deploy_mode | deploy_mode | Direct |
| installed_at | created_at | Rename |
| updated_at | updated_at | Direct |
| status | *(dropped)* | Swarm is truth — runtime only |
| npm_proxy_id | *(→ fqdns table)* | Migrated to fqdns.npm_proxy_id |

### 3. `internal/managers/appstore.go` (7 SQL queries migrated)

| Line (orig) | Old Query | New Query |
|-------------|-----------|-----------|
| 97 | `ALTER TABLE installed_apps ADD COLUMN npm_proxy_id` | Removed — `apps` has all needed columns; only ensures `store_app_id` exists |
| 145 | `SELECT ... FROM installed_apps` | `SELECT ... FROM apps WHERE source = 'casaos'` with column name mapping |
| 741 | `INSERT INTO installed_apps (id, ...)` | `INSERT INTO apps (name, ...) VALUES (?, ..., 'user', 'casaos', TRUE, 'stack', ...)` |
| 956 | `SELECT deploy_mode FROM installed_apps WHERE id = ?` | `SELECT deploy_mode FROM apps WHERE name = ?` |
| 1067 | `SELECT npm_proxy_id FROM installed_apps WHERE id = ?` | `SELECT npm_proxy_id FROM fqdns f JOIN apps a ON a.id = f.app_id WHERE a.name = ?` |
| 1107 | `DELETE FROM installed_apps WHERE id = ?` | `DELETE FROM apps WHERE name = ? AND source = 'casaos'` |
| 1123 | `UPDATE installed_apps SET status = ?` | `UPDATE apps SET updated_at = ? WHERE name = ?` (status not persisted) |

**Additional change:** After INSERT into `apps`, a new FQDN record is created with `npm_proxy_id` (replaces the old column on `installed_apps`).

### 4. `internal/models/app.go` (1 change)

- Added `StoreAppID *string` field to `App` struct (db:"store_app_id")

### 5. `internal/models/appstore.go` (1 addition)

- Added `InstalledAppToApp(ia *InstalledApp) *App` converter function (~40 lines)
- Maps all InstalledApp fields to the unified App model
- Handles nil-to-pointer conversions for optional fields (StoreID, StoreAppID)
- Marked as `Deprecated` — for backward compatibility with CasaOS import flows

---

## Key Design Decisions

### `source = 'casaos'` filter
The `loadInstalledApps` query now filters `WHERE source = 'casaos'` to only load store-installed apps. System/platform apps (pihole, npm, etc.) are in the same `apps` table but have `source = 'cubeos'` — the AppStoreManager shouldn't manage those.

### `DELETE ... AND source = 'casaos'` guard
The RemoveApp DELETE includes `AND source = 'casaos'` as a safety guard to prevent accidental deletion of system apps through the AppStore manager.

### Status not persisted
The `updateAppStatus` function no longer writes status to the database. The `apps` table has no `status` column because Swarm is the single source of truth for runtime state. The in-memory `InstalledApp.Status` is refreshed from Docker/Swarm on every query via `refreshAppStatus`.

### npm_proxy_id → fqdns table
Instead of storing `npm_proxy_id` on the app record (as `installed_apps` did), it's now stored per-FQDN in the `fqdns` table. The RemoveApp function queries it via a JOIN. The InstallApp function creates a FQDN record with the proxy ID after inserting the app.

---

## Verification Results

```
# Schema version
grep "CurrentSchemaVersion" internal/database/schema.go
→ const CurrentSchemaVersion = 10

# No installed_apps CREATE TABLE in schema
grep -c "CREATE TABLE.*installed_apps" internal/database/schema.go
→ 0

# app_catalog table exists in schema
grep -c "CREATE TABLE.*app_catalog" internal/database/schema.go
→ 1

# store_app_id in apps table
grep -c "store_app_id" internal/database/schema.go
→ 1

# Zero active installed_apps SQL in appstore.go
grep -c "FROM installed_apps\|INTO installed_apps\|installed_apps WHERE\|installed_apps SET" internal/managers/appstore.go
→ 0

# InstalledAppToApp converter exists
grep -c "func InstalledAppToApp" internal/models/appstore.go
→ 1

# Migration 10 exists
grep -c "Version:.*10" internal/database/migrations.go
→ 1

# Note: go build / go test cannot run in this environment (proxy.golang.org blocked)
# Build verification must happen on Pi via CI pipeline
```

---

## Net Impact

| Metric | Value |
|--------|-------|
| Lines removed | ~25 (installed_apps table + index from schema) |
| Lines modified | 7 SQL queries in appstore.go |
| Lines added | ~165 (migration 10 + app_catalog table + converter + store_app_id) |
| Files modified | 4 (schema.go, migrations.go, appstore.go, app.go) |
| Files with additions | 1 (appstore.go model converter) |
| Tests broken | None expected (queries produce same data shape) |
| New risks | Medium — SQL column mapping must be verified on Pi with real data |

---

## What's Next — Session 3: FQDN Bug Fix + Error Standardization

Session 3 fixes the only critical bug (UpdateFQDN NPM proxy sync) and standardizes error response helpers across all handlers.

**Key tasks:**
1. Fix `UpdateFQDN` in `fqdns.go` (line 306) — updates DB but never syncs NPM proxy host
2. Delete 5 duplicate error helpers across handlers
3. Migrate all call sites to `writeError`/`writeJSON` from `handlers.go`

**Pre-read files for Session 3:**
- `internal/handlers/fqdns.go` (445 lines)
- `internal/handlers/handlers.go` (826 lines)
- `internal/handlers/appstore.go` (977 lines)
- `internal/handlers/mounts.go` (325 lines)
- `internal/handlers/vpn.go` (325 lines)

---

*Session 2 prompt used: "This is Session 2: Database Migration. Tasks: Migrate all `installed_apps` references to the unified `apps` table. (1) Read schema.go to map columns between installed_apps (line 339) and apps (line 25), (2) Migrate 7 SQL queries in appstore.go (lines 97, 145, 741, 956, 1067, 1107, 1123), (3) Add migration 9→10 in migrations.go, (4) Remove installed_apps CREATE TABLE from schema.go, (5) Add app_catalog table, (6) Bump CurrentSchemaVersion to 10, (7) Add InstalledApp→App converter in models/appstore.go."*
