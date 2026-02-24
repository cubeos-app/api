package managers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"cubeos-api/internal/flowengine"
	feworkflows "cubeos-api/internal/flowengine/workflows"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// =============================================================================
// Cron Parser — minimal 5-field parser (no external dependency)
// =============================================================================

// CronSchedule represents a parsed 5-field cron expression.
// Fields: minute hour day_of_month month day_of_week
type CronSchedule struct {
	Minutes     []bool // [0..59]
	Hours       []bool // [0..23]
	DaysOfMonth []bool // [1..31]
	Months      []bool // [1..12]
	DaysOfWeek  []bool // [0..6] (0 = Sunday)
}

// ParseCron parses a standard 5-field cron expression.
// Supported syntax: exact values (0, 2), wildcards (*), step values (*/6),
// ranges (1-5), and comma-separated lists (1,3,5).
func ParseCron(expr string) (*CronSchedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron: expected 5 fields, got %d", len(fields))
	}

	minutes, err := parseCronField(fields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("cron minute: %w", err)
	}
	hours, err := parseCronField(fields[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("cron hour: %w", err)
	}
	dom, err := parseCronField(fields[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("cron day_of_month: %w", err)
	}
	months, err := parseCronField(fields[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("cron month: %w", err)
	}
	dow, err := parseCronField(fields[4], 0, 6)
	if err != nil {
		return nil, fmt.Errorf("cron day_of_week: %w", err)
	}

	return &CronSchedule{
		Minutes:     minutes,
		Hours:       hours,
		DaysOfMonth: dom,
		Months:      months,
		DaysOfWeek:  dow,
	}, nil
}

// parseCronField parses one field of a cron expression into a boolean slice.
// Supports: *, exact value, step (*/N), range (A-B), comma-separated lists.
func parseCronField(field string, min, max int) ([]bool, error) {
	size := max + 1
	result := make([]bool, size)

	parts := strings.Split(field, ",")
	for _, part := range parts {
		if err := parseCronPart(part, min, max, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func parseCronPart(part string, min, max int, result []bool) error {
	// Handle step values: */N or A-B/N
	step := 1
	if idx := strings.Index(part, "/"); idx >= 0 {
		var err error
		step, err = strconv.Atoi(part[idx+1:])
		if err != nil || step <= 0 {
			return fmt.Errorf("invalid step: %s", part)
		}
		part = part[:idx]
	}

	// Wildcard
	if part == "*" {
		for i := min; i <= max; i += step {
			result[i] = true
		}
		return nil
	}

	// Range: A-B
	if idx := strings.Index(part, "-"); idx >= 0 {
		lo, err := strconv.Atoi(part[:idx])
		if err != nil {
			return fmt.Errorf("invalid range start: %s", part)
		}
		hi, err := strconv.Atoi(part[idx+1:])
		if err != nil {
			return fmt.Errorf("invalid range end: %s", part)
		}
		if lo < min || hi > max || lo > hi {
			return fmt.Errorf("range out of bounds: %d-%d (allowed %d-%d)", lo, hi, min, max)
		}
		for i := lo; i <= hi; i += step {
			result[i] = true
		}
		return nil
	}

	// Exact value
	val, err := strconv.Atoi(part)
	if err != nil {
		return fmt.Errorf("invalid value: %s", part)
	}
	if val < min || val > max {
		return fmt.Errorf("value %d out of bounds (%d-%d)", val, min, max)
	}
	result[val] = true
	return nil
}

// Matches returns true if the given time matches the cron expression.
func (c *CronSchedule) Matches(t time.Time) bool {
	return c.Minutes[t.Minute()] &&
		c.Hours[t.Hour()] &&
		c.DaysOfMonth[t.Day()] &&
		c.Months[int(t.Month())] &&
		c.DaysOfWeek[int(t.Weekday())]
}

// Next returns the next occurrence after the given time.
// Searches up to 366 days ahead to avoid infinite loops.
func (c *CronSchedule) Next(after time.Time) time.Time {
	// Start from the next minute
	t := after.Truncate(time.Minute).Add(time.Minute)

	// Search up to ~366 days (527040 minutes)
	for i := 0; i < 527040; i++ {
		if c.Matches(t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	// Fallback: return 24h later (should never happen with valid cron)
	return after.Add(24 * time.Hour)
}

// =============================================================================
// Scheduler fields and methods — extend BackupManager
// =============================================================================

// backupScheduler holds the scheduler state. Embedded lazily in BackupManager
// to avoid changing the struct layout for consumers that don't need scheduling.
type backupScheduler struct {
	flowEngine *flowengine.WorkflowEngine
	feStore    *flowengine.WorkflowStore
	schedules  []models.BackupSchedule
	scheduleMu sync.RWMutex
	stopCh     chan struct{}
	running    bool
}

// SetFlowEngine wires the FlowEngine for scheduled backup submission.
func (m *BackupManager) SetFlowEngine(engine *flowengine.WorkflowEngine, store *flowengine.WorkflowStore) {
	m.ensureScheduler()
	m.scheduler.flowEngine = engine
	m.scheduler.feStore = store
}

func (m *BackupManager) ensureScheduler() {
	if m.scheduler == nil {
		m.scheduler = &backupScheduler{
			stopCh: make(chan struct{}),
		}
	}
}

// StartScheduler starts the background scheduler goroutine.
// Checks every minute if any enabled schedule is due. Submits BackupWorkflow via FlowEngine.
func (m *BackupManager) StartScheduler(ctx context.Context) {
	m.ensureScheduler()
	if m.scheduler.running {
		return
	}
	m.scheduler.running = true

	// Pre-load schedules and compute next_run_at for any that don't have it
	if err := m.LoadSchedules(ctx); err != nil {
		log.Warn().Err(err).Msg("backup scheduler: failed to load schedules on start")
	}

	go m.schedulerLoop(ctx)
	log.Info().Msg("backup scheduler: started (60s tick)")
}

// StopScheduler stops the background scheduler.
func (m *BackupManager) StopScheduler() {
	if m.scheduler == nil || !m.scheduler.running {
		return
	}
	close(m.scheduler.stopCh)
	m.scheduler.running = false
	log.Info().Msg("backup scheduler: stopped")
}

func (m *BackupManager) schedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.scheduler.stopCh:
			return
		case now := <-ticker.C:
			m.checkSchedules(ctx, now)
		}
	}
}

func (m *BackupManager) checkSchedules(ctx context.Context, now time.Time) {
	schedules, err := m.GetSchedules(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("backup scheduler: failed to load schedules")
		return
	}

	truncated := now.Truncate(time.Minute)

	for _, sched := range schedules {
		if !sched.Enabled {
			continue
		}

		cron, err := ParseCron(sched.CronExpr)
		if err != nil {
			log.Warn().Err(err).Str("schedule", sched.Name).Msg("backup scheduler: invalid cron expression")
			continue
		}

		if cron.Matches(truncated) {
			log.Info().Str("schedule", sched.Name).Str("cron", sched.CronExpr).Msg("backup scheduler: schedule triggered")
			m.submitScheduledBackup(ctx, sched)
			m.updateScheduleRun(ctx, sched.ID, now, cron.Next(now))
		}
	}
}

func (m *BackupManager) submitScheduledBackup(ctx context.Context, sched models.BackupSchedule) {
	if m.scheduler.flowEngine == nil {
		log.Error().Str("schedule", sched.Name).Msg("backup scheduler: FlowEngine not wired, cannot submit backup")
		return
	}

	scope := string(sched.Scope)
	if scope == "" {
		scope = "tier1"
	}
	dest := string(sched.Destination)
	if dest == "" {
		dest = "local"
	}

	workflowInput := feworkflows.BackupInput{
		Scope:       scope,
		Destination: dest,
		DestConfig:  sched.DestConfig,
		Encrypt:     sched.Encryption,
		Description: fmt.Sprintf("Scheduled backup: %s", sched.Name),
	}

	inputJSON, err := json.Marshal(workflowInput)
	if err != nil {
		log.Error().Err(err).Str("schedule", sched.Name).Msg("backup scheduler: failed to marshal workflow input")
		m.setScheduleStatus(ctx, sched.ID, "failed")
		return
	}

	wf, err := m.scheduler.flowEngine.Submit(ctx, flowengine.SubmitParams{
		WorkflowType: feworkflows.BackupWorkflowType,
		ExternalID:   fmt.Sprintf("scheduled-backup-%d", sched.ID),
		Input:        inputJSON,
	})
	if err != nil {
		log.Error().Err(err).Str("schedule", sched.Name).Msg("backup scheduler: failed to submit workflow")
		m.setScheduleStatus(ctx, sched.ID, "failed")
		return
	}

	log.Info().Str("schedule", sched.Name).Str("workflow_id", wf.ID).Msg("backup scheduler: workflow submitted")
	m.setScheduleStatus(ctx, sched.ID, "running")

	// Apply retention and config snapshot retention in background after a delay
	// (give workflow time to complete)
	go func() {
		// Wait for workflow completion (poll up to 30 minutes)
		waitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		if err := flowengine.WaitForCompletion(waitCtx, m.scheduler.feStore, wf.ID); err != nil {
			log.Warn().Err(err).Str("schedule", sched.Name).Msg("backup scheduler: workflow did not complete successfully")
			m.setScheduleStatus(context.Background(), sched.ID, "failed")
			return
		}

		m.setScheduleStatus(context.Background(), sched.ID, "completed")
		log.Info().Str("schedule", sched.Name).Msg("backup scheduler: workflow completed, applying retention")

		retCtx := context.Background()

		// Apply backup retention
		if err := m.ApplyRetention(retCtx, sched.ID); err != nil {
			log.Warn().Err(err).Str("schedule", sched.Name).Msg("backup scheduler: retention failed")
		}

		// Apply config snapshot retention (P0: keep last 20)
		if err := m.ApplyConfigSnapshotRetention(retCtx, 20); err != nil {
			log.Warn().Err(err).Msg("backup scheduler: config snapshot retention failed")
		}
	}()
}

func (m *BackupManager) updateScheduleRun(ctx context.Context, scheduleID int, now time.Time, nextRun time.Time) {
	if m.db == nil {
		return
	}
	_, err := m.db.ExecContext(ctx,
		`UPDATE backup_schedules SET last_run_at = ?, next_run_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		now.Format(time.RFC3339), nextRun.Format(time.RFC3339), scheduleID,
	)
	if err != nil {
		log.Warn().Err(err).Int("schedule_id", scheduleID).Msg("backup scheduler: failed to update schedule run times")
	}
}

func (m *BackupManager) setScheduleStatus(ctx context.Context, scheduleID int, status string) {
	if m.db == nil {
		return
	}
	_, err := m.db.ExecContext(ctx,
		`UPDATE backup_schedules SET last_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		status, scheduleID,
	)
	if err != nil {
		log.Warn().Err(err).Int("schedule_id", scheduleID).Msg("backup scheduler: failed to update schedule status")
	}
}

// =============================================================================
// Schedule CRUD
// =============================================================================

// LoadSchedules reads all schedules from the database into the cache.
func (m *BackupManager) LoadSchedules(ctx context.Context) error {
	schedules, err := m.GetSchedules(ctx)
	if err != nil {
		return err
	}
	m.ensureScheduler()
	m.scheduler.scheduleMu.Lock()
	m.scheduler.schedules = schedules
	m.scheduler.scheduleMu.Unlock()
	return nil
}

// GetSchedules returns all backup schedules from the database.
func (m *BackupManager) GetSchedules(ctx context.Context) ([]models.BackupSchedule, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not wired")
	}

	rows, err := m.db.QueryContext(ctx,
		`SELECT id, name, enabled, cron_expr, scope, destination, dest_config, encryption, retention_count,
		        COALESCE(last_run_at, ''), COALESCE(last_status, ''), COALESCE(next_run_at, '')
		 FROM backup_schedules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("failed to query schedules: %w", err)
	}
	defer rows.Close()

	var schedules []models.BackupSchedule
	for rows.Next() {
		var s models.BackupSchedule
		var destConfig string
		var lastRunAt, nextRunAt string
		if err := rows.Scan(&s.ID, &s.Name, &s.Enabled, &s.CronExpr, &s.Scope, &s.Destination,
			&destConfig, &s.Encryption, &s.RetentionCount,
			&lastRunAt, &s.LastStatus, &nextRunAt); err != nil {
			return nil, fmt.Errorf("failed to scan schedule: %w", err)
		}
		if destConfig != "" && destConfig != "{}" {
			s.DestConfig = json.RawMessage(destConfig)
		}
		s.LastRunAt = lastRunAt
		s.NextRunAt = nextRunAt
		schedules = append(schedules, s)
	}
	return schedules, rows.Err()
}

// GetSchedule returns a single schedule by ID.
func (m *BackupManager) GetSchedule(ctx context.Context, id int) (*models.BackupSchedule, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not wired")
	}

	var s models.BackupSchedule
	var destConfig string
	var lastRunAt, nextRunAt string
	err := m.db.QueryRowContext(ctx,
		`SELECT id, name, enabled, cron_expr, scope, destination, dest_config, encryption, retention_count,
		        COALESCE(last_run_at, ''), COALESCE(last_status, ''), COALESCE(next_run_at, '')
		 FROM backup_schedules WHERE id = ?`, id).
		Scan(&s.ID, &s.Name, &s.Enabled, &s.CronExpr, &s.Scope, &s.Destination,
			&destConfig, &s.Encryption, &s.RetentionCount,
			&lastRunAt, &s.LastStatus, &nextRunAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule: %w", err)
	}
	if destConfig != "" && destConfig != "{}" {
		s.DestConfig = json.RawMessage(destConfig)
	}
	s.LastRunAt = lastRunAt
	s.NextRunAt = nextRunAt
	return &s, nil
}

// CreateSchedule creates a new backup schedule and computes its next run time.
func (m *BackupManager) CreateSchedule(ctx context.Context, schedule models.BackupSchedule) (*models.BackupSchedule, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not wired")
	}

	// Validate cron expression
	cron, err := ParseCron(schedule.CronExpr)
	if err != nil {
		return nil, fmt.Errorf("invalid cron expression: %w", err)
	}

	// Defaults
	if schedule.Scope == "" {
		schedule.Scope = models.BackupScopeTier1
	}
	if schedule.Destination == "" {
		schedule.Destination = models.BackupDestLocal
	}
	if schedule.RetentionCount <= 0 {
		schedule.RetentionCount = 5
	}

	destConfig := "{}"
	if len(schedule.DestConfig) > 0 {
		destConfig = string(schedule.DestConfig)
	}

	nextRun := cron.Next(time.Now())

	result, err := m.db.ExecContext(ctx,
		`INSERT INTO backup_schedules (name, enabled, cron_expr, scope, destination, dest_config, encryption, retention_count, next_run_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		schedule.Name, schedule.Enabled, schedule.CronExpr, schedule.Scope, schedule.Destination,
		destConfig, schedule.Encryption, schedule.RetentionCount, nextRun.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create schedule: %w", err)
	}

	id, _ := result.LastInsertId()
	schedule.ID = int(id)
	schedule.NextRunAt = nextRun.Format(time.RFC3339)

	log.Info().Str("name", schedule.Name).Str("cron", schedule.CronExpr).Msg("backup scheduler: schedule created")
	return &schedule, nil
}

// UpdateSchedule updates an existing backup schedule.
func (m *BackupManager) UpdateSchedule(ctx context.Context, schedule models.BackupSchedule) error {
	if m.db == nil {
		return fmt.Errorf("database not wired")
	}

	// Validate cron expression
	cron, err := ParseCron(schedule.CronExpr)
	if err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	destConfig := "{}"
	if len(schedule.DestConfig) > 0 {
		destConfig = string(schedule.DestConfig)
	}

	nextRun := cron.Next(time.Now())

	_, err = m.db.ExecContext(ctx,
		`UPDATE backup_schedules SET name = ?, enabled = ?, cron_expr = ?, scope = ?, destination = ?,
		        dest_config = ?, encryption = ?, retention_count = ?, next_run_at = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		schedule.Name, schedule.Enabled, schedule.CronExpr, schedule.Scope, schedule.Destination,
		destConfig, schedule.Encryption, schedule.RetentionCount, nextRun.Format(time.RFC3339),
		schedule.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update schedule: %w", err)
	}

	log.Info().Str("name", schedule.Name).Int("id", schedule.ID).Msg("backup scheduler: schedule updated")
	return nil
}

// DeleteSchedule removes a schedule by ID.
func (m *BackupManager) DeleteSchedule(ctx context.Context, id int) error {
	if m.db == nil {
		return fmt.Errorf("database not wired")
	}

	result, err := m.db.ExecContext(ctx, `DELETE FROM backup_schedules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete schedule: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("schedule not found")
	}

	log.Info().Int("id", id).Msg("backup scheduler: schedule deleted")
	return nil
}

// TriggerSchedule immediately runs a schedule (submits a backup workflow).
func (m *BackupManager) TriggerSchedule(ctx context.Context, id int) error {
	sched, err := m.GetSchedule(ctx, id)
	if err != nil {
		return err
	}
	if sched == nil {
		return fmt.Errorf("schedule not found")
	}

	m.submitScheduledBackup(ctx, *sched)

	// Update next_run_at
	cron, err := ParseCron(sched.CronExpr)
	if err == nil {
		m.updateScheduleRun(ctx, sched.ID, time.Now(), cron.Next(time.Now()))
	}

	return nil
}

// =============================================================================
// Retention
// =============================================================================

// ApplyRetention deletes old backups exceeding the retention count for a schedule.
// Only applies to scheduled backups (those with matching schedule_id).
// Manual backups are never auto-deleted.
func (m *BackupManager) ApplyRetention(ctx context.Context, scheduleID int) error {
	if m.db == nil {
		return fmt.Errorf("database not wired")
	}

	// Get retention count for this schedule
	var retentionCount int
	err := m.db.QueryRowContext(ctx,
		`SELECT retention_count FROM backup_schedules WHERE id = ?`, scheduleID).Scan(&retentionCount)
	if err != nil {
		return fmt.Errorf("failed to get retention count: %w", err)
	}
	if retentionCount <= 0 {
		return nil // no retention policy
	}

	// Find backups to delete: those beyond the retention count, ordered by created_at DESC
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, name, destination_path FROM backups
		 WHERE schedule_id = ?
		 ORDER BY created_at DESC
		 LIMIT -1 OFFSET ?`, scheduleID, retentionCount)
	if err != nil {
		return fmt.Errorf("failed to query old backups: %w", err)
	}
	defer rows.Close()

	var toDelete []struct {
		id   int
		name string
		path string
	}
	for rows.Next() {
		var d struct {
			id   int
			name string
			path string
		}
		if err := rows.Scan(&d.id, &d.name, &d.path); err != nil {
			continue
		}
		toDelete = append(toDelete, d)
	}

	for _, d := range toDelete {
		// Delete DB record
		_, err := m.db.ExecContext(ctx, `DELETE FROM backups WHERE id = ?`, d.id)
		if err != nil {
			log.Warn().Err(err).Int("backup_id", d.id).Msg("backup retention: failed to delete DB record")
			continue
		}
		log.Info().Str("name", d.name).Int("backup_id", d.id).Msg("backup retention: deleted old backup record")
	}

	return nil
}

// ApplyConfigSnapshotRetention removes old config snapshots beyond the retention limit.
// P0 specifies: keep last 20 snapshots. Total storage ~4 MB (20 x 200 KB JSON).
func (m *BackupManager) ApplyConfigSnapshotRetention(ctx context.Context, maxSnapshots int) error {
	if m.db == nil {
		return fmt.Errorf("database not wired")
	}
	if maxSnapshots <= 0 {
		maxSnapshots = 20
	}

	result, err := m.db.ExecContext(ctx,
		`DELETE FROM config_snapshots WHERE id NOT IN (
			SELECT id FROM config_snapshots ORDER BY created_at DESC LIMIT ?
		)`, maxSnapshots)
	if err != nil {
		return fmt.Errorf("failed to apply config snapshot retention: %w", err)
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		log.Info().Int64("deleted", deleted).Int("max", maxSnapshots).Msg("backup scheduler: pruned old config snapshots")
	}
	return nil
}
