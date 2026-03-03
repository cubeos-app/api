// Package managers provides signal recording for Iridium operational dashboard.
// The SignalRecorder subscribes to the HAL Iridium SSE stream and persists
// signal quality readings and SBD credit usage into the database.
package managers

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/hal"
)

// SignalRecorder subscribes to HAL Iridium SSE and persists signal + credit events.
type SignalRecorder struct {
	halClient *hal.Client
	db        *sql.DB
	cancel    context.CancelFunc
}

// NewSignalRecorder creates a new signal recorder.
func NewSignalRecorder(halClient *hal.Client, db *sql.DB) *SignalRecorder {
	return &SignalRecorder{
		halClient: halClient,
		db:        db,
	}
}

// Start begins background subscription to HAL Iridium SSE.
// Returns immediately — runs in a goroutine with retry on disconnect.
// The pruning job for old entries runs at startup + daily.
func (r *SignalRecorder) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)

	// Prune stale entries on startup
	go r.pruneOldEntries()

	// Reconnect loop: HAL may not be connected at startup
	go r.subscribeLoop(ctx)

	// Daily pruning
	go r.dailyPruner(ctx)
}

// Stop cancels the background subscription.
func (r *SignalRecorder) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

// subscribeLoop maintains a continuous SSE subscription with reconnect on disconnect.
func (r *SignalRecorder) subscribeLoop(ctx context.Context) {
	backoff := 5 * time.Second
	const maxBackoff = 2 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := r.subscribe(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Debug().Err(err).Dur("retry_in", backoff).Msg("signal_recorder: SSE disconnected, reconnecting")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// subscribe opens the HAL Iridium SSE stream and processes events until disconnect.
func (r *SignalRecorder) subscribe(ctx context.Context) error {
	resp, err := r.halClient.StreamIridiumEvents(ctx)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Reset backoff on successful connect
	scanner := bufio.NewScanner(resp.Body)
	var eventType, dataLine string

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case line == "":
			// End of event — process it
			if eventType != "" && dataLine != "" {
				r.handleEvent(eventType, dataLine)
			}
			eventType = ""
			dataLine = ""
		}
	}

	return scanner.Err()
}

// iridiumSSEEvent mirrors the HAL IridiumEvent struct for JSON decoding.
type iridiumSSEEvent struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Time    string `json:"time"`
	Signal  int    `json:"signal"`
}

// handleEvent processes a single SSE event and persists relevant data.
func (r *SignalRecorder) handleEvent(eventType, data string) {
	var event iridiumSSEEvent
	if err := json.Unmarshal([]byte(data), &event); err != nil {
		return
	}

	switch event.Type {
	case "signal":
		r.recordSignal(event.Signal)

	case "sbdix_complete", "sent":
		// Future: record SBD credit on successful send.
		// The HAL doesn't currently emit these event types, so this is a
		// no-op placeholder. Credits are also recorded via the send handler.
	}
}

// recordSignal inserts a signal history entry.
func (r *SignalRecorder) recordSignal(bars int) {
	if r.db == nil {
		return
	}
	now := time.Now().Unix()
	_, err := r.db.Exec(
		`INSERT INTO signal_history (source, timestamp, value) VALUES ('iridium', ?, ?)`,
		now, float64(bars),
	)
	if err != nil {
		log.Debug().Err(err).Msg("signal_recorder: failed to insert signal_history row")
	}
}

// RecordSBDCredit records a successful or failed SBD send attempt.
// Called directly from the SendIridiumSBD handler after a send completes.
func (r *SignalRecorder) RecordSBDCredit(moStatus int, bytes int) {
	if r.db == nil {
		return
	}
	now := time.Now().Unix()
	_, err := r.db.Exec(
		`INSERT INTO sbd_credits (direction, timestamp, mo_status, bytes) VALUES ('mo', ?, ?, ?)`,
		now, moStatus, bytes,
	)
	if err != nil {
		log.Debug().Err(err).Msg("signal_recorder: failed to insert sbd_credits row")
	}
}

// GetSignalHistory returns signal history entries for the given time range.
// interval: "raw" (all rows), "hour" (hourly avg), "day" (daily avg).
func (r *SignalRecorder) GetSignalHistory(source string, from, to int64, interval string) ([]SignalHistoryPoint, error) {
	if r.db == nil {
		return nil, nil
	}

	switch interval {
	case "hour":
		return r.getAggregatedSignal(source, from, to, 3600)
	case "day":
		return r.getAggregatedSignal(source, from, to, 86400)
	default: // "raw"
		return r.getRawSignal(source, from, to)
	}
}

// SignalHistoryPoint is a single signal measurement (or aggregated bucket).
type SignalHistoryPoint struct {
	Timestamp int64   `json:"timestamp"` // Unix epoch seconds (bucket start for aggregated)
	Value     float64 `json:"value"`     // bars or dBm
	Min       float64 `json:"min,omitempty"`
	Max       float64 `json:"max,omitempty"`
	Count     int     `json:"count,omitempty"`
}

func (r *SignalRecorder) getRawSignal(source string, from, to int64) ([]SignalHistoryPoint, error) {
	rows, err := r.db.Query(
		`SELECT timestamp, value FROM signal_history
		 WHERE source = ? AND timestamp >= ? AND timestamp <= ?
		 ORDER BY timestamp ASC LIMIT 2000`,
		source, from, to,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []SignalHistoryPoint
	for rows.Next() {
		var p SignalHistoryPoint
		if err := rows.Scan(&p.Timestamp, &p.Value); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

func (r *SignalRecorder) getAggregatedSignal(source string, from, to int64, bucketSecs int64) ([]SignalHistoryPoint, error) {
	rows, err := r.db.Query(
		`SELECT
			(timestamp / ?) * ? AS bucket,
			AVG(value) AS avg_val,
			MIN(value) AS min_val,
			MAX(value) AS max_val,
			COUNT(*) AS cnt
		 FROM signal_history
		 WHERE source = ? AND timestamp >= ? AND timestamp <= ?
		 GROUP BY bucket
		 ORDER BY bucket ASC`,
		bucketSecs, bucketSecs, source, from, to,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []SignalHistoryPoint
	for rows.Next() {
		var p SignalHistoryPoint
		if err := rows.Scan(&p.Timestamp, &p.Value, &p.Min, &p.Max, &p.Count); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// SBDCredits holds credit usage statistics.
type SBDCredits struct {
	Today         int `json:"today"`
	ThisMonth     int `json:"this_month"`
	AllTime       int `json:"all_time"`
	Budget        int `json:"budget"`
	WarningThresh int `json:"warning_threshold"`
}

// GetSBDCredits returns SBD usage statistics and budget settings.
func (r *SignalRecorder) GetSBDCredits() (*SBDCredits, error) {
	if r.db == nil {
		return &SBDCredits{}, nil
	}

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()

	var today, month, allTime int
	r.db.QueryRow(
		`SELECT COUNT(*) FROM sbd_credits WHERE direction = 'mo' AND mo_status = 0 AND timestamp >= ?`,
		todayStart,
	).Scan(&today)
	r.db.QueryRow(
		`SELECT COUNT(*) FROM sbd_credits WHERE direction = 'mo' AND mo_status = 0 AND timestamp >= ?`,
		monthStart,
	).Scan(&month)
	r.db.QueryRow(
		`SELECT COUNT(*) FROM sbd_credits WHERE direction = 'mo' AND mo_status = 0`,
	).Scan(&allTime)

	// Read budget from system_config (optional — defaults to 0 = unset)
	budget, warnThresh := r.readBudget()

	return &SBDCredits{
		Today:         today,
		ThisMonth:     month,
		AllTime:       allTime,
		Budget:        budget,
		WarningThresh: warnThresh,
	}, nil
}

// SetBudget saves the monthly SBD budget and warning threshold to system_config.
func (r *SignalRecorder) SetBudget(budget, warnThreshold int) error {
	if r.db == nil {
		return nil
	}
	_, err := r.db.Exec(
		`INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('sbd_monthly_budget', ?, CURRENT_TIMESTAMP)`,
		budget,
	)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(
		`INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('sbd_warning_threshold', ?, CURRENT_TIMESTAMP)`,
		warnThreshold,
	)
	return err
}

func (r *SignalRecorder) readBudget() (budget, warnThresh int) {
	r.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM system_config WHERE key = 'sbd_monthly_budget'`).Scan(&budget)
	r.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM system_config WHERE key = 'sbd_warning_threshold'`).Scan(&warnThresh)
	return
}

// pruneOldEntries deletes signal_history rows older than 90 days.
func (r *SignalRecorder) pruneOldEntries() {
	if r.db == nil {
		return
	}
	cutoff := time.Now().Add(-90 * 24 * time.Hour).Unix()
	result, err := r.db.Exec(`DELETE FROM signal_history WHERE timestamp < ?`, cutoff)
	if err != nil {
		log.Debug().Err(err).Msg("signal_recorder: prune failed")
		return
	}
	n, _ := result.RowsAffected()
	if n > 0 {
		log.Info().Int64("rows_deleted", n).Msg("signal_recorder: pruned old signal_history entries")
	}
}

// dailyPruner runs pruneOldEntries every 24 hours.
func (r *SignalRecorder) dailyPruner(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.pruneOldEntries()
		}
	}
}
