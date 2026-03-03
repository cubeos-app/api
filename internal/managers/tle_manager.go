// Package managers provides a TLE manager for Iridium satellite pass prediction.
// The TLEManager fetches Iridium NEXT TLEs from Celestrak daily, caches them
// in the database, and computes upcoming passes for a given ground location.
package managers

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/akhenakh/sgp4"
	"github.com/rs/zerolog/log"
)

// celestrakURL is the Celestrak endpoint for Iridium NEXT TLEs (3-line format).
// Override with CELESTRAK_IRIDIUM_URL environment variable.
const defaultCelestrakURL = "https://celestrak.org/SATCAT/TLE/iridium-NEXT.txt"

// IridiumLocation represents a ground station for pass prediction.
type IridiumLocation struct {
	ID      int64   `db:"id" json:"id"`
	Name    string  `db:"name" json:"name"`
	Lat     float64 `db:"lat" json:"lat"`
	Lon     float64 `db:"lon" json:"lon"`
	AltM    float64 `db:"alt_m" json:"alt_m"`
	Builtin bool    `db:"builtin" json:"builtin"`
}

// tleCacheRow is the DB row for a cached TLE entry.
type tleCacheRow struct {
	ID            int64  `db:"id"`
	SatelliteName string `db:"satellite_name"`
	Line1         string `db:"line1"`
	Line2         string `db:"line2"`
	FetchedAt     int64  `db:"fetched_at"`
}

// PassSummary is the API response for a single satellite pass over a ground station.
type PassSummary struct {
	Satellite   string    `json:"satellite"`
	AOS         time.Time `json:"aos"`
	LOS         time.Time `json:"los"`
	DurationMin float64   `json:"duration_min"`
	PeakElevDeg float64   `json:"peak_elev_deg"`
	PeakAzimuth float64   `json:"peak_azimuth"`
	AOSAzimuth  float64   `json:"aos_azimuth"`
	LOSAzimuth  float64   `json:"los_azimuth"`
	IsActive    bool      `json:"is_active"` // pass is currently in progress
}

// TLEManager fetches and caches Iridium NEXT TLEs and computes passes.
type TLEManager struct {
	db     *sql.DB
	cancel context.CancelFunc
}

// NewTLEManager creates a new TLE manager.
func NewTLEManager(db *sql.DB) *TLEManager {
	return &TLEManager{db: db}
}

// Start begins the daily TLE refresh background job.
// If the cache is empty or stale (>24h), an immediate refresh is triggered.
func (m *TLEManager) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	go m.refreshLoop(ctx)
}

// Stop cancels the background refresh goroutine.
func (m *TLEManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *TLEManager) refreshLoop(ctx context.Context) {
	// Refresh immediately if cache is empty or stale
	age, err := m.cacheAge()
	if err != nil || age > 24*time.Hour {
		if err := m.RefreshTLEs(ctx); err != nil {
			log.Warn().Err(err).Msg("tle_manager: initial TLE refresh failed")
		}
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.RefreshTLEs(ctx); err != nil {
				log.Warn().Err(err).Msg("tle_manager: daily TLE refresh failed")
			}
		}
	}
}

// cacheAge returns the age of the most recently fetched TLE entry.
func (m *TLEManager) cacheAge() (time.Duration, error) {
	var maxFetchedAt int64
	if err := m.db.QueryRow(`SELECT COALESCE(MAX(fetched_at), 0) FROM iridium_tle_cache`).Scan(&maxFetchedAt); err != nil {
		return 0, err
	}
	if maxFetchedAt == 0 {
		return 999 * time.Hour, nil // empty cache
	}
	return time.Since(time.Unix(maxFetchedAt, 0)), nil
}

// RefreshTLEs fetches fresh TLEs from Celestrak and updates the cache.
func (m *TLEManager) RefreshTLEs(ctx context.Context) error {
	url := os.Getenv("CELESTRAK_IRIDIUM_URL")
	if url == "" {
		url = defaultCelestrakURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "CubeOS/1.0 (Iridium pass predictor)")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch TLEs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Celestrak returned HTTP %d", resp.StatusCode)
	}

	rows, err := parseTLEFile(resp.Body)
	if err != nil {
		return fmt.Errorf("parse TLEs: %w", err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("no TLEs parsed from Celestrak response")
	}

	now := time.Now().Unix()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM iridium_tle_cache`); err != nil {
		return fmt.Errorf("clear cache: %w", err)
	}

	for _, row := range rows {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO iridium_tle_cache (satellite_name, line1, line2, fetched_at) VALUES (?, ?, ?, ?)`,
			row.SatelliteName, row.Line1, row.Line2, now); err != nil {
			return fmt.Errorf("insert TLE %q: %w", row.SatelliteName, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit TLEs: %w", err)
	}

	log.Info().Int("count", len(rows)).Msg("tle_manager: TLE cache refreshed")
	return nil
}

// ComputePasses returns upcoming satellite passes over the given location.
// hours controls the prediction window; minElevDeg filters out low-elevation passes.
func (m *TLEManager) ComputePasses(ctx context.Context, lat, lon, altM float64, hours int, minElevDeg float64) ([]PassSummary, error) {
	rows, err := m.loadCachedTLEs(ctx)
	if err != nil {
		return nil, fmt.Errorf("load TLEs: %w", err)
	}
	if len(rows) == 0 {
		// Try a refresh before failing
		if err := m.RefreshTLEs(ctx); err != nil {
			return nil, fmt.Errorf("no TLEs cached and refresh failed: %w", err)
		}
		rows, err = m.loadCachedTLEs(ctx)
		if err != nil || len(rows) == 0 {
			return nil, fmt.Errorf("no TLE data available")
		}
	}

	now := time.Now().UTC()
	end := now.Add(time.Duration(hours) * time.Hour)

	var passes []PassSummary
	for _, row := range rows {
		tleStr := row.SatelliteName + "\n" + row.Line1 + "\n" + row.Line2
		tle, err := sgp4.ParseTLE(tleStr)
		if err != nil {
			log.Warn().Str("sat", row.SatelliteName).Err(err).Msg("tle_manager: TLE parse failed, skipping")
			continue
		}

		satPasses, err := tle.GeneratePasses(lat, lon, altM, now, end, 30)
		if err != nil {
			continue
		}

		for _, p := range satPasses {
			if p.MaxElevation < minElevDeg {
				continue
			}
			dur := p.Duration.Minutes()
			ps := PassSummary{
				Satellite:   strings.TrimSpace(row.SatelliteName),
				AOS:         p.AOS,
				LOS:         p.LOS,
				DurationMin: dur,
				PeakElevDeg: p.MaxElevation,
				PeakAzimuth: p.MaxElevationAz,
				AOSAzimuth:  p.AOSAzimuth,
				LOSAzimuth:  p.LOSAzimuth,
				IsActive:    now.After(p.AOS) && now.Before(p.LOS),
			}
			passes = append(passes, ps)
		}
	}

	// Sort by AOS time
	sortPassesByAOS(passes)
	return passes, nil
}

func (m *TLEManager) loadCachedTLEs(ctx context.Context) ([]tleCacheRow, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id, satellite_name, line1, line2, fetched_at FROM iridium_tle_cache ORDER BY satellite_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []tleCacheRow
	for rows.Next() {
		var r tleCacheRow
		if err := rows.Scan(&r.ID, &r.SatelliteName, &r.Line1, &r.Line2, &r.FetchedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// GetLocations returns all locations from the database.
func (m *TLEManager) GetLocations(ctx context.Context) ([]IridiumLocation, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id, name, lat, lon, alt_m, builtin FROM iridium_locations ORDER BY builtin DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var locs []IridiumLocation
	for rows.Next() {
		var l IridiumLocation
		var builtinInt int
		if err := rows.Scan(&l.ID, &l.Name, &l.Lat, &l.Lon, &l.AltM, &builtinInt); err != nil {
			return nil, err
		}
		l.Builtin = builtinInt == 1
		locs = append(locs, l)
	}
	return locs, rows.Err()
}

// AddLocation inserts a new custom location.
func (m *TLEManager) AddLocation(ctx context.Context, name string, lat, lon, altM float64) (int64, error) {
	if name == "" {
		return 0, fmt.Errorf("name is required")
	}
	if lat < -90 || lat > 90 {
		return 0, fmt.Errorf("latitude must be between -90 and 90")
	}
	if lon < -180 || lon > 180 {
		return 0, fmt.Errorf("longitude must be between -180 and 180")
	}
	res, err := m.db.ExecContext(ctx,
		`INSERT INTO iridium_locations (name, lat, lon, alt_m, builtin) VALUES (?, ?, ?, ?, 0)`,
		name, lat, lon, altM)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteLocation removes a custom location (built-in locations cannot be deleted).
func (m *TLEManager) DeleteLocation(ctx context.Context, id int64) error {
	res, err := m.db.ExecContext(ctx,
		`DELETE FROM iridium_locations WHERE id = ? AND builtin = 0`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("location %d not found or is a built-in location", id)
	}
	return nil
}

// CacheInfo returns the number of cached TLEs and when they were last fetched.
func (m *TLEManager) CacheInfo(ctx context.Context) (count int, fetchedAt time.Time, err error) {
	var maxFetchedAt int64
	if err = m.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(fetched_at), 0) FROM iridium_tle_cache`).Scan(&count, &maxFetchedAt); err != nil {
		return
	}
	if maxFetchedAt > 0 {
		fetchedAt = time.Unix(maxFetchedAt, 0)
	}
	return
}

// parseTLEFile reads a 3-line TLE file (name + line1 + line2 per satellite).
func parseTLEFile(r io.Reader) ([]tleCacheRow, error) {
	scanner := bufio.NewScanner(r)
	var rows []tleCacheRow
	var lines []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) == 3 {
			rows = append(rows, tleCacheRow{
				SatelliteName: strings.TrimSpace(lines[0]),
				Line1:         lines[1],
				Line2:         lines[2],
			})
			lines = lines[:0]
		}
	}
	return rows, scanner.Err()
}

// sortPassesByAOS sorts passes in ascending AOS time order (simple insertion sort for small slices).
func sortPassesByAOS(passes []PassSummary) {
	for i := 1; i < len(passes); i++ {
		for j := i; j > 0 && passes[j].AOS.Before(passes[j-1].AOS); j-- {
			passes[j], passes[j-1] = passes[j-1], passes[j]
		}
	}
}
