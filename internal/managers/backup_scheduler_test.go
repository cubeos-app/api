package managers

import (
	"testing"
	"time"
)

func TestParseCron_Valid(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"daily 2am", "0 2 * * *"},
		{"every 6h", "0 */6 * * *"},
		{"sunday 2am", "0 2 * * 0"},
		{"every 5 min", "*/5 * * * *"},
		{"weekdays 9am", "0 9 * * 1-5"},
		{"first of month", "0 0 1 * *"},
		{"every minute", "* * * * *"},
		{"complex", "0,30 9-17 * * 1-5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCron(tt.expr)
			if err != nil {
				t.Errorf("ParseCron(%q) returned error: %v", tt.expr, err)
			}
		})
	}
}

func TestParseCron_Invalid(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"too few fields", "0 2 * *"},
		{"too many fields", "0 2 * * * *"},
		{"bad minute", "60 * * * *"},
		{"bad hour", "0 25 * * *"},
		{"bad dow", "0 0 * * 7"},
		{"bad range", "0 0 * * 6-2"},
		{"bad step", "*/0 * * * *"},
		{"bad value", "abc * * * *"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCron(tt.expr)
			if err == nil {
				t.Errorf("ParseCron(%q) should have returned error", tt.expr)
			}
		})
	}
}

func TestCronSchedule_Matches(t *testing.T) {
	// "0 2 * * *" = daily at 2:00 AM
	cron, err := ParseCron("0 2 * * *")
	if err != nil {
		t.Fatal(err)
	}

	// Should match 2:00 AM on any day
	match := time.Date(2025, 6, 15, 2, 0, 0, 0, time.UTC)
	if !cron.Matches(match) {
		t.Error("should match 2:00 AM")
	}

	// Should not match 3:00 AM
	noMatch := time.Date(2025, 6, 15, 3, 0, 0, 0, time.UTC)
	if cron.Matches(noMatch) {
		t.Error("should not match 3:00 AM")
	}

	// Should not match 2:30 AM
	noMatch2 := time.Date(2025, 6, 15, 2, 30, 0, 0, time.UTC)
	if cron.Matches(noMatch2) {
		t.Error("should not match 2:30 AM")
	}
}

func TestCronSchedule_Matches_Weekday(t *testing.T) {
	// "0 9 * * 1-5" = weekdays at 9:00 AM
	cron, err := ParseCron("0 9 * * 1-5")
	if err != nil {
		t.Fatal(err)
	}

	// Monday at 9:00 AM (June 16, 2025 is a Monday)
	monday := time.Date(2025, 6, 16, 9, 0, 0, 0, time.UTC)
	if !cron.Matches(monday) {
		t.Errorf("should match Monday 9am (weekday=%d)", monday.Weekday())
	}

	// Sunday at 9:00 AM (June 15, 2025 is a Sunday)
	sunday := time.Date(2025, 6, 15, 9, 0, 0, 0, time.UTC)
	if cron.Matches(sunday) {
		t.Errorf("should not match Sunday 9am (weekday=%d)", sunday.Weekday())
	}
}

func TestCronSchedule_Matches_Step(t *testing.T) {
	// "*/5 * * * *" = every 5 minutes
	cron, err := ParseCron("*/5 * * * *")
	if err != nil {
		t.Fatal(err)
	}

	for min := 0; min < 60; min++ {
		tm := time.Date(2025, 6, 15, 10, min, 0, 0, time.UTC)
		expected := min%5 == 0
		if cron.Matches(tm) != expected {
			t.Errorf("minute %d: expected %v, got %v", min, expected, !expected)
		}
	}
}

func TestCronSchedule_Next(t *testing.T) {
	// "0 2 * * *" = daily at 2:00 AM
	cron, err := ParseCron("0 2 * * *")
	if err != nil {
		t.Fatal(err)
	}

	// Starting from 10:00 PM, next should be 2:00 AM next day
	start := time.Date(2025, 6, 15, 22, 0, 0, 0, time.UTC)
	next := cron.Next(start)
	expected := time.Date(2025, 6, 16, 2, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("Next(%v) = %v, want %v", start, next, expected)
	}

	// Starting from 1:00 AM, next should be 2:00 AM same day
	start2 := time.Date(2025, 6, 15, 1, 0, 0, 0, time.UTC)
	next2 := cron.Next(start2)
	expected2 := time.Date(2025, 6, 15, 2, 0, 0, 0, time.UTC)
	if !next2.Equal(expected2) {
		t.Errorf("Next(%v) = %v, want %v", start2, next2, expected2)
	}
}

func TestCronSchedule_Next_EveryMinute(t *testing.T) {
	cron, err := ParseCron("* * * * *")
	if err != nil {
		t.Fatal(err)
	}

	start := time.Date(2025, 6, 15, 10, 30, 45, 0, time.UTC)
	next := cron.Next(start)
	// Should be 10:31 (next minute after truncation + 1 min)
	expected := time.Date(2025, 6, 15, 10, 31, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("Next(%v) = %v, want %v", start, next, expected)
	}
}

func TestCronSchedule_CommaList(t *testing.T) {
	// "0,30 * * * *" = at minute 0 and 30 of every hour
	cron, err := ParseCron("0,30 * * * *")
	if err != nil {
		t.Fatal(err)
	}

	at0 := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	at30 := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	at15 := time.Date(2025, 6, 15, 10, 15, 0, 0, time.UTC)

	if !cron.Matches(at0) {
		t.Error("should match minute 0")
	}
	if !cron.Matches(at30) {
		t.Error("should match minute 30")
	}
	if cron.Matches(at15) {
		t.Error("should not match minute 15")
	}
}
