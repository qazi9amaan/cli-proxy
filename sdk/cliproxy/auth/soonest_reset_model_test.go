package auth

import (
	"strconv"
	"testing"
	"time"
)

// These tests port the window-model tests from cliproxy-rs
// (crates/cpa-server/src/scheduler.rs): they assert how a credential's passive
// quota snapshot is read into the weekly reset, rollover, and exhausted flags
// that drive soonest-reset routing.

const testDay = 24 * time.Hour

// modelBase is a fixed, whole-second UTC instant so epoch round-trips are exact.
var modelBase = time.Unix(1_700_000_000, 0).UTC()

func epochSecs(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

func TestObserveWindows_ReadClaudeAndCodexSignals(t *testing.T) {
	now := modelBase

	// A weekly reset already behind is unknown, not "soonest"; it is a rollover.
	stale := map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Reset": epochSecs(now.Add(-60 * time.Second)),
	}
	w := observeWindows("claude", stale, now, now)
	if w.hasWeekly {
		t.Fatalf("stale weekly reset should be unknown, got %v", w.weeklyReset)
	}
	if w.rolledOver == nil || w.rolledOver.window != windowClaude7d || !w.rolledOver.at.Equal(now.Add(-60*time.Second)) {
		t.Fatalf("expected Claude7d rollover at now-60s, got %+v", w.rolledOver)
	}
	if w.exhausted {
		t.Fatalf("stale reset must not be exhausted")
	}

	// Utilization 1.0 exhausts the 5-hour window until its reset.
	full := map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": "1.0",
		"Anthropic-Ratelimit-Unified-5h-Reset":       epochSecs(now.Add(600 * time.Second)),
	}
	if !observeWindows("claude", full, now, now).exhausted {
		t.Fatalf("utilization 1.0 should exhaust the 5h window")
	}
	if observeWindows("claude", full, now, now.Add(601*time.Second)).exhausted {
		t.Fatalf("5h window should recover after its reset")
	}

	// Codex: the longer window is weekly whichever header carries it;
	// reset-after counts from the observation.
	observed := now.Add(-100 * time.Second)
	codex := map[string]string{
		"X-Codex-Primary-Used-Percent":        "100",
		"X-Codex-Primary-Window-Minutes":      "300",
		"X-Codex-Primary-Reset-After-Seconds": "3600",
		"X-Codex-Secondary-Used-Percent":      "40",
		"X-Codex-Secondary-Window-Minutes":    "10080",
		"X-Codex-Secondary-Reset-At":          epochSecs(now.Add(2 * testDay)),
	}
	w = observeWindows("codex", codex, observed, now)
	if !w.exhausted {
		t.Fatalf("the 5-hour primary is used up")
	}
	if !w.hasWeekly || !w.weeklyReset.Equal(now.Add(2*testDay)) {
		t.Fatalf("weekly reset should be the secondary reset, got %v", w.weeklyReset)
	}
	if observeWindows("codex", codex, observed, observed.Add(3601*time.Second)).exhausted {
		t.Fatalf("primary should recover after its 3600s reset")
	}

	weeklyPrimary := map[string]string{
		"X-Codex-Primary-Used-Percent":   "51",
		"X-Codex-Primary-Window-Minutes": "10080",
		"X-Codex-Primary-Reset-At":       epochSecs(now.Add(3 * testDay)),
	}
	w = observeWindows("codex", weeklyPrimary, now, now)
	if !w.hasWeekly || !w.weeklyReset.Equal(now.Add(3*testDay)) || w.exhausted {
		t.Fatalf("primary as weekly: got weekly=%v exhausted=%v", w.weeklyReset, w.exhausted)
	}

	reached := map[string]string{"X-Codex-Limit-Reached": "True"}
	if !observeWindows("codex", reached, now, now).exhausted {
		t.Fatalf("limit-reached flag should exhaust")
	}

	// Another provider's headers mean nothing here.
	w = observeWindows("gemini", codex, now, now)
	if w.hasWeekly || w.exhausted {
		t.Fatalf("unknown provider should know nothing, got %+v", w)
	}
}

func TestObserveWindows_SurviveUnrepresentableLengths(t *testing.T) {
	now := modelBase
	for _, tc := range []struct {
		used      string
		exhausted bool
	}{{"0", false}, {"100", true}} {
		huge := map[string]string{
			"X-Codex-Primary-Used-Percent":   tc.used,
			"X-Codex-Primary-Window-Minutes": "1e308",
		}
		if got := observeWindows("codex", huge, now, now).exhausted; got != tc.exhausted {
			t.Fatalf("used %s%%: exhausted=%v want %v", tc.used, got, tc.exhausted)
		}
		later := now.Add(5*time.Hour + time.Second)
		if observeWindows("codex", huge, now, later).exhausted {
			t.Fatalf("used %s%%: should recover after the five-hour fallback", tc.used)
		}
	}

	// Long but representable lengths still count.
	long := map[string]string{
		"X-Codex-Primary-Used-Percent":   "100",
		"X-Codex-Primary-Window-Minutes": "1e9",
	}
	if !observeWindows("codex", long, now, now.Add(testDay)).exhausted {
		t.Fatalf("a representable 1e9-minute window should still hold")
	}
}

func TestObserveWindows_CodexLimitReachedExpiresWithWindowReset(t *testing.T) {
	now := modelBase
	flagged := map[string]string{
		"X-Codex-Limit-Reached":          "true",
		"X-Codex-Primary-Used-Percent":   "100",
		"X-Codex-Primary-Window-Minutes": "300",
		"X-Codex-Primary-Reset-At":       epochSecs(now.Add(60 * time.Second)),
	}
	if !observeWindows("codex", flagged, now, now).exhausted {
		t.Fatalf("flagged+used-up should exhaust")
	}
	if observeWindows("codex", flagged, now, now.Add(61*time.Second)).exhausted {
		t.Fatalf("flag should expire with the window reset")
	}

	below := map[string]string{
		"X-Codex-Limit-Reached":        "true",
		"X-Codex-Primary-Used-Percent": "40",
		"X-Codex-Primary-Reset-At":     epochSecs(now.Add(600 * time.Second)),
	}
	if !observeWindows("codex", below, now, now.Add(599*time.Second)).exhausted {
		t.Fatalf("flag holds until the soonest reported reset")
	}
	if observeWindows("codex", below, now, now.Add(601*time.Second)).exhausted {
		t.Fatalf("flag should expire at the reported reset")
	}

	bare := map[string]string{"X-Codex-Limit-Reached": "true"}
	if !observeWindows("codex", bare, now, now.Add(5*time.Hour-time.Second)).exhausted {
		t.Fatalf("bare flag should hold five hours")
	}
	if observeWindows("codex", bare, now, now.Add(5*time.Hour+time.Second)).exhausted {
		t.Fatalf("bare flag should expire after five hours")
	}
}

func TestObserveWindows_CodexParsesUsageResetLengthIndependently(t *testing.T) {
	now := modelBase
	weekly := now.Add(3 * testDay)
	noUsage := map[string]string{
		"X-Codex-Secondary-Window-Minutes": "10080",
		"X-Codex-Secondary-Reset-At":       epochSecs(weekly),
	}
	w := observeWindows("codex", noUsage, now, now)
	if !w.hasWeekly || !w.weeklyReset.Equal(weekly) || w.exhausted {
		t.Fatalf("no-usage window should still report its reset, got %+v", w)
	}

	resetOnly := map[string]string{"X-Codex-Secondary-Reset-After-Seconds": "7200"}
	w = observeWindows("codex", resetOnly, now, now)
	if !w.hasWeekly || !w.weeklyReset.Equal(now.Add(7200*time.Second)) {
		t.Fatalf("reset-only secondary should be weekly, got %v", w.weeklyReset)
	}
}

func TestObserveWindows_CodexPrimaryLongerIsWeekly(t *testing.T) {
	now := modelBase
	weekly := now.Add(3 * testDay)
	both := map[string]string{
		"X-Codex-Primary-Used-Percent":          "51",
		"X-Codex-Primary-Window-Minutes":        "10080",
		"X-Codex-Primary-Reset-At":              epochSecs(weekly),
		"X-Codex-Secondary-Used-Percent":        "100",
		"X-Codex-Secondary-Window-Minutes":      "300",
		"X-Codex-Secondary-Reset-After-Seconds": "3600",
	}
	w := observeWindows("codex", both, now, now)
	if !w.hasWeekly || !w.weeklyReset.Equal(weekly) || !w.exhausted {
		t.Fatalf("primary longer should be weekly and exhausted, got %+v", w)
	}
	w = observeWindows("codex", both, now, now.Add(3601*time.Second))
	if !w.hasWeekly || !w.weeklyReset.Equal(weekly) || w.exhausted {
		t.Fatalf("secondary should recover while primary stays weekly, got %+v", w)
	}
}

// Devin has no analogue in cliproxy-rs; this guards the preserved behaviour that
// a Devin credential orders by its weekly quota reset and exhausts on a used-up
// daily window.
func TestObserveWindows_DevinWeeklyResetAndDailyExhaustion(t *testing.T) {
	observed := modelBase
	weekly := observed.Add(2 * testDay)
	daily := observed.Add(6 * time.Hour)
	signals := map[string]string{
		"weekly_quota_reset_at":          weekly.Format(time.RFC3339),
		"daily_quota_reset_at":           daily.Format(time.RFC3339),
		"weekly_quota_remaining_percent": "80%",
		"daily_quota_remaining_percent":  "0%",
	}
	w := observeWindows("devin", signals, observed, observed)
	if !w.hasWeekly || !w.weeklyReset.Equal(weekly) {
		t.Fatalf("devin weekly reset should drive ordering, got %v", w.weeklyReset)
	}
	if !w.exhausted {
		t.Fatalf("a used-up daily window should mark devin exhausted")
	}
	// After the daily reset passes, the credential is usable again.
	if observeWindows("devin", signals, observed, daily.Add(time.Second)).exhausted {
		t.Fatalf("devin should recover after the daily reset")
	}
}

func TestOrderKey_Ordering(t *testing.T) {
	now := modelBase
	soon := orderKey{class: 1, hasWeekly: true, weekly: now.Add(time.Hour)}
	late := orderKey{class: 1, hasWeekly: true, weekly: now.Add(2 * time.Hour)}
	probeFirst := orderKey{class: 0}
	probedUnknown := orderKey{class: 2}
	exhausted := orderKey{exhausted: true, class: 1, hasWeekly: true, weekly: now}

	// Unprobed-unknown (probe) sorts before any known reset.
	if !probeFirst.less(soon) {
		t.Fatalf("probe class should sort before a known reset")
	}
	// Known reset sorts before a probed-but-unknown account.
	if !soon.less(probedUnknown) {
		t.Fatalf("known reset should sort before probed-unknown")
	}
	// Earlier known reset wins.
	if !soon.less(late) {
		t.Fatalf("earlier weekly reset should sort first")
	}
	// Exhausted always sorts last.
	if !probedUnknown.less(exhausted) || !soon.less(exhausted) {
		t.Fatalf("exhausted should sort after usable accounts")
	}
	if !soon.equal(orderKey{class: 1, hasWeekly: true, weekly: now.Add(time.Hour)}) {
		t.Fatalf("equal should match identical keys")
	}
}

func TestProbedState(t *testing.T) {
	at := modelBase
	// No record: never probed.
	if probedState(nil, false, nil) {
		t.Fatalf("no record means not probed")
	}
	// Record present, no current rollover: probed.
	if !probedState(map[windowID]time.Time{}, true, nil) {
		t.Fatalf("a spent probe with no rollover is probed")
	}
	// Rollover of a window never marked: re-probe.
	roll := &rollover{window: windowClaude7d, at: at.Add(time.Hour), gap: time.Hour}
	if probedState(map[windowID]time.Time{windowClaude5h: at}, true, roll) {
		t.Fatalf("a rollover of an unmarked window should re-probe")
	}
	// Rollover within gap of the marker: still probed.
	withinGap := map[windowID]time.Time{windowClaude7d: at}
	if !probedState(withinGap, true, &rollover{window: windowClaude7d, at: at.Add(30 * time.Minute), gap: time.Hour}) {
		t.Fatalf("a rollover within the gap is the same probe")
	}
	// Rollover beyond gap: re-probe.
	if probedState(withinGap, true, &rollover{window: windowClaude7d, at: at.Add(2 * time.Hour), gap: time.Hour}) {
		t.Fatalf("a rollover beyond the gap should re-probe")
	}
}
