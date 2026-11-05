package auth

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// This file ports the usage-window model that drives the soonest-reset routing
// strategy from cliproxy-rs (crates/cpa-server/src/scheduler.rs). A credential's
// passive quota snapshot (Claude anthropic-ratelimit-unified-* headers, Codex
// x-codex-* headers, Devin quota snapshots) is read into a Windows value that
// names the long (weekly) window's reset, whether that window has rolled over
// since it was last learned, and whether any window is currently used up. The
// selector then spends the account whose weekly window resets soonest first.

// fallbackWindow is how long a used-up window without a usable reset or length
// is assumed to hold, and the half-length used for rollover gaps when the
// length is unknown.
const fallbackWindow = 5 * time.Hour

// windowID identifies which usage window a rollover or probe marker belongs to,
// so a rollover of one window is never compared with a probe made for another.
type windowID int

const (
	windowClaude7d windowID = iota
	windowClaude5h
	windowCodexPrimary
	windowCodexSecondary
	windowDevinWeekly
	windowDevinDaily
)

// rollover is a long window that rolled over: its stated reset passed, so what
// was learned about it is stale and the credential may be probed again.
type rollover struct {
	window windowID
	// at is the stated reset that passed.
	at time.Time
	// gap is how far apart two rollovers of this window must be to count as
	// different ones: half its length (five hours when unknown), which absorbs
	// the rounding of relative resets around a boundary.
	gap time.Duration
}

// windows is what soonest-reset knows about a credential's usage windows from
// its latest passive quota observation. The zero value is "nothing known".
type windows struct {
	// weeklyReset is when the long (weekly) window resets, while that is still
	// ahead; hasWeekly reports whether it is known.
	weeklyReset time.Time
	hasWeekly   bool
	// rolledOver is set when the long window's stated reset has passed.
	rolledOver *rollover
	// exhausted reports that a window is used up and has not reset yet.
	exhausted bool
}

// orderKey is the soonest-reset sort key: usable accounts before used-up ones,
// then by class (unprobed-unknown first so it is probed, then known resets, then
// accounts whose probe taught nothing), then the earliest weekly reset.
type orderKey struct {
	exhausted bool
	class     uint8
	hasWeekly bool
	weekly    time.Time
}

// less reports whether a sorts before b, mirroring the Rust tuple ordering
// (false < true; 0 < 1 < 2; a missing weekly reset before a known one, then the
// earliest known reset first).
func (a orderKey) less(b orderKey) bool {
	if a.exhausted != b.exhausted {
		return !a.exhausted
	}
	if a.class != b.class {
		return a.class < b.class
	}
	if a.hasWeekly != b.hasWeekly {
		return !a.hasWeekly
	}
	if !a.hasWeekly {
		return false
	}
	return a.weekly.Before(b.weekly)
}

func (a orderKey) equal(b orderKey) bool {
	return a.exhausted == b.exhausted && a.class == b.class && a.hasWeekly == b.hasWeekly && a.weekly.Equal(b.weekly)
}

// order ranks a credential's windows. probed reports whether the account was
// already probed for what it reports now.
func (w windows) order(probed bool) orderKey {
	var class uint8
	switch {
	case w.hasWeekly:
		class = 1
	case !probed:
		class = 0
	default:
		class = 2
	}
	return orderKey{exhausted: w.exhausted, class: class, hasWeekly: w.hasWeekly, weekly: w.weeklyReset}
}

// probedState reports whether a credential was already probed for what it
// reports now. A probe holds until its long window rolls over after it: a reset
// of that same window that passed and is more than the window's gap later than
// the rollover last probed for it.
func probedState(record map[windowID]time.Time, recordExists bool, rolledOver *rollover) bool {
	if !recordExists {
		return false
	}
	if rolledOver == nil {
		return true
	}
	at, ok := record[rolledOver.window]
	if !ok {
		return false
	}
	return !rolledOver.at.After(at.Add(rolledOver.gap))
}

// window is one usage window read from quota signals; each part may be missing.
type window struct {
	id             windowID
	usedUp         bool
	reset          time.Time
	hasReset       bool
	statedReset    time.Time
	hasStatedReset bool
	lengthSecs     float64
	hasLength      bool
}

// exhaustedUntil returns until when a used-up window holds: its reset, else its
// length (or five hours) after the observation. The bool is false when the
// window is not used up.
func (w *window) exhaustedUntil(observedAt time.Time) (time.Time, bool) {
	if !w.usedUp {
		return time.Time{}, false
	}
	if w.hasReset {
		return w.reset, true
	}
	if w.hasLength {
		if t, ok := addSeconds(observedAt, w.lengthSecs); ok {
			return t, true
		}
	}
	return observedAt.Add(fallbackWindow), true
}

// observeWindows reads a credential's signal snapshot, observed at observedAt
// and read at now, for provider (claude, codex, devin; anything else knows
// nothing).
func observeWindows(provider string, signals map[string]string, observedAt, now time.Time) windows {
	if len(signals) == 0 {
		return windows{}
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	var long, short *window
	switch provider {
	case "claude":
		long = claudeWindow(signals, windowClaude7d, "7d", 7*24*60, observedAt)
		short = claudeWindow(signals, windowClaude5h, "5h", 300, observedAt)
	case "codex":
		long, short = codexWindows(signals, observedAt)
	case "devin":
		long, short = devinWindows(signals, observedAt)
	default:
		return windows{}
	}

	wins := [2]*window{long, short}
	var until time.Time
	hasUntil := false
	for _, w := range wins {
		if w == nil {
			continue
		}
		if t, ok := w.exhaustedUntil(observedAt); ok && (!hasUntil || t.After(until)) {
			until, hasUntil = t, true
		}
	}

	// X-Codex-Limit-Reached lasts as long as the used-up windows do; when none
	// is used up, until the soonest reset any window reports; with no reset at
	// all, five hours from the observation.
	flagUntil, hasFlag := time.Time{}, false
	if provider == "codex" {
		if v, ok := signalGet(signals, "x-codex-limit-reached"); ok && strings.EqualFold(v, "true") {
			switch {
			case hasUntil:
				flagUntil, hasFlag = until, true
			default:
				var soonest time.Time
				hasSoon := false
				for _, w := range wins {
					if w == nil || !w.hasReset {
						continue
					}
					if !hasSoon || w.reset.Before(soonest) {
						soonest, hasSoon = w.reset, true
					}
				}
				if hasSoon {
					flagUntil, hasFlag = soonest, true
				} else {
					flagUntil, hasFlag = observedAt.Add(fallbackWindow), true
				}
			}
		}
	}

	var weeklyReset time.Time
	hasWeekly := false
	if long != nil && long.hasReset && long.reset.After(now) {
		weeklyReset, hasWeekly = long.reset, true
	}

	var rolled *rollover
	if long != nil && long.hasStatedReset && !long.statedReset.After(now) {
		gap := fallbackWindow / 2
		if long.hasLength {
			gap = secondsToDuration(long.lengthSecs / 2)
		}
		rolled = &rollover{window: long.id, at: long.statedReset, gap: gap}
	}

	maxUntil, hasMax := until, hasUntil
	if hasFlag && (!hasMax || flagUntil.After(maxUntil)) {
		maxUntil, hasMax = flagUntil, true
	}
	exhausted := hasMax && maxUntil.After(now)

	return windows{weeklyReset: weeklyReset, hasWeekly: hasWeekly, rolledOver: rolled, exhausted: exhausted}
}

func claudeWindow(signals map[string]string, id windowID, label string, minutes float64, observedAt time.Time) *window {
	prefix := "anthropic-ratelimit-unified-" + label + "-"
	status, _ := signalGet(signals, prefix+"status")
	util, hasUtil := signalNumber(signals, prefix+"utilization")
	usedUp := strings.EqualFold(status, "rejected") || (hasUtil && util >= 1.0)
	reset, hasReset := time.Time{}, false
	if raw, ok := signalGet(signals, prefix+"reset"); ok {
		reset, hasReset = resetTime(raw)
	}
	lengthSecs, hasLength := windowLengthSecs(minutes, observedAt)
	return &window{
		id:             id,
		usedUp:         usedUp,
		reset:          reset,
		hasReset:       hasReset,
		statedReset:    reset,
		hasStatedReset: hasReset,
		lengthSecs:     lengthSecs,
		hasLength:      hasLength,
	}
}

func codexWindows(signals map[string]string, observedAt time.Time) (*window, *window) {
	primary := codexWindow(signals, windowCodexPrimary, "primary", observedAt)
	secondary := codexWindow(signals, windowCodexSecondary, "secondary", observedAt)
	const day = 24 * 3600.0
	switch {
	case primary != nil && secondary != nil:
		// The longer window is the weekly one, whichever header carries it;
		// without lengths, secondary is weekly.
		pLen := 0.0
		if primary.hasLength {
			pLen = primary.lengthSecs
		}
		sLen := math.Inf(1)
		if secondary.hasLength {
			sLen = secondary.lengthSecs
		}
		if pLen > sLen {
			return primary, secondary
		}
		return secondary, primary
	case primary != nil:
		if primary.hasLength && primary.lengthSecs >= day {
			return primary, nil
		}
		return nil, primary
	case secondary != nil:
		if !secondary.hasLength || secondary.lengthSecs >= day {
			return secondary, nil
		}
		return nil, secondary
	default:
		return nil, nil
	}
}

func codexWindow(signals map[string]string, id windowID, label string, observedAt time.Time) *window {
	prefix := "x-codex-" + label + "-"
	used, hasUsed := signalNumber(signals, prefix+"used-percent")

	absReset, hasAbs := time.Time{}, false
	if raw, ok := signalGet(signals, prefix+"reset-at"); ok {
		absReset, hasAbs = resetTime(raw)
	}
	after, hasAfter := signalNumber(signals, prefix+"reset-after-seconds")
	relReset, hasRel := time.Time{}, false
	if hasAfter && after >= 0 {
		if t, ok := addSeconds(observedAt, after); ok {
			relReset, hasRel = t, true
		}
	}
	reset, hasReset := absReset, hasAbs
	if !hasReset && hasRel {
		reset, hasReset = relReset, true
	}
	// A zero delay still ends an exhausted window now, but its time is just the
	// observation's, so it names no rollover.
	statedReset, hasStated := absReset, hasAbs
	if !hasStated && hasRel && after > 0 {
		statedReset, hasStated = relReset, true
	}
	lengthSecs, hasLength := 0.0, false
	if m, ok := signalNumber(signals, prefix+"window-minutes"); ok {
		lengthSecs, hasLength = windowLengthSecs(m, observedAt)
	}
	// A window exists when any of usage, reset or length was reported.
	if !hasUsed && !hasReset && !hasLength {
		return nil
	}
	return &window{
		id:             id,
		usedUp:         hasUsed && used >= 100,
		reset:          reset,
		hasReset:       hasReset,
		statedReset:    statedReset,
		hasStatedReset: hasStated,
		lengthSecs:     lengthSecs,
		hasLength:      hasLength,
	}
}

// devinWindows reads the Devin quota snapshot (underscore keys written directly
// by the Devin refresh, not from response headers). Devin has no analogue in
// cliproxy-rs; it is kept here so Devin credentials keep ordering by their
// weekly reset under soonest-reset. The weekly window is the long one.
func devinWindows(signals map[string]string, observedAt time.Time) (*window, *window) {
	weekly := devinWindow(signals, windowDevinWeekly, "weekly", 7*24*60, observedAt)
	daily := devinWindow(signals, windowDevinDaily, "daily", 24*60, observedAt)
	return weekly, daily
}

func devinWindow(signals map[string]string, id windowID, label string, minutes float64, observedAt time.Time) *window {
	reset, hasReset := time.Time{}, false
	if raw, ok := signalGet(signals, label+"_quota_reset_at"); ok {
		reset, hasReset = resetTime(raw)
	}
	remaining, hasRemaining := devinRemainingPercentSignal(signals, label+"_quota_remaining_percent")
	lengthSecs, hasLength := windowLengthSecs(minutes, observedAt)
	if !hasReset && !hasRemaining {
		return nil
	}
	return &window{
		id:             id,
		usedUp:         hasRemaining && remaining <= 0,
		reset:          reset,
		hasReset:       hasReset,
		statedReset:    reset,
		hasStatedReset: hasReset,
		lengthSecs:     lengthSecs,
		hasLength:      hasLength,
	}
}

// devinRemainingPercentSignal parses a Devin "80%" remaining value.
func devinRemainingPercentSignal(signals map[string]string, name string) (float64, bool) {
	raw, ok := signalGet(signals, name)
	if !ok {
		return 0, false
	}
	raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "%"))
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, false
	}
	return n, true
}

// signalGet returns a signal value by case-insensitive name, trimmed.
func signalGet(signals map[string]string, name string) (string, bool) {
	for k, v := range signals {
		if strings.EqualFold(k, name) {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// signalNumber returns a signal value parsed as a finite float.
func signalNumber(signals map[string]string, name string) (float64, bool) {
	v, ok := signalGet(signals, name)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, false
	}
	return n, true
}

// resetTime parses a reset signal: epoch seconds (fractions allowed), RFC 3339,
// or an HTTP-date.
func resetTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if sec, err := strconv.ParseFloat(raw, 64); err == nil {
		if math.IsInf(sec, 0) || math.IsNaN(sec) || sec <= 0 {
			return time.Time{}, false
		}
		whole := math.Floor(sec)
		nsec := int64((sec - whole) * float64(time.Second))
		return time.Unix(int64(whole), nsec).UTC(), true
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed, true
	}
	if parsed, err := http.ParseTime(raw); err == nil {
		return parsed, true
	}
	return time.Time{}, false
}

// windowLengthSecs returns a window length in seconds when the reported minutes
// are positive and representable as a deadline from observedAt.
func windowLengthSecs(minutes float64, observedAt time.Time) (float64, bool) {
	if math.IsNaN(minutes) || math.IsInf(minutes, 0) || minutes <= 0 {
		return 0, false
	}
	secs := minutes * 60.0
	if math.IsInf(secs, 0) || math.IsNaN(secs) || secs <= 0 {
		return 0, false
	}
	if _, ok := addSeconds(observedAt, secs); !ok {
		return 0, false
	}
	return secs, true
}

// addSeconds adds a (possibly large) number of seconds to t, reporting whether
// the result is representable without overflow.
func addSeconds(t time.Time, secs float64) (time.Time, bool) {
	if math.IsNaN(secs) || math.IsInf(secs, 0) {
		return time.Time{}, false
	}
	whole := math.Floor(secs)
	const safeBound = 1 << 62
	if whole < -float64(safeBound) || whole > float64(safeBound) {
		return time.Time{}, false
	}
	sec := int64(whole)
	base := t.Unix()
	if (sec > 0 && base > math.MaxInt64-sec) || (sec < 0 && base < math.MinInt64-sec) {
		return time.Time{}, false
	}
	nsec := int64((secs - whole) * float64(time.Second))
	return time.Unix(base+sec, int64(t.Nanosecond())+nsec).UTC(), true
}

// secondsToDuration converts seconds to a Duration, clamping values that would
// overflow (used only for rollover gaps, where adversarial window lengths need
// not be exact).
func secondsToDuration(secs float64) time.Duration {
	if math.IsNaN(secs) || secs <= 0 {
		return 0
	}
	if secs >= float64(math.MaxInt64)/float64(time.Second) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(secs * float64(time.Second))
}
