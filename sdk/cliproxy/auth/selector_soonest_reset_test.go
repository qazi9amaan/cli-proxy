package auth

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// These tests port the soonest-reset selector tests from cliproxy-rs
// (crates/cpa-server/src/scheduler.rs). They drive the selector through the
// window model: a credential whose weekly window resets soonest is spent first,
// an unknown account is probed exactly once (and re-probed on a rollover),
// used-up accounts fall behind, and equal ranks take turns.

// claudeWindowsAt builds a Claude observation observed at observed and read at
// now: the 7-day reset weeklySecs later and the 5-hour window's status/reset.
func claudeWindowsAt(observed, now time.Time, weeklySecs int64, fiveHour string, fiveHourReset time.Time) windows {
	signals := map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.40",
		"Anthropic-Ratelimit-Unified-7d-Reset":       epochSecs(observed.Add(time.Duration(weeklySecs) * time.Second)),
		"Anthropic-Ratelimit-Unified-5h-Status":      fiveHour,
		"Anthropic-Ratelimit-Unified-5h-Reset":       epochSecs(fiveHourReset),
	}
	return observeWindows("claude", signals, observed, now)
}

func claudeWindowsNow(now time.Time, weeklySecs int64, fiveHour string, fiveHourReset time.Time) windows {
	return claudeWindowsAt(now, now, weeklySecs, fiveHour, fiveHourReset)
}

// soonestWith returns a selector whose clock is fixed at now and whose window
// model is the injected ranks closure (mirroring the Rust Ranks closure).
func soonestWith(now time.Time, ranks func(*Auth) windows) *SoonestResetSelector {
	return &SoonestResetSelector{
		nowFunc:  func() time.Time { return now },
		rankFunc: func(a *Auth, _ string, _ time.Time) windows { return ranks(a) },
	}
}

func mustPick(t *testing.T, s Selector, auths ...*Auth) string {
	t.Helper()
	got, err := s.Pick(context.Background(), "claude", "m", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil {
		t.Fatalf("Pick() returned nil")
	}
	return got.ID
}

func TestSoonestReset_SpendsEarliestWeeklyWindowFirst(t *testing.T) {
	wall := modelBase
	inAnHour := wall.Add(time.Hour)
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}

	ranksAt := func(bFiveHour string, now time.Time) func(*Auth) windows {
		wa := claudeWindowsAt(wall, now, 4*int64(testDay/time.Second), "allowed", inAnHour)
		wb := claudeWindowsAt(wall, now, int64(testDay/time.Second), bFiveHour, inAnHour)
		return func(x *Auth) windows {
			if x.ID == "a" {
				return wa
			}
			return wb
		}
	}

	// The sooner weekly reset (b, one day) is used up first.
	s := soonestWith(wall, ranksAt("allowed", wall))
	for i := 0; i < 3; i++ {
		if got := mustPick(t, s, a, b); got != "b" {
			t.Fatalf("pick #%d = %q, want b", i, got)
		}
	}

	// b cools on a 429: the next soonest (a) takes over.
	b.Quota.Exceeded = true
	b.Quota.NextRecoverAt = wall.Add(time.Hour)
	if got := mustPick(t, s, a, b); got != "a" {
		t.Fatalf("after b cooldown = %q, want a", got)
	}
	b.Quota.Exceeded = false
	b.Quota.NextRecoverAt = time.Time{}

	// Without the cooldown, b's used-up 5-hour window also hands over to a...
	s = soonestWith(wall, ranksAt("rejected", wall))
	for i := 0; i < 2; i++ {
		if got := mustPick(t, s, a, b); got != "a" {
			t.Fatalf("exhausted-b pick #%d = %q, want a", i, got)
		}
	}
	// ...until that window resets, an hour later.
	s.rankFunc = func(x *Auth, _ string, _ time.Time) windows {
		r := ranksAt("rejected", inAnHour.Add(time.Second))
		return r(x)
	}
	if got := mustPick(t, s, a, b); got != "b" {
		t.Fatalf("after 5h reset = %q, want b", got)
	}
}

func TestSoonestReset_ProbesUnknownAccountsOnceThenRanksThem(t *testing.T) {
	wall := modelBase
	inAnHour := wall.Add(time.Hour)
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}
	c := &Auth{ID: "c", Provider: "claude"}
	d := &Auth{ID: "d", Provider: "claude"}

	known := func(x *Auth) windows {
		switch x.ID {
		case "c":
			return claudeWindowsNow(wall, int64(testDay/time.Second), "rejected", inAnHour)
		case "d":
			return claudeWindowsNow(wall, 3*int64(testDay/time.Second), "allowed", inAnHour)
		default:
			return windows{}
		}
	}
	s := soonestWith(wall, known)

	// One probe each for the unknown accounts, then the known reset.
	var order []string
	for i := 0; i < 4; i++ {
		order = append(order, mustPick(t, s, a, b, c, d))
	}
	if got := order; got[0] != "a" || got[1] != "b" || got[2] != "d" || got[3] != "d" {
		t.Fatalf("probe order = %v, want [a b d d]", got)
	}

	// a's probe answered with a reset in 12 hours: it now ranks by it, ahead of
	// d; b's answer reported nothing, so it stays behind the known resets.
	learned := func(x *Auth) windows {
		if x.ID == "a" {
			return claudeWindowsNow(wall.Add(time.Second), 12*3600, "allowed", inAnHour)
		}
		return known(x)
	}
	s.rankFunc = func(x *Auth, _ string, _ time.Time) windows { return learned(x) }

	if got := mustPick(t, s, a, b, c, d); got != "a" {
		t.Fatalf("learned a = %q, want a", got)
	}
	if got := mustPick(t, s, b, c, d); got != "d" {
		t.Fatalf("after a = %q, want d", got)
	}
	if got := mustPick(t, s, b, c); got != "b" {
		t.Fatalf("probed-unknown before used-up = %q, want b", got)
	}
	if got := mustPick(t, s, c); got != "c" {
		t.Fatalf("used-up is the last resort = %q, want c", got)
	}
}

func TestSoonestReset_RotatesEqualRanks(t *testing.T) {
	wall := modelBase
	inAnHour := wall.Add(time.Hour)
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}
	same := claudeWindowsNow(wall, 2*int64(testDay/time.Second), "allowed", inAnHour)
	s := soonestWith(wall, func(*Auth) windows { return same })

	var turns []string
	for i := 0; i < 4; i++ {
		turns = append(turns, mustPick(t, s, a, b))
	}
	if turns[0] != "a" || turns[1] != "b" || turns[2] != "a" || turns[3] != "b" {
		t.Fatalf("equal ranks = %v, want [a b a b]", turns)
	}
}

func TestSoonestReset_AnswersWithoutAResetDoNotReArmTheProbe(t *testing.T) {
	wall := modelBase
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}
	bKnown := claudeWindowsNow(wall, 2*int64(testDay/time.Second), "allowed", wall.Add(time.Hour))

	var aWin windows
	s := soonestWith(wall, func(x *Auth) windows {
		if x.ID == "a" {
			return aWin
		}
		return bKnown
	})

	var picks []string
	for i := 0; i < 5; i++ {
		if i == 0 {
			aWin = windows{}
		} else {
			seen := wall.Add(time.Duration(i) * time.Second)
			aWin = observeWindows("claude", map[string]string{
				"Anthropic-Ratelimit-Unified-5h-Status": "allowed",
			}, seen, seen)
		}
		picks = append(picks, mustPick(t, s, a, b))
	}
	if picks[0] != "a" || picks[1] != "b" || picks[2] != "b" || picks[3] != "b" || picks[4] != "b" {
		t.Fatalf("picks = %v, want [a b b b b]", picks)
	}
}

func TestSoonestReset_AProbeThatFailsBeforeHeadersIsSpent(t *testing.T) {
	wall := modelBase
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}
	bKnown := claudeWindowsNow(wall, 2*int64(testDay/time.Second), "allowed", wall.Add(time.Hour))
	s := soonestWith(wall, func(x *Auth) windows {
		if x.ID == "a" {
			return windows{}
		}
		return bKnown
	})

	if got := mustPick(t, s, a, b); got != "a" {
		t.Fatalf("the probe = %q, want a", got)
	}
	if got := mustPick(t, s, a, b); got != "b" {
		t.Fatalf("spent probe = %q, want b", got)
	}
	if got := mustPick(t, s, a, b); got != "b" {
		t.Fatalf("spent probe = %q, want b", got)
	}
}

func TestSoonestReset_ReArmsOnlyOnARollover(t *testing.T) {
	wall := modelBase
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}
	bKnown := claudeWindowsNow(wall, 2*int64(testDay/time.Second), "allowed", wall.Add(time.Hour))
	aReset := wall.Add(60 * time.Second)

	aRolled := func(seen time.Time) windows {
		return observeWindows("claude", map[string]string{
			"Anthropic-Ratelimit-Unified-7d-Reset": epochSecs(aReset),
		}, seen, wall.Add(61*time.Second))
	}

	var aWin windows
	s := soonestWith(wall, func(x *Auth) windows {
		if x.ID == "a" {
			return aWin
		}
		return bKnown
	})

	var picks []string
	for i := 0; i < 3; i++ {
		aWin = aRolled(wall.Add(time.Duration(i) * time.Second))
		picks = append(picks, mustPick(t, s, a, b))
	}
	if picks[0] != "a" || picks[1] != "b" || picks[2] != "b" {
		t.Fatalf("one probe per rollover = %v, want [a b b]", picks)
	}

	// The next weekly rollover re-arms it once more.
	next := aReset.Add(7 * testDay)
	aWin = observeWindows("claude", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Reset": epochSecs(next),
	}, wall, next.Add(time.Second))
	if got := mustPick(t, s, a, b); got != "a" {
		t.Fatalf("next rollover = %q, want a", got)
	}
	if got := mustPick(t, s, a, b); got != "b" {
		t.Fatalf("after re-probe = %q, want b", got)
	}
}

func TestSoonestReset_ZeroRelativeResetsDoNotReArmTheProbe(t *testing.T) {
	wall := modelBase
	a := &Auth{ID: "a", Provider: "codex"}
	b := &Auth{ID: "b", Provider: "claude"}
	bKnown := claudeWindowsNow(wall, 2*int64(testDay/time.Second), "allowed", wall.Add(time.Hour))
	zero := map[string]string{
		"X-Codex-Secondary-Used-Percent":        "0",
		"X-Codex-Secondary-Window-Minutes":      "10080",
		"X-Codex-Secondary-Reset-After-Seconds": "0",
	}

	var aWin windows
	s := soonestWith(wall, func(x *Auth) windows {
		if x.ID == "a" {
			return aWin
		}
		return bKnown
	})

	var picks []string
	for i := 0; i < 4; i++ {
		if i == 0 {
			aWin = windows{}
		} else {
			seen := wall.Add(time.Duration(2*i) * time.Second)
			aWin = observeWindows("codex", zero, seen, seen.Add(time.Second))
		}
		picks = append(picks, mustPick(t, s, a, b))
	}
	if picks[0] != "a" || picks[1] != "b" || picks[2] != "b" || picks[3] != "b" {
		t.Fatalf("zero relative resets = %v, want [a b b b]", picks)
	}

	// The zero delay still ends a used-up window now (not exhausted after it).
	usedUp := map[string]string{
		"X-Codex-Primary-Used-Percent":        "100",
		"X-Codex-Primary-Reset-After-Seconds": "0",
	}
	if observeWindows("codex", usedUp, wall, wall).exhausted {
		t.Fatalf("a zero-delay reset should end the window now")
	}
}

func TestSoonestReset_RolloversWithinHalfAWindowAreOneRollover(t *testing.T) {
	wall := modelBase
	a := &Auth{ID: "a", Provider: "codex"}
	b := &Auth{ID: "b", Provider: "claude"}
	bKnown := claudeWindowsNow(wall, 2*int64(testDay/time.Second), "allowed", wall.Add(time.Hour))

	codex := func(seen time.Time, after int64, read time.Time) windows {
		return observeWindows("codex", map[string]string{
			"X-Codex-Secondary-Window-Minutes":      "10080",
			"X-Codex-Secondary-Reset-After-Seconds": strconv.FormatInt(after, 10),
		}, seen, read)
	}

	var aWin windows
	s := soonestWith(wall, func(x *Auth) windows {
		if x.ID == "a" {
			return aWin
		}
		return bKnown
	})
	pick := func(w windows) string {
		aWin = w
		return mustPick(t, s, a, b)
	}

	boundary := wall.Add(600 * time.Second)
	// Reset reached: probed once.
	if got := pick(codex(wall, 600, boundary.Add(time.Second))); got != "a" {
		t.Fatalf("first probe = %q, want a", got)
	}
	// Lagging answers keep reporting one second left, each from a later observation.
	for i := int64(1); i < 4; i++ {
		seen := boundary.Add(time.Duration(i) * time.Second)
		if got := pick(codex(seen, 1, seen.Add(2*time.Second))); got != "b" {
			t.Fatalf("lagging answer %d = %q, want b", i, got)
		}
	}
	// A week later the window really rolls over again: one more probe.
	next := boundary.Add(7 * testDay)
	if got := pick(codex(next.Add(-5*time.Second), 5, next.Add(time.Second))); got != "a" {
		t.Fatalf("real rollover = %q, want a", got)
	}
	if got := pick(codex(next.Add(-5*time.Second), 5, next.Add(time.Second))); got != "b" {
		t.Fatalf("after re-probe = %q, want b", got)
	}
}

func TestSoonestReset_ProbeMarkersAreKeptPerWindow(t *testing.T) {
	wall := modelBase
	a := &Auth{ID: "a", Provider: "codex"}
	b := &Auth{ID: "b", Provider: "claude"}
	bKnown := claudeWindowsNow(wall, 5*int64(testDay/time.Second), "allowed", wall.Add(time.Hour))
	r := wall.Add(600 * time.Second)

	var aWin windows
	s := soonestWith(wall, func(x *Auth) windows {
		if x.ID == "a" {
			return aWin
		}
		return bKnown
	})
	pick := func(w windows) string {
		aWin = w
		return mustPick(t, s, a, b)
	}

	// 1. Only Secondary-Reset-At: R and no lengths: secondary is taken as weekly.
	partial := map[string]string{"X-Codex-Secondary-Reset-At": epochSecs(r)}
	w := observeWindows("codex", partial, wall, r.Add(time.Second))
	if w.rolledOver == nil || w.rolledOver.window != windowCodexSecondary {
		t.Fatalf("expected secondary rollover, got %+v", w.rolledOver)
	}
	if got := pick(w); got != "a" {
		t.Fatalf("secondary probe = %q, want a", got)
	}

	// 2. The answer: primary is the weekly window resetting at R+1 day, sooner
	//    than b; a keeps it.
	complete := map[string]string{
		"X-Codex-Primary-Used-Percent":     "10",
		"X-Codex-Primary-Window-Minutes":   "10080",
		"X-Codex-Primary-Reset-At":         epochSecs(r.Add(testDay)),
		"X-Codex-Secondary-Used-Percent":   "10",
		"X-Codex-Secondary-Window-Minutes": "300",
		"X-Codex-Secondary-Reset-At":       epochSecs(r.Add(5 * time.Hour)),
	}
	if got := pick(observeWindows("codex", complete, r.Add(time.Second), r.Add(2*time.Second))); got != "a" {
		t.Fatalf("learned primary = %q, want a", got)
	}

	// 3. Just after R+1 day, primary rolls over: one probe, not suppressed by
	//    the secondary's marker R.
	w = observeWindows("codex", complete, r.Add(time.Second), r.Add(testDay+time.Second))
	if w.rolledOver == nil || w.rolledOver.window != windowCodexPrimary {
		t.Fatalf("expected primary rollover, got %+v", w.rolledOver)
	}
	if got := pick(w); got != "a" {
		t.Fatalf("primary probe = %q, want a", got)
	}
	if got := pick(w); got != "b" {
		t.Fatalf("probed for that rollover = %q, want b", got)
	}
}

// claudeSignals builds the Claude quota snapshot (7-day reset weeklySecs ahead,
// an allowed 5-hour window resetting in an hour) for the real observeAuthWindows
// parsing path.
func claudeSignals(now time.Time, weeklySecs int64) map[string]string {
	return map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.40",
		"Anthropic-Ratelimit-Unified-7d-Reset":       epochSecs(now.Add(time.Duration(weeklySecs) * time.Second)),
		"Anthropic-Ratelimit-Unified-5h-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-5h-Reset":       epochSecs(now.Add(time.Hour)),
	}
}

// Exercises the production observeAuthWindows path (no injected rankFunc): the
// credential whose weekly window resets soonest is spent first, derived from its
// passive quota snapshot.
func TestSoonestReset_RanksViaObservedQuotaSignals(t *testing.T) {
	wall := modelBase
	a := &Auth{ID: "a", Provider: "claude", Quota: QuotaState{Signals: claudeSignals(wall, 4*int64(testDay/time.Second)), ObservedAt: wall}}
	b := &Auth{ID: "b", Provider: "claude", Quota: QuotaState{Signals: claudeSignals(wall, int64(testDay/time.Second)), ObservedAt: wall}}
	s := &SoonestResetSelector{nowFunc: func() time.Time { return wall }}

	for i := 0; i < 3; i++ {
		if got := mustPick(t, s, a, b); got != "b" {
			t.Fatalf("pick #%d = %q, want b (soonest weekly via observeAuthWindows)", i, got)
		}
	}
}

// At the bound, two live unknown accounts each probe exactly once and keep their
// spent state: the old blunt clear would have re-armed both once the map filled.
func TestSoonestReset_LiveProbesSurviveAtTheBound(t *testing.T) {
	now := modelBase
	s := &SoonestResetSelector{
		nowFunc:  func() time.Time { return now },
		rankFunc: func(*Auth, string, time.Time) windows { return windows{} },
		maxKeys:  1,
	}
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}

	var picks []string
	for i := 0; i < 6; i++ {
		now = now.Add(time.Second)
		picks = append(picks, mustPick(t, s, a, b))
	}
	if picks[0] != "a" || picks[1] != "b" {
		t.Fatalf("initial probes = %v, want a then b", picks[:2])
	}
	for i := 2; i < len(picks); i++ {
		if picks[i] == picks[i-1] {
			t.Fatalf("pick #%d repeated %q: a spent probe was wrongly re-armed at the bound", i, picks[i])
		}
	}
}

// Provider/model filtering, cooldowns and priorities are not registry removals.
func TestSoonestReset_FilteredSubsetsPreserveSpentProbes(t *testing.T) {
	for _, scope := range []struct{ provider, model string }{{"codex", "m"}, {"claude", "other-model"}, {"claude", "m"}} {
		t.Run(scope.provider+"/"+scope.model, func(t *testing.T) {
			now := modelBase
			s := &SoonestResetSelector{nowFunc: func() time.Time { return now }, maxKeys: 1}
			a := &Auth{ID: "a", Provider: "claude"}
			c := &Auth{ID: "c", Provider: scope.provider}
			b := &Auth{ID: "b", Provider: "claude", Quota: QuotaState{Signals: claudeSignals(now, 86400), ObservedAt: now}}
			mustPick(t, s, a)
			if _, err := s.Pick(context.Background(), scope.provider, scope.model, cliproxyexecutor.Options{}, []*Auth{c}); err != nil {
				t.Fatal(err)
			}
			if got := mustPick(t, s, a, b); got != "b" {
				t.Fatalf("filtered-out a was re-armed: picked %s, want known b", got)
			}
			if len(s.probes) != 2 {
				t.Fatalf("spent records = %d, want 2 despite rotation limit", len(s.probes))
			}
		})
	}
}

func TestSoonestReset_ManagerRegistryRemovalPrunesOnlyRemovedProbes(t *testing.T) {
	for _, reload := range []bool{false, true} {
		t.Run(strconv.FormatBool(reload), func(t *testing.T) {
			ctx := context.Background()
			s := &SoonestResetSelector{maxKeys: 1}
			store := newMemoryAuthTestStore()
			manager := NewManager(store, NewSessionAffinitySelector(s), nil)
			a := &Auth{ID: "a", Provider: "claude"}
			b := &Auth{ID: "b", Provider: "codex"}
			for _, auth := range []*Auth{a, b} {
				if _, err := manager.Register(ctx, auth); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Save(ctx, auth); err != nil {
					t.Fatal(err)
				}
				mustPick(t, s, auth)
			}
			if reload {
				if err := store.Delete(ctx, a.ID); err != nil {
					t.Fatal(err)
				}
				if err := manager.Load(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				manager.Remove(ctx, a.ID)
			}
			if _, ok := s.probes[a.ID]; ok {
				t.Fatal("removed credential retained probe")
			}
			if _, ok := s.probes[b.ID]; !ok {
				t.Fatal("other provider lost its spent probe")
			}
		})
	}
}

func TestSoonestReset_ManagerQuotaResetPreservesAffinity(t *testing.T) {
	ctx := context.Background()
	now := modelBase
	inner := &SoonestResetSelector{nowFunc: func() time.Time { return now }}
	selector := NewSessionAffinitySelector(inner)
	manager := NewManager(nil, selector, nil)
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude", Quota: QuotaState{Signals: claudeSignals(now, 86400), ObservedAt: now}}
	c := &Auth{ID: "c", Provider: "codex"}
	for _, auth := range []*Auth{a, b, c} {
		if _, err := manager.Register(ctx, auth); err != nil {
			t.Fatal(err)
		}
	}
	mustPick(t, inner, a)
	mustPick(t, inner, c)
	pinned := cliproxyexecutor.Options{OriginalRequest: []byte(`{"metadata":{"user_id":"user_xxx_account__session_ac980658-63bd-4fb3-97ba-8da64cb1e344"}}`)}
	if got, err := selector.Pick(ctx, "claude", "m", pinned, []*Auth{b}); err != nil || got == nil || got.ID != "b" {
		t.Fatalf("pin = %v, %v", got, err)
	}
	pinA := cliproxyexecutor.Options{OriginalRequest: []byte(`{"metadata":{"user_id":"user_xxx_account__session_bc980658-63bd-4fb3-97ba-8da64cb1e999"}}`)}
	if got, err := selector.Pick(ctx, "claude", "m", pinA, []*Auth{a}); err != nil || got == nil || got.ID != "a" {
		t.Fatalf("pin a = %v, %v", got, err)
	}
	if _, _, err := manager.ResetQuota(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := inner.probes[a.ID]; ok {
		t.Fatal("manager reset did not re-arm a")
	}
	if _, ok := inner.probes[c.ID]; !ok {
		t.Fatal("manager reset cleared other credential")
	}
	if got, err := selector.Pick(ctx, "claude", "m", pinned, []*Auth{a, b}); err != nil || got == nil || got.ID != "b" {
		t.Fatalf("reset moved pin = %v, %v", got, err)
	}
	if got := mustPick(t, inner, a, b); got != "a" {
		t.Fatalf("reset probe = %s, want a", got)
	}
	if got := mustPick(t, inner, a, b); got != "b" {
		t.Fatalf("after reset probe = %s, want b", got)
	}
	if got, err := selector.Pick(ctx, "claude", "m", pinA, []*Auth{a, b}); err != nil || got == nil || got.ID != "a" {
		t.Fatalf("reset lost own affinity = %v, %v", got, err)
	}
}

// An explicit quota reset re-arms only that credential's probe, mirroring the
// Rust scheduler's reset_cooldowns; other credentials' spent state is untouched.
func TestSoonestReset_QuotaResetReArmsThatCredentialsProbe(t *testing.T) {
	now := modelBase
	s := &SoonestResetSelector{
		nowFunc:  func() time.Time { return now },
		rankFunc: func(*Auth, string, time.Time) windows { return windows{} },
	}
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}

	if got := mustPick(t, s, a, b); got != "a" {
		t.Fatalf("probe a = %q, want a", got)
	}
	if got := mustPick(t, s, a, b); got != "b" {
		t.Fatalf("probe b = %q, want b", got)
	}

	s.OnQuotaReset("a")

	if got := mustPick(t, s, a, b); got != "a" {
		t.Fatalf("after reset, re-probe a = %q, want a", got)
	}
	s.mu.Lock()
	_, hasB := s.probes["b"]
	s.mu.Unlock()
	if !hasB {
		t.Fatalf("quota reset for a wrongly cleared b's probe")
	}
}

// The quota-reset hook reaches the soonest-reset selector through a
// session-affinity wrapper (whose own bindings stay in place) and nothing else.
func TestSoonestResetSelectorOf_UnwrapsSessionAffinity(t *testing.T) {
	inner := &SoonestResetSelector{}
	if got := soonestResetSelectorOf(inner); got != inner {
		t.Fatalf("direct unwrap = %v, want the selector", got)
	}
	if got := soonestResetSelectorOf(NewSessionAffinitySelector(inner)); got != inner {
		t.Fatalf("session-affinity unwrap = %v, want the wrapped selector", got)
	}
	if got := soonestResetSelectorOf(&RoundRobinSelector{}); got != nil {
		t.Fatalf("non-soonest selector unwrap = %v, want nil", got)
	}
}

// Session affinity continues to apply unchanged: a pinned thread keeps its
// credential while a fresh thread starts on the soonest reset.
func TestSoonestReset_NeverMovesASessionPin(t *testing.T) {
	wall := modelBase
	inAnHour := wall.Add(time.Hour)
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude"}
	ranks := func(x *Auth) windows {
		if x.ID == "a" {
			return claudeWindowsNow(wall, 4*int64(testDay/time.Second), "allowed", inAnHour)
		}
		return claudeWindowsNow(wall, int64(testDay/time.Second), "allowed", inAnHour)
	}
	inner := soonestWith(wall, ranks)
	selector := NewSessionAffinitySelector(inner)

	pinned := cliproxyexecutor.Options{OriginalRequest: []byte(`{"metadata":{"user_id":"user_xxx_account__session_ac980658-63bd-4fb3-97ba-8da64cb1e344"}}`)}
	fresh := cliproxyexecutor.Options{OriginalRequest: []byte(`{"metadata":{"user_id":"user_yyy_account__session_bc980658-63bd-4fb3-97ba-8da64cb1e999"}}`)}

	// The thread starts while only a is available, and keeps a afterwards.
	if got, err := selector.Pick(context.Background(), "claude", "m", pinned, []*Auth{a}); err != nil || got == nil || got.ID != "a" {
		t.Fatalf("pin start = %v (err %v), want a", got, err)
	}
	for i := 0; i < 2; i++ {
		got, err := selector.Pick(context.Background(), "claude", "m", pinned, []*Auth{a, b})
		if err != nil || got == nil || got.ID != "a" {
			t.Fatalf("pin keep #%d = %v (err %v), want a", i, got, err)
		}
	}

	// A new thread starts on the soonest reset.
	got, err := selector.Pick(context.Background(), "claude", "m", fresh, []*Auth{a, b})
	if err != nil || got == nil || got.ID != "b" {
		t.Fatalf("fresh thread = %v (err %v), want b", got, err)
	}
}

func TestSoonestReset_ConcurrentPicksReserveOneProbe(t *testing.T) {
	now := modelBase
	s := &SoonestResetSelector{nowFunc: func() time.Time { return now }}
	a := &Auth{ID: "a", Provider: "claude"}
	b := &Auth{ID: "b", Provider: "claude", Quota: QuotaState{Signals: claudeSignals(now, 86400), ObservedAt: now}}
	const requests = 32
	start := make(chan struct{})
	results := make(chan string, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			picked, err := s.Pick(context.Background(), "claude", "m", cliproxyexecutor.Options{}, []*Auth{a, b})
			if err != nil || picked == nil {
				results <- "error"
				return
			}
			results <- picked.ID
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	counts := make(map[string]int)
	for id := range results {
		counts[id]++
	}
	if counts["a"] != 1 || counts["b"] != requests-1 {
		t.Fatalf("concurrent picks = %v, want one a and %d b", counts, requests-1)
	}
}
