package auth

import (
	"context"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// SoonestResetSelector concentrates traffic on the available credential whose
// weekly usage window resets soonest, so capacity that refills (or expires)
// first is burned first. It ports the soonest-reset strategy from cliproxy-rs
// (crates/cpa-server/src/scheduler.rs): credentials are ranked by the window
// model in soonest_reset_windows.go, an account with no known reset is probed
// exactly once (and re-probed once its long window rolls over), used-up accounts
// fall behind usable ones, and equal ranks take turns.
//
// Credential priority tiers, availability/cooldown filtering, and session
// affinity continue to apply through the shared selector pipeline, exactly as
// for the other strategies.
type SoonestResetSelector struct {
	// nowFunc overrides the clock for tests; nil means time.Now.
	nowFunc func() time.Time

	// rankFunc overrides how a credential's windows are derived; nil means the
	// production observeAuthWindows. Set only by tests to feed frozen windows,
	// mirroring the Rust scheduler's injectable Ranks closure.
	rankFunc func(auth *Auth, provider string, now time.Time) windows

	mu sync.Mutex
	// lastPicked records the last credential picked per rotation scope so equal
	// ranks take turns, mirroring RoundRobinSelector.
	lastPicked map[string]string
	// probes records, per credential, the rollover each spent probe was made
	// for (per window). A present entry means the account's one probe for an
	// unknown reset was spent.
	probes  map[string]map[windowID]time.Time
	maxKeys int
}

// keyLimit bounds the rotation map, mirroring RoundRobinSelector.
func (s *SoonestResetSelector) keyLimit() int {
	if s.maxKeys > 0 {
		return s.maxKeys
	}
	return 4096
}

func (s *SoonestResetSelector) now() time.Time {
	if s != nil && s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

// Pick selects the available auth with the soonest upcoming weekly reset,
// spending a one-shot probe on an unknown account when one is the best choice.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := s.now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	if len(available) == 0 {
		return nil, newAuthUnavailableError(time.Time{}, now)
	}

	key := provider + ":" + canonicalModelKey(model)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureState(key)
	picked := s.pickLocked(key, provider, available, now)
	s.lastPicked[key] = picked.ID
	return picked, nil
}

// rankedAuth carries one candidate's computed order alongside its rollover, so
// the probe can be spent without recomputing the window model.
type rankedAuth struct {
	order   orderKey
	rolled  *rollover
	auth    *Auth
	isProbe bool
}

// pickLocked ranks the available candidates (already ID-sorted), picks the best
// rank (rotating among ties), and spends the probe when the pick is a probe.
// Must be called with s.mu held.
func (s *SoonestResetSelector) pickLocked(key, provider string, available []*Auth, now time.Time) *Auth {

	ranked := make([]rankedAuth, len(available))
	var best orderKey
	for i, candidate := range available {
		w := s.rank(candidate, provider, now)
		record, exists := s.probes[candidate.ID]
		order := w.order(probedState(record, exists, w.rolledOver))
		ranked[i] = rankedAuth{order: order, rolled: w.rolledOver, auth: candidate, isProbe: order.class == 0}
		if i == 0 || order.less(best) {
			best = order
		}
	}

	// Equal ranks take turns: the first tied credential ordered after the last
	// pick, wrapping to the first tied one.
	last := s.lastPicked[key]
	var chosen *rankedAuth
	var first *rankedAuth
	for i := range ranked {
		if !ranked[i].order.equal(best) {
			continue
		}
		if first == nil {
			first = &ranked[i]
		}
		if ranked[i].auth.ID > last {
			chosen = &ranked[i]
			break
		}
	}
	if chosen == nil {
		chosen = first
	}

	if chosen.isProbe {
		// Its one probe, spent whatever the answer: the next pick ranks it by
		// what the answer reports, if anything.
		markers, ok := s.probes[chosen.auth.ID]
		if !ok {
			markers = make(map[windowID]time.Time)
			s.probes[chosen.auth.ID] = markers
		}
		if chosen.rolled != nil {
			markers[chosen.rolled.window] = chosen.rolled.at
		}
	}
	return chosen.auth
}

// retainRegisteredProbes removes records only against the manager's complete
// registry, never a request's filtered candidate set. Live records may exceed
// keyLimit: forgetting one would incorrectly re-arm its one-shot probe.
// The caller must hold the manager lock while supplying its registry.
func (s *SoonestResetSelector) retainRegisteredProbes(auths map[string]*Auth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.probes {
		if _, exists := auths[id]; !exists {
			delete(s.probes, id)
		}
	}
}

// rank derives a credential's windows, honouring a test override when set.
func (s *SoonestResetSelector) rank(auth *Auth, provider string, now time.Time) windows {
	if s.rankFunc != nil {
		return s.rankFunc(auth, provider, now)
	}
	return observeAuthWindows(auth, provider, now)
}

// observeAuthWindows derives the usage windows from a credential's passive quota
// snapshot. The credential's own provider is preferred; the selection provider
// is a fallback when it is unset.
func observeAuthWindows(auth *Auth, provider string, now time.Time) windows {
	if auth == nil || len(auth.Quota.Signals) == 0 {
		return windows{}
	}
	credentialProvider := auth.Provider
	if credentialProvider == "" {
		credentialProvider = provider
	}
	return observeWindows(credentialProvider, auth.Quota.Signals, auth.Quota.ObservedAt, now)
}

// ensureState initialises the rotation and probe maps. The rotation map is
// bounded by clearing it, mirroring RoundRobinSelector. Probe records survive
// until a quota reset or authoritative registry removal.
// Must be called with s.mu held.
func (s *SoonestResetSelector) ensureState(key string) {
	if s.lastPicked == nil {
		s.lastPicked = make(map[string]string)
	}
	if _, ok := s.lastPicked[key]; !ok && len(s.lastPicked) >= s.keyLimit() {
		s.lastPicked = make(map[string]string)
	}
	if s.probes == nil {
		s.probes = make(map[string]map[windowID]time.Time)
	}
}

// OnQuotaReset re-arms a credential's one probe after an explicit quota reset so
// the next pick may probe it afresh, mirroring the Rust scheduler's
// reset_cooldowns. Only that credential's probe state is cleared; every other
// credential's spent state and all session affinity are left untouched.
func (s *SoonestResetSelector) OnQuotaReset(authID string) {
	if s == nil || authID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.probes, authID)
}

// soonestResetSelectorOf returns the soonest-reset selector reached through the
// active selector, unwrapping a session-affinity wrapper (whose own bindings are
// not affected). It returns nil when soonest-reset routing is not active.
func soonestResetSelectorOf(selector Selector) *SoonestResetSelector {
	switch sel := selector.(type) {
	case *SoonestResetSelector:
		return sel
	case *SessionAffinitySelector:
		if sel != nil {
			return soonestResetSelectorOf(sel.fallback)
		}
	}
	return nil
}
