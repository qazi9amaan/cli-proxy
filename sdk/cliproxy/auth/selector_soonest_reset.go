package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// maxObservedQuotaResetHorizon bounds how far ahead an observed reset may lie
// before it is ignored. The longest known quota window (Anthropic 7 days) plus
// slack covers a just-rolled-over observation; anything further out is a
// billing boundary or clock skew, not an upcoming window reset.
const maxObservedQuotaResetHorizon = 8 * 24 * time.Hour

// SoonestResetSelector concentrates traffic on the available credential whose
// observed quota window resets soonest, so capacity that refills (or expires)
// first is burned first. Reset times come from the passive quota signals
// captured on upstream responses (Claude unified rate-limit headers, Codex
// reset watermarks, Devin quota snapshots). Credentials without a usable
// observation rank behind observed ones in stable ID order, so a cold pool
// degenerates to fill-first until observations arrive.
type SoonestResetSelector struct {
	// nowFunc overrides the clock for tests; nil means time.Now.
	nowFunc func() time.Time
}

func (s *SoonestResetSelector) now() time.Time {
	if s != nil && s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

// Pick selects the available auth with the earliest upcoming observed quota reset.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := s.now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	return pickSoonestReset(available, now), nil
}

// pickSoonestReset returns the candidate with the earliest upcoming observed
// quota reset. Candidates arrive ID-sorted, so a strict Before comparison keeps
// ties and observation-less pools on the first candidate in ID order.
func pickSoonestReset(available []*Auth, now time.Time) *Auth {
	if len(available) == 0 {
		return nil
	}
	picked := available[0]
	pickedReset, pickedObserved := nextObservedQuotaReset(picked, now)
	for _, candidate := range available[1:] {
		reset, observed := nextObservedQuotaReset(candidate, now)
		if !observed {
			continue
		}
		if !pickedObserved || reset.Before(pickedReset) {
			picked = candidate
			pickedReset = reset
			pickedObserved = true
		}
	}
	return picked
}

// nextObservedQuotaReset derives the earliest upcoming reset instant from the
// credential's passive quota signal snapshot. Past resets mean the window
// already rolled over and carry no ordering information.
func nextObservedQuotaReset(auth *Auth, now time.Time) (time.Time, bool) {
	if auth == nil || len(auth.Quota.Signals) == 0 {
		return time.Time{}, false
	}
	var earliest time.Time
	for key, value := range auth.Quota.Signals {
		resetAt, ok := quotaSignalResetTime(key, value, auth.Quota.ObservedAt)
		if !ok || !resetAt.After(now) || resetAt.Sub(now) > maxObservedQuotaResetHorizon {
			continue
		}
		if earliest.IsZero() || resetAt.Before(earliest) {
			earliest = resetAt
		}
	}
	return earliest, !earliest.IsZero()
}

// quotaSignalResetTime converts one quota signal into an absolute reset
// instant. Underscore keys (Devin snapshots) normalize to the hyphenated
// header-style suffixes. Overage resets are billing-period boundaries, not
// window resets, and never participate in ordering.
func quotaSignalResetTime(key, value string, observedAt time.Time) (time.Time, bool) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "_", "-")
	if strings.Contains(normalized, "overage") {
		return time.Time{}, false
	}
	switch {
	case strings.HasSuffix(normalized, "-reset-after-seconds"):
		if observedAt.IsZero() {
			return time.Time{}, false
		}
		seconds, errParse := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if errParse != nil || seconds <= 0 {
			return time.Time{}, false
		}
		return observedAt.Add(time.Duration(seconds * float64(time.Second))), true
	case strings.HasSuffix(normalized, "-reset"), strings.HasSuffix(normalized, "-reset-at"):
		return parseQuotaResetTimestamp(value)
	default:
		return time.Time{}, false
	}
}

// parseQuotaResetTimestamp accepts the upstream reset formats: Unix epoch
// seconds (Claude unified headers, Codex reset-at), RFC 3339 (Devin), and
// HTTP-date.
func parseQuotaResetTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if sec, errParse := strconv.ParseFloat(raw, 64); errParse == nil && sec > 0 {
		secInt := int64(sec)
		nsec := int64((sec - float64(secInt)) * 1e9)
		return time.Unix(secInt, nsec), true
	}
	if parsed, errParse := time.Parse(time.RFC3339, raw); errParse == nil {
		return parsed, true
	}
	if parsed, errParse := http.ParseTime(raw); errParse == nil {
		return parsed, true
	}
	return time.Time{}, false
}
