package forwarder

import (
	"math/rand"
	"strings"
	"sync"
	"time"

	"snispf/internal/logx"
)

// Decoy-health tuning. A decoy SNI is judged only after a few samples, dropped
// when its recent wrong_seq confirm rate falls too low, and re-probed after an
// exponentially backed-off cooldown.
const (
	decoyWindow     = 20               // decay attempts/confirms past this many samples (recency bias)
	decoyMinSamples = 5                // need this many attempts before judging a decoy
	decoyMinRate    = 0.5              // drop a decoy below this confirm rate
	decoyBackoffMin = 30 * time.Second // first cooldown after a drop
	decoyBackoffMax = 10 * time.Minute // cooldown ceiling
)

// decoyHealth tracks one decoy SNI's recent wrong_seq confirmation outcomes. A
// decoy that stops passing the DPI — it left a whitelist, or the DPI learned and
// blocked it — is taken out of rotation, then re-probed after the cooldown.
type decoyHealth struct {
	attempts      float64
	confirms      float64
	disabledUntil time.Time
	backoff       time.Duration
}

// decoyPool selects decoy SNIs for the fake ClientHello and prunes ones that stop
// confirming. It is whitelist-safe: under a single-domain whitelist only the
// whitelisted decoy ever confirms, so only it stays in rotation; non-passing
// decoys are dropped automatically.
type decoyPool struct {
	mu     sync.Mutex
	names  []string
	health map[string]*decoyHealth
}

func newDecoyPool(names []string) *decoyPool {
	p := &decoyPool{health: make(map[string]*decoyHealth)}
	seen := make(map[string]bool)
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		p.names = append(p.names, n)
		p.health[n] = &decoyHealth{}
	}
	return p
}

// pick returns a decoy SNI from the currently-healthy set, or "" when the pool is
// empty (caller falls back to the endpoint's base decoy). A decoy whose cooldown
// has expired is eligible again — that pick is its re-probe. If every decoy is in
// cooldown, the one whose cooldown ends soonest is returned anyway so the pool
// never starves: under a single-domain whitelist that lone decoy is the only
// thing that can work, and dropping it would kill all traffic.
func (p *decoyPool) pick() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.names) == 0 {
		return ""
	}
	now := time.Now()
	var active []string
	soonest := ""
	var soonestT time.Time
	for _, n := range p.names {
		h := p.health[n]
		if !now.Before(h.disabledUntil) {
			active = append(active, n)
			continue
		}
		if soonest == "" || h.disabledUntil.Before(soonestT) {
			soonest = n
			soonestT = h.disabledUntil
		}
	}
	if len(active) == 0 {
		return soonest
	}
	return active[rand.Intn(len(active))]
}

// record folds one confirm outcome into a decoy's health and drops the decoy
// (with exponential backoff) when its recent confirm rate falls below the floor.
// A confirm after a drop clears the cooldown and resets the backoff.
func (p *decoyPool) record(name string, ok bool) {
	if p == nil || name == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[name]
	if h == nil {
		return
	}
	if h.attempts >= decoyWindow {
		h.attempts /= 2
		h.confirms /= 2
	}
	h.attempts++
	if ok {
		h.confirms++
		if !h.disabledUntil.IsZero() {
			logx.Infof("decoy %q recovered, back in rotation", name)
			h.disabledUntil = time.Time{}
			h.backoff = 0
		}
		return
	}
	if h.attempts < decoyMinSamples || h.confirms/h.attempts >= decoyMinRate {
		return
	}
	if h.backoff == 0 {
		h.backoff = decoyBackoffMin
	} else {
		h.backoff *= 2
		if h.backoff > decoyBackoffMax {
			h.backoff = decoyBackoffMax
		}
	}
	h.disabledUntil = time.Now().Add(h.backoff)
	logx.Warnf("decoy %q dropped from rotation rate=%.2f cooldown=%s", name, h.confirms/h.attempts, h.backoff)
}
