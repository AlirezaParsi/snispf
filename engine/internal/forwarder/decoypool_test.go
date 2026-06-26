package forwarder

import (
	"testing"
	"time"
)

func TestDecoyPoolNilSafe(t *testing.T) {
	var p *decoyPool
	if got := p.pick(); got != "" {
		t.Fatalf("nil pick = %q, want empty", got)
	}
	p.record("x", false) // must not panic
}

func TestDecoyPoolDedupAndEmpty(t *testing.T) {
	p := newDecoyPool([]string{" a.com ", "a.com", "", "b.com"})
	if len(p.names) != 2 {
		t.Fatalf("names = %v, want 2 deduped/trimmed", p.names)
	}
	if got := newDecoyPool(nil).pick(); got != "" {
		t.Fatalf("empty pool pick = %q, want empty", got)
	}
}

func TestDecoyPoolDropsBadDecoy(t *testing.T) {
	p := newDecoyPool([]string{"bad.com", "good.com"})
	// Fail bad.com past the min-sample / min-rate floor.
	for i := 0; i < decoyMinSamples+2; i++ {
		p.record("bad.com", false)
	}
	if !p.health["bad.com"].disabledUntil.After(time.Now()) {
		t.Fatal("bad.com should be disabled after sustained failures")
	}
	// good.com untouched stays eligible; pick must never return the disabled one
	// while a healthy one exists.
	for i := 0; i < 50; i++ {
		if got := p.pick(); got != "good.com" {
			t.Fatalf("pick = %q while bad.com disabled, want good.com", got)
		}
	}
}

func TestDecoyPoolBelowMinSamplesNotDropped(t *testing.T) {
	p := newDecoyPool([]string{"x.com"})
	for i := 0; i < decoyMinSamples-1; i++ {
		p.record("x.com", false)
	}
	if !p.health["x.com"].disabledUntil.IsZero() {
		t.Fatal("decoy dropped before min samples reached")
	}
}

func TestDecoyPoolRecoverClearsCooldown(t *testing.T) {
	p := newDecoyPool([]string{"x.com"})
	for i := 0; i < decoyMinSamples+2; i++ {
		p.record("x.com", false)
	}
	if p.health["x.com"].disabledUntil.IsZero() {
		t.Fatal("x.com should be disabled")
	}
	// Force the cooldown open, then a confirm must clear it and reset backoff.
	p.health["x.com"].disabledUntil = time.Now().Add(-time.Second)
	p.record("x.com", true)
	h := p.health["x.com"]
	if !h.disabledUntil.IsZero() || h.backoff != 0 {
		t.Fatalf("confirm did not clear cooldown: disabledUntil=%v backoff=%v", h.disabledUntil, h.backoff)
	}
}

func TestDecoyPoolNeverStarves(t *testing.T) {
	p := newDecoyPool([]string{"only.com"})
	for i := 0; i < decoyMinSamples+2; i++ {
		p.record("only.com", false)
	}
	// Every decoy in cooldown — pick must still return the lone decoy (a re-probe)
	// rather than "", or all traffic would die under a single-domain whitelist.
	if got := p.pick(); got != "only.com" {
		t.Fatalf("pick = %q with all disabled, want only.com (never starve)", got)
	}
}

func TestDecoyPoolBackoffGrows(t *testing.T) {
	p := newDecoyPool([]string{"x.com"})
	for i := 0; i < decoyMinSamples; i++ { // exactly enough to trigger the first drop
		p.record("x.com", false)
	}
	first := p.health["x.com"].backoff
	if first != decoyBackoffMin {
		t.Fatalf("first backoff = %v, want %v", first, decoyBackoffMin)
	}
	p.record("x.com", false) // another failure while disabled grows backoff
	if p.health["x.com"].backoff <= first {
		t.Fatalf("backoff did not grow: %v <= %v", p.health["x.com"].backoff, first)
	}
}
