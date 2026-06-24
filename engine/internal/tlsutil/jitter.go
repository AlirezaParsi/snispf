package tlsutil

import (
	"math/rand"
	"time"
)

// jitterFrac randomizes pacing delays by ±this fraction so the inter-fragment /
// inter-fake cadence isn't a fixed, fingerprintable interval. 0 disables it.
var jitterFrac = 0.30

// randFloat is a seam so tests can make JitterDelay deterministic.
var randFloat = rand.Float64

// JitterDelay returns base scaled by a random factor in
// [1-jitterFrac, 1+jitterFrac], clamped to >= 0. A non-positive base or zero
// jitter fraction returns base unchanged.
func JitterDelay(base time.Duration) time.Duration {
	if base <= 0 || jitterFrac <= 0 {
		return base
	}
	factor := 1 + jitterFrac*(2*randFloat()-1)
	d := time.Duration(float64(base) * factor)
	if d < 0 {
		return 0
	}
	return d
}
