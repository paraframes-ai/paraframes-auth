// Package ratelimit implements a simple per-key token-bucket limiter with
// background eviction of idle buckets.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter tracks token buckets keyed by an arbitrary string (typically client IP).
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*entry
	rps     rate.Limit
	burst   int
	ttl     time.Duration
}

type entry struct {
	limiter *rate.Limiter
	lastAt  time.Time
}

// New constructs a Limiter allowing rps sustained requests with the given burst.
func New(rps float64, burst int) *Limiter {
	l := &Limiter{
		buckets: make(map[string]*entry),
		rps:     rate.Limit(rps),
		burst:   burst,
		ttl:     10 * time.Minute,
	}
	go l.evictLoop()
	return l
}

// Allow reports whether a request for key may proceed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	e, ok := l.buckets[key]
	if !ok {
		e = &entry{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.buckets[key] = e
	}
	e.lastAt = time.Now()
	l.mu.Unlock()
	return e.limiter.Allow()
}

func (l *Limiter) evictLoop() {
	ticker := time.NewTicker(l.ttl)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-l.ttl)
		l.mu.Lock()
		for k, e := range l.buckets {
			if e.lastAt.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}
