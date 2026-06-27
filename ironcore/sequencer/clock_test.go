package sequencer_test

import (
	"sync"
	"time"
)

// fakeClock is an injectable group.Clock for deterministic lease-expiry testing.
// The mutex makes it safe to advance from one goroutine while another calls Now.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t0 time.Time) *fakeClock { return &fakeClock{now: t0} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
