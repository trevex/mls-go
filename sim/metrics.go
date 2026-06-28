package sim

import "time"

// Metrics holds deterministic counters + measured (non-scheduling) CPU timing.
type Metrics struct {
	Delivered       int
	Reflected       int
	CtrlDropped     int
	DataDropped     int // transport loss (NOT a key-loss failure)
	Blocked         int
	CatchupRequests int
	LogRetransmits  int
	Recoveries      int
	LostRekeys      int
	Forks           int
	DataSent        int
	DataDecryptable int
	CommitMsgs      int
	CommitBytes     int
	MaxOverlap      int    // max |saCache| observed (the W actually needed +1)
	MaxSendLag      uint64 // max (currentEpoch - sendEpoch) observed
	cpuNanos        map[string]int64
	cpuCount        map[string]int64
}

func newMetrics() *Metrics {
	return &Metrics{cpuNanos: map[string]int64{}, cpuCount: map[string]int64{}}
}

// cpu records measured wall time of a real crypto call (NEVER used for scheduling).
func (m *Metrics) cpu(op string, d time.Duration) {
	m.cpuNanos[op] += d.Nanoseconds()
	m.cpuCount[op]++
}

func (m *Metrics) commitFanout(vni uint32, size, nDS int) {
	m.CommitMsgs += nDS // dual-peering ~doubles fan-out
	m.CommitBytes += size * nDS
}

func (m *Metrics) observeOverlap(n int) {
	if n > m.MaxOverlap {
		m.MaxOverlap = n
	}
}

func (m *Metrics) observeSendLag(lag uint64) {
	if lag > m.MaxSendLag {
		m.MaxSendLag = lag
	}
}
