package sim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"
	"time"
)

// Metrics holds deterministic counters + measured (non-scheduling) CPU timing.
type Metrics struct {
	Delivered       int
	Reflected       int
	CtrlDropped     int
	DataDropped     int // transport loss (NOT a key-loss failure)
	Blocked         int
	CatchupRequests int
	LogRetransmits  int
	CommitRejected  int // commits dropped by a reflector's local register (dedup / loser)
	CommitResends   int // committer resends of an unconfirmed head commit (drop recovery)
	DataSent        int
	DataDecryptable int
	CommitMsgs      int
	CommitBytes     int
	MaxOverlap      int    // max |saCache| observed (the W actually needed +1)
	MaxSendLag      uint64 // max (currentEpoch - sendEpoch) observed
	PlaintextHandshakeExposures int // member handshakes a reflector saw as PublicMessage in an encrypted VNI
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

func (m *Metrics) commitFanout(size, nDS int) {
	m.CommitMsgs += nDS // each replica peers a single reflector (nDS=1 per call)
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

// Report renders the text table (default output).
func (m *Metrics) Report() string {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	// Writes to an in-memory tabwriter never fail; ignore the errors.
	_, _ = fmt.Fprintf(w, "metric\tvalue\n")
	_, _ = fmt.Fprintf(w, "delivered\t%d\n", m.Delivered)
	_, _ = fmt.Fprintf(w, "ctrl-dropped\t%d\n", m.CtrlDropped)
	_, _ = fmt.Fprintf(w, "data-sent\t%d\n", m.DataSent)
	_, _ = fmt.Fprintf(w, "data-decryptable\t%d\n", m.DataDecryptable)
	_, _ = fmt.Fprintf(w, "data-dropped(transport)\t%d\n", m.DataDropped)
	_, _ = fmt.Fprintf(w, "catchup-requests\t%d\n", m.CatchupRequests)
	_, _ = fmt.Fprintf(w, "log-retransmits\t%d\n", m.LogRetransmits)
	_, _ = fmt.Fprintf(w, "commit-msgs(fanout)\t%d\n", m.CommitMsgs)
	_, _ = fmt.Fprintf(w, "commit-bytes(fanout)\t%d\n", m.CommitBytes)
	_, _ = fmt.Fprintf(w, "max-SA-overlap(W+1)\t%d\n", m.MaxOverlap)
	_, _ = fmt.Fprintf(w, "max-send-lag\t%d\n", m.MaxSendLag)
	_, _ = fmt.Fprintf(w, "plaintext-handshake-exposures\t%d\n", m.PlaintextHandshakeExposures)
	for _, op := range sortedStr(m.cpuCount) {
		n := m.cpuCount[op]
		avg := time.Duration(0)
		if n > 0 {
			avg = time.Duration(m.cpuNanos[op] / n)
		}
		_, _ = fmt.Fprintf(w, "cpu/%s (n=%d)\t%s\n", op, n, avg)
	}
	_ = w.Flush()
	return b.String()
}

// ReportJSON renders a stable JSON object (deterministic key order via struct).
func (m *Metrics) ReportJSON() ([]byte, error) {
	type cpuEntry struct {
		Op      string `json:"op"`
		Count   int64  `json:"count"`
		AvgNano int64  `json:"avg_nanos"`
	}
	var cpus []cpuEntry
	for _, op := range sortedStr(m.cpuCount) {
		n := m.cpuCount[op]
		var avg int64
		if n > 0 {
			avg = m.cpuNanos[op] / n
		}
		cpus = append(cpus, cpuEntry{op, n, avg})
	}
	return json.MarshalIndent(struct {
		*Metrics
		CPU []cpuEntry `json:"cpu"`
	}{m, cpus}, "", "  ")
}

func sortedStr(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
