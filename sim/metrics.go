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
	_ = vni
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

// Report renders the text table (default output).
func (m *Metrics) Report() string {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "metric\tvalue\n")
	fmt.Fprintf(w, "delivered\t%d\n", m.Delivered)
	fmt.Fprintf(w, "ctrl-dropped\t%d\n", m.CtrlDropped)
	fmt.Fprintf(w, "data-sent\t%d\n", m.DataSent)
	fmt.Fprintf(w, "data-decryptable\t%d\n", m.DataDecryptable)
	fmt.Fprintf(w, "data-dropped(transport)\t%d\n", m.DataDropped)
	fmt.Fprintf(w, "forks\t%d\n", m.Forks)
	fmt.Fprintf(w, "recoveries\t%d\n", m.Recoveries)
	fmt.Fprintf(w, "lost-rekeys\t%d\n", m.LostRekeys)
	fmt.Fprintf(w, "catchup-requests\t%d\n", m.CatchupRequests)
	fmt.Fprintf(w, "log-retransmits\t%d\n", m.LogRetransmits)
	fmt.Fprintf(w, "commit-msgs(fanout)\t%d\n", m.CommitMsgs)
	fmt.Fprintf(w, "commit-bytes(fanout)\t%d\n", m.CommitBytes)
	fmt.Fprintf(w, "max-SA-overlap(W+1)\t%d\n", m.MaxOverlap)
	fmt.Fprintf(w, "max-send-lag\t%d\n", m.MaxSendLag)
	for _, op := range sortedStr(m.cpuCount) {
		n := m.cpuCount[op]
		avg := time.Duration(0)
		if n > 0 {
			avg = time.Duration(m.cpuNanos[op] / n)
		}
		fmt.Fprintf(w, "cpu/%s (n=%d)\t%s\n", op, n, avg)
	}
	w.Flush()
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
