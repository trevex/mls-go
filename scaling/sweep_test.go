package scaling

import (
	"strings"
	"testing"
)

func TestSweepEmitsRowPerPoint(t *testing.T) {
	base := baseParams()
	rows := Sweep(base, []int{1000, 10000}, []int{1000, 10000, 100000})
	if len(rows) != 2*3 {
		t.Fatalf("got %d rows, want 6", len(rows))
	}
	for _, r := range rows {
		if r.MLS.ReflectorFwdBytesPerSec <= 0 {
			t.Fatalf("row H=%d V=%d has non-positive reflector load", r.H, r.V)
		}
	}
}

func TestKneeIsSmallestSaturatingV(t *testing.T) {
	base := baseParams()
	base.FwdBudgetBytesPerSec = 1e6 // low budget so some V saturates
	rows := Sweep(base, []int{1000}, []int{1000, 10000, 100000, 1000000})
	knee, found := Knee(rows)
	if !found {
		t.Fatal("expected a knee under a low budget")
	}
	// Every V below the knee must be unsaturated; the knee itself saturated.
	for _, r := range rows {
		if r.V < knee && r.MLS.ReflectorSaturated {
			t.Fatalf("V=%d saturated below reported knee V=%d", r.V, knee)
		}
	}
}

func TestCSVHasHeaderAndRows(t *testing.T) {
	rows := Sweep(baseParams(), []int{1000}, []int{1000, 10000})
	csv := CSV(rows)
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 1+2 {
		t.Fatalf("got %d lines, want header + 2 rows", len(lines))
	}
	if !strings.HasPrefix(lines[0], "H,V,M,") {
		t.Fatalf("unexpected CSV header: %q", lines[0])
	}
}

func TestPktKneeSmallestSaturatingV(t *testing.T) {
	base := baseParams()
	base.MTUPayload = 1460
	base.PktBudgetPerSec = 1e4 // low pps budget so some V saturates
	rows := Sweep(base, []int{1000}, []int{1000, 10000, 100000, 1000000})
	knee, found := PktKnee(rows)
	if !found {
		t.Fatal("expected a pkt knee under a low pps budget")
	}
	for _, r := range rows {
		if r.V < knee && r.MLS.ReflectorPktSaturated {
			t.Fatalf("V=%d pkt-saturated below reported pkt knee V=%d", r.V, knee)
		}
	}
}

func TestCSVHasPktColumns(t *testing.T) {
	base := baseParams()
	base.MTUPayload = 1460
	csv := CSV(Sweep(base, []int{1000}, []int{1000}))
	header := strings.SplitN(csv, "\n", 2)[0]
	for _, col := range []string{"host_commit_cpu_frac_busy", "packets_per_commit", "reflector_fwd_pkts_per_s", "reflector_pkt_saturated"} {
		if !strings.Contains(header, col) {
			t.Fatalf("CSV header missing %q: %s", col, header)
		}
	}
}
