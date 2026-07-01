package scaling

import (
	"fmt"
	"sort"
	"strings"
)

// Row is one swept envelope point with both projections.
type Row struct {
	H, V, M int
	MLS     Projection
	IKEv2   IKEv2Projection
}

// Sweep evaluates base over the cartesian product of hosts × vnis (M and rates
// come from base). Rows are returned sorted by (H, V) for determinism.
func Sweep(base Params, hosts, vnis []int) []Row {
	var rows []Row
	for _, h := range hosts {
		for _, v := range vnis {
			p := base
			p.H, p.V = h, v
			rows = append(rows, Row{H: h, V: v, M: p.M, MLS: Project(p), IKEv2: IKEv2Project(p)})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].H != rows[j].H {
			return rows[i].H < rows[j].H
		}
		return rows[i].V < rows[j].V
	})
	return rows
}

// Knee returns the smallest V at which the reflector saturates its BYTE budget
// (across all H in the rows). found=false if nothing saturates.
func Knee(rows []Row) (v int, found bool) {
	best := 0
	for _, r := range rows {
		if r.MLS.ReflectorSaturated && (!found || r.V < best) {
			best, found = r.V, true
		}
	}
	return best, found
}

// PktKnee returns the smallest V at which the reflector saturates its PACKET
// budget (across all H). found=false if nothing saturates.
func PktKnee(rows []Row) (v int, found bool) {
	best := 0
	for _, r := range rows {
		if r.MLS.ReflectorPktSaturated && (!found || r.V < best) {
			best, found = r.V, true
		}
	}
	return best, found
}

// CSV renders rows as CSV with a stable header. Values use %g for compactness.
func CSV(rows []Row) string {
	var b strings.Builder
	b.WriteString("H,V,M,density,reflector_fwd_bytes_per_s,reflector_order_ops_per_s," +
		"host_apply_per_s,host_cpu_frac_busy,host_commit_cpu_frac_busy,reflector_saturated," +
		"packets_per_commit,reflector_fwd_pkts_per_s,reflector_pkt_saturated," +
		"ikev2_establish_handshakes,ikev2_steady_handshakes_per_s\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%d,%d,%d,%g,%g,%g,%g,%g,%g,%t,%d,%g,%t,%g,%g\n",
			r.H, r.V, r.M, r.MLS.Density,
			r.MLS.ReflectorFwdBytesPerSec, r.MLS.ReflectorOrderOpsPerSec,
			r.MLS.HostApplyPerSec, r.MLS.HostCPUFracBusy, r.MLS.HostCommitCPUFracBusy,
			r.MLS.ReflectorSaturated,
			r.MLS.PacketsPerCommit, r.MLS.ReflectorFwdPktsPerSec, r.MLS.ReflectorPktSaturated,
			r.IKEv2.EstablishHandshakes, r.IKEv2.HandshakesPerSecSteady)
	}
	return b.String()
}
