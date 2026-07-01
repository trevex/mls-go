// Package scaling projects MLS-per-VNI control-plane load across a datacenter
// envelope from measured per-event constants, and costs an analytical
// pairwise-IKEv2 baseline over the same points. Baseline runs at a single
// reflector (S=1); sharding is a deferred parameter. Stdlib-only.
package scaling

// Params is one envelope point plus the measured constants for this M.
type Params struct {
	H, V, M int // hosts, VNIs, mean members-per-VNI

	S int // reflector shards (baseline 1; kept as a parameter for future sweeps)

	RRekey     float64 // PCS rekeys per VNI per second (1 / rekey-interval-seconds)
	LambdaMove float64 // migration/churn events per VNI per second

	BytesPerCommit int   // measured commit bytes for this M (bench.MeasureCommitBytes)
	CPUApplyNanos  int64 // measured cpu_per_apply for this M (0 = unknown; CPU frac left 0)

	FwdBudgetBytesPerSec float64 // reflector forwarding budget (>0 enables the knee test)
}

// Projection is the MLS load at one envelope point.
type Projection struct {
	Density                 float64 // D = V*M/H (mean VNIs-per-host)
	ReflectorFwdBytesPerSec float64 // (V/S)*(rRekey+λ)*(M-1)*bytesPerCommit
	ReflectorOrderOpsPerSec float64 // (V/S)*(rRekey+λ) — linearization throughput
	HostApplyPerSec         float64 // D*(rRekey+λ) — flat in V
	HostSAInstallsPerSec    float64 // == HostApplyPerSec (one epoch = one SA program)
	HostCPUFracBusy         float64 // HostApplyPerSec * cpuApplySeconds (fraction of one core)
	ReflectorSaturated      bool    // FwdBudget>0 && ReflectorFwdBytesPerSec > FwdBudget
}

func (p Params) shards() int {
	if p.S < 1 {
		return 1
	}
	return p.S
}

// Project computes the MLS load for one point.
func Project(p Params) Projection {
	rate := p.RRekey + p.LambdaMove
	density := float64(p.V) * float64(p.M) / float64(p.H)
	perShardVNIs := float64(p.V) / float64(p.shards())
	fanout := float64(p.M - 1)

	fwd := perShardVNIs * rate * fanout * float64(p.BytesPerCommit)
	apply := density * rate

	return Projection{
		Density:                 density,
		ReflectorFwdBytesPerSec: fwd,
		ReflectorOrderOpsPerSec: perShardVNIs * rate,
		HostApplyPerSec:         apply,
		HostSAInstallsPerSec:    apply,
		HostCPUFracBusy:         apply * float64(p.CPUApplyNanos) / 1e9,
		ReflectorSaturated:      p.FwdBudgetBytesPerSec > 0 && fwd > p.FwdBudgetBytesPerSec,
	}
}

// IKEv2Projection is the analytical pairwise-IKEv2 cost at one envelope point.
type IKEv2Projection struct {
	EstablishHandshakes        float64 // one-time full mesh: V * M*(M-1)/2
	HandshakesPerSecSteady     float64 // per migration a member re-handshakes M-1 peers: V*λ*(M-1)
	DataPlaneMemberVNIsPerHost float64 // topology-bound; equals MLS Density (parity)
}

// IKEv2Project costs the same (H,V,M,λ) point under a pairwise-IKEv2 model.
// Key-agreement is O(M^2) to establish and O(M) per membership change (each a
// full round-trip handshake with half-open state), versus MLS's one fanned-out
// commit with O(log M) crypto. The data-plane SA count is identical to MLS.
func IKEv2Project(p Params) IKEv2Projection {
	return IKEv2Projection{
		EstablishHandshakes:        float64(p.V) * float64(p.M) * float64(p.M-1) / 2,
		HandshakesPerSecSteady:     float64(p.V) * p.LambdaMove * float64(p.M-1),
		DataPlaneMemberVNIsPerHost: float64(p.V) * float64(p.M) / float64(p.H),
	}
}
