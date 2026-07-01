package scaling

import "testing"

func baseParams() Params {
	return Params{
		H: 1000, V: 10000, M: 20, S: 1,
		RRekey: 1.0 / 3600, LambdaMove: 1.0 / 600,
		BytesPerCommit: 2000, CPUApplyNanos: 200000,
		FwdBudgetBytesPerSec: 100e6,
	}
}

func TestDensityIsVMoverH(t *testing.T) {
	p := baseParams()
	got := Project(p).Density
	want := float64(p.V) * float64(p.M) / float64(p.H) // 200
	if got != want {
		t.Fatalf("Density = %v, want %v", got, want)
	}
}

func TestHostApplyIsFlatInV(t *testing.T) {
	// Host load depends on density D = V*M/H. Holding D fixed (scale V and H
	// together), host apply rate must not change.
	p1 := baseParams()
	p2 := baseParams()
	p2.V *= 10
	p2.H *= 10 // D unchanged
	a1 := Project(p1).HostApplyPerSec
	a2 := Project(p2).HostApplyPerSec
	if a1 != a2 {
		t.Fatalf("host apply not flat at fixed density: %v vs %v", a1, a2)
	}
}

func TestReflectorLoadLinearInV(t *testing.T) {
	p1 := baseParams()
	p2 := baseParams()
	p2.V *= 2
	r1 := Project(p1).ReflectorFwdBytesPerSec
	r2 := Project(p2).ReflectorFwdBytesPerSec
	if r2 <= r1*1.9 || r2 >= r1*2.1 {
		t.Fatalf("reflector fwd not ~linear in V: %v -> %v", r1, r2)
	}
}

func TestSaturationFlag(t *testing.T) {
	p := baseParams()
	p.FwdBudgetBytesPerSec = 1 // tiny budget ⇒ saturated
	if !Project(p).ReflectorSaturated {
		t.Fatal("expected ReflectorSaturated=true under tiny budget")
	}
	p.FwdBudgetBytesPerSec = 1e15 // huge budget ⇒ not saturated
	if Project(p).ReflectorSaturated {
		t.Fatal("expected ReflectorSaturated=false under huge budget")
	}
}

func TestIKEv2EstablishIsQuadraticInM(t *testing.T) {
	p := baseParams()
	p.M = 10
	a := IKEv2Project(p).EstablishHandshakes
	p.M = 20
	b := IKEv2Project(p).EstablishHandshakes
	// M-mesh is V*M*(M-1)/2; doubling M ~quadruples per-VNI handshakes.
	if b <= a*3.5 {
		t.Fatalf("IKEv2 establish not ~quadratic in M: M=10 -> %v, M=20 -> %v", a, b)
	}
}

func TestIKEv2SteadyScalesWithChurnAndFanout(t *testing.T) {
	p := baseParams()
	got := IKEv2Project(p).HandshakesPerSecSteady
	want := float64(p.V) * p.LambdaMove * float64(p.M-1)
	if got != want {
		t.Fatalf("IKEv2 steady = %v, want %v", got, want)
	}
}

func TestDataPlaneSACountParity(t *testing.T) {
	// Data-plane SA count is topology-bound ⇒ identical for MLS and IKEv2.
	p := baseParams()
	if IKEv2Project(p).DataPlaneMemberVNIsPerHost != Project(p).Density {
		t.Fatal("data-plane SA parity broken: IKEv2 and MLS must match (topology-bound)")
	}
}
