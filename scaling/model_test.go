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
