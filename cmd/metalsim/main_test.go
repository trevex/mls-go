package main

import (
	"os"
	"testing"

	"github.com/trevex/mls-go/sim"
)

// withDiscardedStdout runs fn with os.Stdout pointed at /dev/null so the CLI's
// table/JSON output does not pollute test logs, restoring it afterwards.
func withDiscardedStdout(t *testing.T, fn func()) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devnull.Close() }()
	orig := os.Stdout
	os.Stdout = devnull
	defer func() { os.Stdout = orig }()
	fn()
}

// TestRunAllPassesAndExitsZero is the CLI smoke test: every built-in scenario
// (text output) must hold its invariants, so runAll returns exit code 0. The
// scenarios are run at their tuned defaults (one seed) — overriding clients/VNIs
// changes the membership model and is not what the gate exercises.
func TestRunAllPassesAndExitsZero(t *testing.T) {
	withDiscardedStdout(t, func() {
		if code := runAll(0, 0, 1, 0, -1, false, false); code != 0 {
			t.Fatalf("runAll text: exit code = %d, want 0 (all built-in scenarios must pass)", code)
		}
	})
}

// TestRunAllJSON exercises the JSON output branch of runAll and printOne.
func TestRunAllJSON(t *testing.T) {
	withDiscardedStdout(t, func() {
		if code := runAll(0, 0, 2, 0, -1, true, false); code != 0 {
			t.Fatalf("runAll json: exit code = %d, want 0", code)
		}
	})
}

// TestPrintOneFailVerbose covers printOne's FAIL-status header and the verbose
// trace branch using the negative control, which is a single fast scenario that
// deliberately violates the zero-loss invariant.
func TestPrintOneFailVerbose(t *testing.T) {
	r := sim.Run(sim.NegativeControl(), 1)
	if r.InvariantsHeld {
		t.Fatal("negative control unexpectedly held its invariants")
	}
	withDiscardedStdout(t, func() {
		printOne("negative_control", r, false, true) // verbose text
		printOne("negative_control", r, true, false) // JSON
	})
}

func TestApplyOverrides(t *testing.T) {
	sc := sim.Nominal()
	baseClients, baseVNIs := sc.Clients, sc.VNIs

	// Zero / sentinel values leave the scenario defaults untouched.
	applyOverrides(&sc, 0, 0, 0, -1)
	if sc.Clients != baseClients || sc.VNIs != baseVNIs {
		t.Fatalf("zero overrides changed defaults: clients %d->%d vnis %d->%d",
			baseClients, sc.Clients, baseVNIs, sc.VNIs)
	}

	// Non-zero values are applied.
	applyOverrides(&sc, 7, 3, 42, 0.25)
	if sc.Clients != 7 {
		t.Errorf("Clients = %d, want 7", sc.Clients)
	}
	if sc.VNIs != 3 {
		t.Errorf("VNIs = %d, want 3", sc.VNIs)
	}
	if sc.SettleRounds != 42 {
		t.Errorf("SettleRounds = %d, want 42", sc.SettleRounds)
	}
	if sc.Faults.DropProb != 0.25 {
		t.Errorf("DropProb = %v, want 0.25", sc.Faults.DropProb)
	}
}
