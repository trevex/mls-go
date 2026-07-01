# MLS-vs-IKEv2 Scaling Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce measured per-event MLS crypto constants, project reflector and host control-plane load across a datacenter envelope (single reflector, `S=1`) with an analytical IKEv2 overlay, and validate the projection against the real discrete-event sim — yielding a falsifiable "MLS is/isn't a good fit" verdict.

**Architecture:** Three tiers. **Tier 1** (`bench/`): deterministic byte-constant measurement + non-deterministic `testing.B` CPU benchmarks over members-per-VNI `M`. **Tier 2** (`scaling/` + `cmd/scalebench/`): pure formulas fed by Tier-1 constants, sweeping `(H, V)` at `S=1`, emitting CSV + knee/verdict + IKEv2 overlay. **Tier 3** (`sim/` extensions): leave/migration churn, per-actor/per-tick rate + convergence metrics, and a validation test that the sim's realized fan-out matches the model.

**Tech Stack:** Go (stdlib-only, root module `github.com/trevex/mls-go`), driven under `nix develop -c`. Reuses `mls/group`, `mls/cipher`, `ironcore`, `sim`.

**Design spec:** `docs/superpowers/specs/2026-07-01-scaling-benchmark-design.md`.

---

## Conventions (all tasks)

- Go is not on the bare PATH. Run every Go command as `nix develop -c <cmd>`.
- Root module is **stdlib-only**. Do not add imports outside the standard library or the repo's own packages. `make check-zero-dep` must still pass.
- Ciphersuite constants: `cipher.X25519_AES128GCM_SHA256_Ed25519` (0x0001, classical) and `cipher.XWING_AES256GCM_SHA256_Ed25519` (0xF001, PQ). Resolve with `cipher.Lookup(id) (cipher.Suite, bool)`.
- Credentials/lifetimes follow the sim's pattern: `tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte(id)}`, `tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)}`, Ed25519 signer via `ed25519.GenerateKey(rand.Reader)`.

## File Structure

- `bench/bench.go` — deterministic constant measurement helpers (build M-member group, measure commit/welcome bytes).
- `bench/bench_test.go` — byte-growth assertions + CPU `testing.B` benchmarks.
- `scaling/model.go` — `Params`, `Project` (MLS), `IKEv2Project` (overlay).
- `scaling/model_test.go` — formula unit tests.
- `scaling/sweep.go` — `(H,V)` sweep + CSV emit + knee detection.
- `scaling/sweep_test.go` — sweep/CSV/knee tests.
- `cmd/scalebench/main.go` — CLI: measure constants → sweep → CSV/verdict.
- `cmd/scalebench/main_test.go` — CLI smoke test.
- `sim/scenario.go` — add `migrationPlan` + `MigrationChurn` scenario (modify).
- `sim/migration_test.go` — migration convergence test.
- `sim/metrics.go` — rate + convergence fields/methods/report rows (modify).
- `sim/client.go`, `sim/sim.go` — increment the new counters (modify).
- `sim/rate_test.go` — rate/convergence metric tests.
- `sim/validation_test.go` — Tier-2↔Tier-3 fan-out cross-check.
- `docs/scaling-results.md` — results write-up (final task).
- `Makefile` — `bench` + `scalebench` targets (modify).

---

## Task 1: Tier-1 deterministic constant measurement (`bench` package)

**Files:**
- Create: `bench/bench.go`
- Test: `bench/bench_test.go`

- [ ] **Step 1: Write the failing test**

`bench/bench_test.go`:

```go
package bench

import (
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

func classical(t *testing.T) cipher.Suite {
	t.Helper()
	s, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("classical suite not registered")
	}
	return s
}

func TestBuildGroupHasMMembers(t *testing.T) {
	s := classical(t)
	for _, M := range []int{1, 2, 8, 32} {
		g, err := BuildGroup(s, M)
		if err != nil {
			t.Fatalf("BuildGroup(M=%d): %v", M, err)
		}
		if got := len(g.ActiveLeaves()); got != M {
			t.Fatalf("M=%d: ActiveLeaves=%d, want %d", M, got, M)
		}
	}
}

func TestCommitBytesPositiveAndGrows(t *testing.T) {
	s := classical(t)
	small, err := MeasureCommitBytes(s, 4, OpUpdate)
	if err != nil {
		t.Fatal(err)
	}
	large, err := MeasureCommitBytes(s, 64, OpUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if small <= 0 || large <= 0 {
		t.Fatalf("non-positive commit bytes: small=%d large=%d", small, large)
	}
	// TreeKEM UpdatePath grows with tree depth ⇒ a 64-member commit is larger
	// than a 4-member one (monotone; not asserting the exact log constant).
	if large <= small {
		t.Fatalf("expected commit bytes to grow with M: M=4 -> %d, M=64 -> %d", small, large)
	}
}

func TestWelcomeBytesPositive(t *testing.T) {
	s := classical(t)
	b, err := MeasureWelcomeBytes(s, 16)
	if err != nil {
		t.Fatal(err)
	}
	if b <= 0 {
		t.Fatalf("welcome bytes = %d, want > 0", b)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c go test ./bench/ -run TestBuildGroupHasMMembers -v`
Expected: FAIL — `bench` package / `BuildGroup` undefined.

- [ ] **Step 3: Write the implementation**

`bench/bench.go`:

```go
// Package bench measures deterministic per-event MLS size constants (commit and
// welcome bytes as a function of members-per-VNI M) and provides testing.B CPU
// benchmarks. The byte measurements are deterministic and feed the scaling
// model (see scaling/); the CPU benchmarks are machine-dependent and reporting
// only. Stdlib-only.
package bench

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/tree"
)

// Op selects which membership operation's commit to size.
type Op int

const (
	OpUpdate Op = iota // empty PCS rekey commit
	OpAdd              // commit adding one member
	OpRemove           // commit removing one member
)

func life() tree.Lifetime { return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)} }

func cred(id string) tree.Credential {
	return tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte(id)}
}

func newSigner() crypto.Signer {
	_, s, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return s
}

func keyPackage(s cipher.Suite, id string) group.KeyPackage {
	kp, _, _, err := group.NewKeyPackage(s, cred(id), newSigner(), life())
	if err != nil {
		panic(err)
	}
	return kp
}

// BuildGroup returns a committer's Group whose ratchet tree holds exactly M
// members (founder + M-1 added in a single commit, applied to the committer's
// own state). M must be >= 1.
func BuildGroup(s cipher.Suite, M int) (*group.Group, error) {
	if M < 1 {
		return nil, fmt.Errorf("M must be >= 1, got %d", M)
	}
	g, err := group.NewGroup(s, []byte("bench-group"), cred("founder"), newSigner(), life())
	if err != nil {
		return nil, err
	}
	if M == 1 {
		return g, nil
	}
	adds := make([]group.Proposal, 0, M-1)
	for i := 1; i < M; i++ {
		adds = append(adds, group.ProposeAdd(keyPackage(s, fmt.Sprintf("m-%d", i))))
	}
	if _, _, err := g.Commit(group.CommitOptions{ByValue: adds}); err != nil {
		return nil, err
	}
	return g, nil
}

// MeasureCommitBytes returns the wire size of the named op's commit on a fresh
// M-member group.
func MeasureCommitBytes(s cipher.Suite, M int, op Op) (int, error) {
	g, err := BuildGroup(s, M)
	if err != nil {
		return 0, err
	}
	var opts group.CommitOptions
	switch op {
	case OpUpdate:
		// empty commit
	case OpAdd:
		opts.ByValue = []group.Proposal{group.ProposeAdd(keyPackage(s, "joiner"))}
	case OpRemove:
		leaves := g.ActiveLeaves()
		if len(leaves) < 2 {
			return 0, fmt.Errorf("need >=2 members to remove, have %d", len(leaves))
		}
		// leaves[0] is the founder/committer; remove another.
		opts.ByValue = []group.Proposal{group.ProposeRemove(leaves[1])}
	default:
		return 0, fmt.Errorf("unknown op %d", op)
	}
	commit, _, err := g.Commit(opts)
	if err != nil {
		return 0, err
	}
	return len(commit), nil
}

// MeasureWelcomeBytes returns the wire size of the Welcome produced when adding
// one member to an M-member group — a proxy for a joiner's imported group state.
func MeasureWelcomeBytes(s cipher.Suite, M int) (int, error) {
	g, err := BuildGroup(s, M)
	if err != nil {
		return 0, err
	}
	_, welcome, err := g.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(keyPackage(s, "joiner"))},
	})
	if err != nil {
		return 0, err
	}
	return len(welcome), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c go test ./bench/ -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add bench/bench.go bench/bench_test.go
git commit -m "bench: deterministic MLS commit/welcome byte constants over M"
```

---

## Task 2: Tier-1 CPU benchmarks (reporting only)

**Files:**
- Modify: `bench/bench_test.go` (append benchmarks)

- [ ] **Step 1: Add the benchmarks**

Append to `bench/bench_test.go`:

```go
// benchSuites are the suites we characterize: classical (0x0001) and PQ X-Wing.
func benchSuites(b *testing.B) map[string]cipher.Suite {
	b.Helper()
	out := map[string]cipher.Suite{}
	for name, id := range map[string]cipher.CipherSuite{
		"classical": cipher.X25519_AES128GCM_SHA256_Ed25519,
		"xwing":     cipher.XWING_AES256GCM_SHA256_Ed25519,
	} {
		s, ok := cipher.Lookup(id)
		if !ok {
			b.Fatalf("suite %s not registered", name)
		}
		out[name] = s
	}
	return out
}

// BenchmarkCommitUpdate measures committer cpu_per_commit(M) for an empty PCS
// rekey across suites and sizes. Machine-dependent; reporting only.
func BenchmarkCommitUpdate(b *testing.B) {
	for name, s := range benchSuites(b) {
		for _, M := range []int{2, 8, 32, 128} {
			b.Run(fmt.Sprintf("%s/M=%d", name, M), func(b *testing.B) {
				g, err := BuildGroup(s, M)
				if err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, _, err := g.Commit(group.CommitOptions{}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkApply measures cpu_per_apply(M): a member processing one Update
// commit. Rebuilds a pristine follower per op via a fresh committer commit.
func BenchmarkApply(b *testing.B) {
	for name, s := range benchSuites(b) {
		for _, M := range []int{2, 8, 32, 128} {
			b.Run(fmt.Sprintf("%s/M=%d", name, M), func(b *testing.B) {
				committer, err := BuildGroup(s, M)
				if err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					commit, _, err := committer.Commit(group.CommitOptions{})
					if err != nil {
						b.Fatal(err)
					}
					follower, err := BuildGroup(s, M)
					if err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
					// A fresh M-member follower at epoch 1 processes the update.
					_ = follower.ProcessCommit(nil, commit)
				}
			})
		}
	}
}
```

Note: `fmt` and `group` are already imported by the test file (add them to the import block if not present — the test uses `fmt.Sprintf` and `group.CommitOptions`).

- [ ] **Step 2: Run the benchmarks briefly to verify they build and run**

Run: `nix develop -c go test ./bench/ -run '^$' -bench BenchmarkCommitUpdate -benchtime 3x`
Expected: benchmark output lines for `classical/M=2 … xwing/M=128`; no failures. (X-Wing rows should show visibly larger ns/op than classical — the PQ cost.)

- [ ] **Step 3: Verify the full package still passes normal tests**

Run: `nix develop -c go test ./bench/`
Expected: PASS (benchmarks are skipped without `-bench`).

- [ ] **Step 4: Commit**

```bash
git add bench/bench_test.go
git commit -m "bench: cpu_per_commit / cpu_per_apply benchmarks (classical + X-Wing)"
```

---

## Task 3: Tier-2 scaling model core (MLS projection)

**Files:**
- Create: `scaling/model.go`
- Test: `scaling/model_test.go`

- [ ] **Step 1: Write the failing test**

`scaling/model_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c go test ./scaling/ -run TestDensityIsVMoverH -v`
Expected: FAIL — `scaling` package / `Params` undefined.

- [ ] **Step 3: Write the implementation**

`scaling/model.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c go test ./scaling/ -v`
Expected: PASS (all four tests).

- [ ] **Step 5: Commit**

```bash
git add scaling/model.go scaling/model_test.go
git commit -m "scaling: MLS load projection (density-bounded host, Sigma-bound reflector)"
```

---

## Task 4: Tier-2 IKEv2 analytical overlay

**Files:**
- Modify: `scaling/model.go` (append `IKEv2Projection` + `IKEv2Project`)
- Modify: `scaling/model_test.go` (append tests)

- [ ] **Step 1: Write the failing test**

Append to `scaling/model_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c go test ./scaling/ -run TestIKEv2 -v`
Expected: FAIL — `IKEv2Project` undefined.

- [ ] **Step 3: Write the implementation**

Append to `scaling/model.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c go test ./scaling/ -v`
Expected: PASS (all model + IKEv2 tests).

- [ ] **Step 5: Commit**

```bash
git add scaling/model.go scaling/model_test.go
git commit -m "scaling: analytical pairwise-IKEv2 overlay for head-to-head"
```

---

## Task 5: Tier-2 sweep + CSV + knee detection

**Files:**
- Create: `scaling/sweep.go`
- Test: `scaling/sweep_test.go`

- [ ] **Step 1: Write the failing test**

`scaling/sweep_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c go test ./scaling/ -run TestSweepEmitsRowPerPoint -v`
Expected: FAIL — `Sweep` undefined.

- [ ] **Step 3: Write the implementation**

`scaling/sweep.go`:

```go
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

// Knee returns the smallest V at which the reflector saturates (across all H in
// the rows). found=false if nothing saturates.
func Knee(rows []Row) (v int, found bool) {
	best := 0
	for _, r := range rows {
		if r.MLS.ReflectorSaturated && (!found || r.V < best) {
			best, found = r.V, true
		}
	}
	return best, found
}

// CSV renders rows as CSV with a stable header. Values use %g for compactness.
func CSV(rows []Row) string {
	var b strings.Builder
	b.WriteString("H,V,M,density,reflector_fwd_bytes_per_s,reflector_order_ops_per_s," +
		"host_apply_per_s,host_cpu_frac_busy,reflector_saturated," +
		"ikev2_establish_handshakes,ikev2_steady_handshakes_per_s\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%d,%d,%d,%g,%g,%g,%g,%g,%t,%g,%g\n",
			r.H, r.V, r.M, r.MLS.Density,
			r.MLS.ReflectorFwdBytesPerSec, r.MLS.ReflectorOrderOpsPerSec,
			r.MLS.HostApplyPerSec, r.MLS.HostCPUFracBusy, r.MLS.ReflectorSaturated,
			r.IKEv2.EstablishHandshakes, r.IKEv2.HandshakesPerSecSteady)
	}
	return b.String()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c go test ./scaling/ -v`
Expected: PASS (sweep + knee + CSV tests, plus the earlier model tests).

- [ ] **Step 5: Commit**

```bash
git add scaling/sweep.go scaling/sweep_test.go
git commit -m "scaling: (H,V) sweep, CSV emit, and reflector-saturation knee"
```

---

## Task 6: Tier-2 CLI (`cmd/scalebench`)

**Files:**
- Create: `cmd/scalebench/main.go`
- Test: `cmd/scalebench/main_test.go`

- [ ] **Step 1: Write the failing test**

`cmd/scalebench/main_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestRunProducesCSVAndVerdict(t *testing.T) {
	out, err := run(config{
		M: 20, hosts: []int{1000, 10000}, vnis: []int{1000, 100000},
		rekeySeconds: 3600, moveSeconds: 600, fwdBudgetMBps: 100,
		suiteID: 0x0001,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "H,V,M,") {
		t.Fatal("expected CSV header in output")
	}
	if !strings.Contains(out, "VERDICT") {
		t.Fatal("expected a verdict line in output")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c go test ./cmd/scalebench/ -v`
Expected: FAIL — `run` / `config` undefined.

- [ ] **Step 3: Write the implementation**

`cmd/scalebench/main.go`:

```go
// scalebench measures MLS per-event byte constants and projects reflector and
// host control-plane load across a datacenter envelope (single reflector, S=1),
// with an analytical pairwise-IKEv2 overlay. It prints a CSV sweep and a
// one-line fit verdict.
//
// Usage:
//
//	scalebench [-m 20] [-suite 0x0001] [-rekey-s 3600] [-move-s 600]
//	           [-fwd-budget-mbps 100] [-hosts 1000,10000] [-vnis 1e3,1e4,1e5]
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/trevex/mls-go/bench"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/scaling"
)

type config struct {
	M             int
	hosts, vnis   []int
	rekeySeconds  float64
	moveSeconds   float64
	fwdBudgetMBps float64
	suiteID       uint16
}

// run measures the commit-byte constant for cfg.M and returns the CSV + verdict.
func run(cfg config) (string, error) {
	suite, ok := cipher.Lookup(cipher.CipherSuite(cfg.suiteID))
	if !ok {
		return "", fmt.Errorf("ciphersuite %#x not registered", cfg.suiteID)
	}
	bytesPerCommit, err := bench.MeasureCommitBytes(suite, cfg.M, bench.OpUpdate)
	if err != nil {
		return "", fmt.Errorf("measuring commit bytes: %w", err)
	}
	base := scaling.Params{
		M: cfg.M, S: 1,
		RRekey:               1.0 / cfg.rekeySeconds,
		LambdaMove:           1.0 / cfg.moveSeconds,
		BytesPerCommit:       bytesPerCommit,
		FwdBudgetBytesPerSec: cfg.fwdBudgetMBps * 1e6,
	}
	rows := scaling.Sweep(base, cfg.hosts, cfg.vnis)

	var b strings.Builder
	fmt.Fprintf(&b, "# suite=%#x M=%d bytes_per_commit=%d rekey=%.0fs move=%.0fs budget=%.0fMB/s S=1\n",
		cfg.suiteID, cfg.M, bytesPerCommit, cfg.rekeySeconds, cfg.moveSeconds, cfg.fwdBudgetMBps)
	b.WriteString(scaling.CSV(rows))
	if knee, found := scaling.Knee(rows); found {
		fmt.Fprintf(&b, "VERDICT: single reflector saturates at V=%d VNIs (budget %.0f MB/s) — trigger for deferred sharding\n",
			knee, cfg.fwdBudgetMBps)
	} else {
		b.WriteString("VERDICT: single reflector stays under budget across the swept envelope — MLS fits at S=1\n")
	}
	return b.String(), nil
}

func parseIntList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f, err := strconv.ParseFloat(part, 64) // accept 1e5 forms
		if err != nil {
			return nil, fmt.Errorf("bad integer %q: %w", part, err)
		}
		out = append(out, int(f))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	return out, nil
}

func main() {
	m := flag.Int("m", 20, "mean members per VNI")
	suite := flag.String("suite", "0x0001", "ciphersuite id (0x0001 classical, 0xF001 X-Wing)")
	rekey := flag.Float64("rekey-s", 3600, "PCS rekey interval per VNI, seconds")
	move := flag.Float64("move-s", 600, "mean seconds between membership changes per VNI")
	budget := flag.Float64("fwd-budget-mbps", 100, "reflector forwarding budget, MB/s")
	hosts := flag.String("hosts", "1000,10000", "comma list of host counts")
	vnis := flag.String("vnis", "1e3,1e4,1e5", "comma list of VNI counts")
	flag.Parse()

	sid, err := strconv.ParseUint(strings.TrimPrefix(*suite, "0x"), 16, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scalebench: bad -suite %q: %v\n", *suite, err)
		os.Exit(2)
	}
	hs, err := parseIntList(*hosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scalebench: -hosts: %v\n", err)
		os.Exit(2)
	}
	vs, err := parseIntList(*vnis)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scalebench: -vnis: %v\n", err)
		os.Exit(2)
	}
	out, err := run(config{
		M: *m, hosts: hs, vnis: vs,
		rekeySeconds: *rekey, moveSeconds: *move, fwdBudgetMBps: *budget,
		suiteID: uint16(sid),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "scalebench: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(out)
}
```

- [ ] **Step 4: Run test + a manual smoke run**

Run: `nix develop -c go test ./cmd/scalebench/ -v`
Expected: PASS.

Run: `nix develop -c go run ./cmd/scalebench -m 20 -suite 0xF001 -fwd-budget-mbps 50`
Expected: a comment header, CSV rows, and a `VERDICT:` line (X-Wing's larger commit bytes should push the knee to a smaller V than classical).

- [ ] **Step 5: Commit**

```bash
git add cmd/scalebench/main.go cmd/scalebench/main_test.go
git commit -m "scalebench: CLI measuring commit constants and projecting the sweep + verdict"
```

---

## Task 7: Tier-3 sim — leave + migration churn

**Files:**
- Modify: `sim/scenario.go`
- Test: `sim/migration_test.go`

Context: `sim/sim.go`'s `dispatchChurn` already handles `ChurnOp{Join: false}` (it deletes the member from `desired`/`intended` and triggers a committer reconcile → a Remove commit; the removed client hits `ErrSelfRemoved` → `leaveVNI`). The gap is only that no scenario generates leaves. A VM migration = a member leaving on its old host + a non-member joining on the new host, modeled as two `ChurnOp`s. The founder (`client-0`) is the committer of every channel and must never leave.

- [ ] **Step 1: Write the failing test**

`sim/migration_test.go`:

```go
package sim

import "testing"

func TestMigrationChurnConverges(t *testing.T) {
	r := Run(MigrationChurn(), 1)
	if !r.InvariantsHeld {
		t.Fatalf("migration_churn invariants failed: %s", failureSummary(r))
	}
	// A migration issues Remove commits; assert some leaves actually happened by
	// checking commits were produced (removes + adds both commit).
	if r.Metrics.CommitMsgs == 0 {
		t.Fatal("migration scenario produced no commits")
	}
}

func TestMigrationChurnDeterministic(t *testing.T) {
	a := Run(MigrationChurn(), 5)
	b := Run(MigrationChurn(), 5)
	if len(a.Trace) != len(b.Trace) {
		t.Fatalf("trace length mismatch: %d vs %d", len(a.Trace), len(b.Trace))
	}
	for i := range a.Trace {
		if a.Trace[i] != b.Trace[i] {
			t.Fatalf("trace diverged at %d", i)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c go test ./sim/ -run TestMigrationChurn -v`
Expected: FAIL — `MigrationChurn` undefined.

- [ ] **Step 3: Write the implementation**

Add to `sim/scenario.go` (after `EncryptedChurn`):

```go
// migrationPlan models VM migration across hosts: for each VNI, hosts 1 and 2
// initially hold a VM (join), then each VM migrates to a new host (the old host
// leaves, a spare host joins). The founder (client 0) is the committer and never
// migrates. Requires clients >= 5 (0 founder, 1-2 initial, 3-4 destinations).
func migrationPlan(vnis int) []ChurnOp {
	var ops []ChurnOp
	for v := 0; v < vnis; v++ {
		vv := uint32(v)
		// initial placement
		ops = append(ops, ChurnOp{Join: true, Client: 1, VNI: vv})
		ops = append(ops, ChurnOp{Join: true, Client: 2, VNI: vv})
	}
	for v := 0; v < vnis; v++ {
		vv := uint32(v)
		// migrate host1's VM -> host3, host2's VM -> host4 (leave src, join dst)
		ops = append(ops, ChurnOp{Join: false, Client: 1, VNI: vv})
		ops = append(ops, ChurnOp{Join: true, Client: 3, VNI: vv})
		ops = append(ops, ChurnOp{Join: false, Client: 2, VNI: vv})
		ops = append(ops, ChurnOp{Join: true, Client: 4, VNI: vv})
	}
	return ops
}

// MigrationChurn exercises leave + join membership churn modeling VM migration
// across hosts. Asserts the dual-redundancy invariants still hold under removes.
func MigrationChurn() Scenario {
	s := base("migration_churn", 5, 2)
	s.Churn = migrationPlan(2)
	return s
}
```

Register it in `ByName` so the CLI can run it. Change the `ByName` loop source from `append(All(), NegativeControl())` to also include the migration scenario:

```go
func ByName(name string) (Scenario, bool) {
	for _, s := range append(All(), NegativeControl(), MigrationChurn()) {
		if s.Name == name {
			return s, true
		}
	}
	return Scenario{}, false
}
```

Leave `All()` unchanged for now (the migration scenario is validated by its own test; promote it into `All()` in a follow-up once it has soaked). Add a one-line comment above `All()` noting this.

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c go test ./sim/ -run TestMigrationChurn -v`
Expected: PASS.

If invariants FAIL: this is real signal that the sim's leave path has a defect (not a test bug). Debug with `systematic-debugging` — inspect whether the removed client's SA cache / membership expectation is handled. Do not weaken the invariant to make it pass.

- [ ] **Step 5: Run the whole sim suite to confirm no regressions**

Run: `nix develop -c go test ./sim/`
Expected: PASS (existing scenarios unaffected).

- [ ] **Step 6: Commit**

```bash
git add sim/scenario.go sim/migration_test.go
git commit -m "sim: leave + VM-migration churn scenario (migration_churn)"
```

---

## Task 8: Tier-3 sim — per-actor / per-tick rate + convergence metrics

**Files:**
- Modify: `sim/metrics.go`
- Modify: `sim/client.go`
- Modify: `sim/sim.go`
- Test: `sim/rate_test.go`

- [ ] **Step 1: Write the failing test**

`sim/rate_test.go`:

```go
package sim

import "testing"

func TestRateMetricsPopulated(t *testing.T) {
	r := Run(Nominal(), 1)
	m := r.Metrics
	if m.CommitsIssued == 0 {
		t.Fatal("no commits issued")
	}
	if m.CommitsApplied == 0 {
		t.Fatal("no commits applied")
	}
	if m.CommitDeliveries < m.CommitsApplied {
		t.Fatalf("deliveries (%d) should be >= applied (%d)", m.CommitDeliveries, m.CommitsApplied)
	}
	if m.Horizon == 0 {
		t.Fatal("horizon (max tick) not recorded")
	}
}

func TestFanoutAmplificationExceedsOne(t *testing.T) {
	// Each issued commit is fanned out to multiple subscribers, so realized
	// deliveries per issued commit must exceed 1 in a multi-member scenario.
	r := Run(Nominal(), 1)
	amp := r.Metrics.FanoutAmplification()
	if amp <= 1.0 {
		t.Fatalf("fanout amplification = %v, want > 1", amp)
	}
}

func TestConvergenceTicksRecorded(t *testing.T) {
	r := Run(Nominal(), 1)
	if r.Metrics.MaxConvergeTicks == 0 {
		t.Fatal("expected a positive worst-case commit convergence gap")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c go test ./sim/ -run TestRateMetricsPopulated -v`
Expected: FAIL — `CommitsIssued` etc. undefined.

- [ ] **Step 3: Extend `Metrics`**

In `sim/metrics.go`, add fields to the `Metrics` struct (after `PlaintextHandshakeExposures`):

```go
	// Per-actor / per-tick control-plane rate accounting (Tier-3 scaling metrics).
	CommitsIssued    int    // commits a committer originated (new heads, not resends)
	CommitDeliveries int    // commit envelopes delivered to client actors (realized fan-out)
	CommitsApplied   int    // successful HandleCommit at a member
	Horizon          uint64 // max event tick reached (rate denominator)
	MaxConvergeTicks uint64 // worst-case (applyTick - issueTick) over all commits

	convIssuedAt map[string]uint64 // channel:epoch -> issue tick (convergence tracking)
```

Update `newMetrics` to initialize the map:

```go
func newMetrics() *Metrics {
	return &Metrics{
		cpuNanos:     map[string]int64{},
		cpuCount:     map[string]int64{},
		convIssuedAt: map[string]uint64{},
	}
}
```

Add helper methods (anywhere in `metrics.go`):

```go
// FanoutAmplification is realized commit deliveries per issued commit (the
// reflector's M-1 fan-out factor, measured).
func (m *Metrics) FanoutAmplification() float64 {
	if m.CommitsIssued == 0 {
		return 0
	}
	return float64(m.CommitDeliveries) / float64(m.CommitsIssued)
}

func convKey(ch uint32, epoch uint64) string {
	return fmt.Sprintf("%d:%d", ch, epoch)
}

// commitIssued records the tick a committer produced the commit for (ch, epoch).
func (m *Metrics) commitIssued(ch uint32, epoch, tick uint64) {
	k := convKey(ch, epoch)
	if _, seen := m.convIssuedAt[k]; !seen {
		m.convIssuedAt[k] = tick
	}
}

// commitConverged records a member applying (ch, epoch) at tick, updating the
// worst-case convergence gap.
func (m *Metrics) commitConverged(ch uint32, epoch, tick uint64) {
	if issued, ok := m.convIssuedAt[convKey(ch, epoch)]; ok && tick >= issued {
		if gap := tick - issued; gap > m.MaxConvergeTicks {
			m.MaxConvergeTicks = gap
		}
	}
}
```

Add report rows in `Report()` (after the plaintext-exposures line):

```go
	_, _ = fmt.Fprintf(w, "commits-issued\t%d\n", m.CommitsIssued)
	_, _ = fmt.Fprintf(w, "commit-deliveries\t%d\n", m.CommitDeliveries)
	_, _ = fmt.Fprintf(w, "commits-applied\t%d\n", m.CommitsApplied)
	_, _ = fmt.Fprintf(w, "fanout-amplification\t%.2f\n", m.FanoutAmplification())
	_, _ = fmt.Fprintf(w, "max-converge-ticks\t%d\n", m.MaxConvergeTicks)
	_, _ = fmt.Fprintf(w, "horizon\t%d\n", m.Horizon)
```

- [ ] **Step 4: Increment the counters in `client.go`**

In `sendCommit`, record issue + count (the committer's new head — the epoch produced is `base+1`):

```go
func (c *Client) sendCommit(ch uint32, base uint64, msg []byte) {
	c.toReflector(ch, Envelope{
		VNI:     ch,
		Type:    MsgCommit,
		Base:    base,
		Payload: msg,
		Hash:    contentHash(msg),
	})
	c.metrics.commitFanout(len(msg), 1)
	c.metrics.CommitsIssued++
	c.metrics.commitIssued(ch, base+1, c.sched.Now())
}
```

In `onCommit`, count every inbound commit delivery and every successful apply. Add at the very top of `onCommit` (before the `st == nil` guard):

```go
	c.metrics.CommitDeliveries++
```

And in the `case err == nil:` branch (after `c.cacheCurrentSA(env.VNI)`):

```go
		c.metrics.CommitsApplied++
		c.metrics.commitConverged(env.VNI, st.ctrl.Epoch(), c.sched.Now())
```

In `onLogReply`, count catch-up applies too — in the `if err := ...HandleCommit; err == nil` branch (after `c.cacheCurrentSA`):

```go
			c.metrics.CommitsApplied++
			c.metrics.commitConverged(env.VNI, st.ctrl.Epoch(), c.sched.Now())
```

- [ ] **Step 5: Record the horizon in `sim.go`**

In `Run`'s main loop, track the max tick. Replace the loop body's dispatch line region:

```go
	for {
		e, ok := s.Pop()
		if !ok {
			break
		}
		if e.At > metrics.Horizon {
			metrics.Horizon = e.At
		}
		trace = append(trace, w.dispatch(e))
		if s.Now() >= w.settleDeadline && !w.faultsLifted {
			w.faults.liftAll()
			w.faultsLifted = true
		}
	}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `nix develop -c go test ./sim/ -run 'TestRateMetricsPopulated|TestFanoutAmplificationExceedsOne|TestConvergenceTicksRecorded' -v`
Expected: PASS.

- [ ] **Step 7: Update the determinism test allow-list**

`sim/sim_test.go`'s `TestDeterminism` snapshots deterministic counters. Add the new integer counters to `deterministicMetrics` and `snap` so same-seed runs are still asserted identical:

Add fields to the `deterministicMetrics` struct: `CommitsIssued, CommitDeliveries, CommitsApplied int` and `Horizon, MaxConvergeTicks uint64`. Add the matching values to the `snap` return. (Do not add `cpuNanos`; those stay excluded.)

- [ ] **Step 8: Run the full sim suite**

Run: `nix develop -c go test ./sim/`
Expected: PASS (determinism test still green with the new counters).

- [ ] **Step 9: Commit**

```bash
git add sim/metrics.go sim/client.go sim/sim.go sim/rate_test.go sim/sim_test.go
git commit -m "sim: per-actor commit rate, fan-out amplification, convergence-gap metrics"
```

---

## Task 9: Tier-2 ↔ Tier-3 validation

**Files:**
- Test: `sim/validation_test.go`

This closes the loop: the sim's *realized* fan-out (measured by the real bus over the real stack) must match the model's `(M-1)` amplification term, validating that `scaling.Project`'s structural assumption is faithful. We compare against the sim's own membership rather than a hardcoded M, since membership varies over the run.

- [ ] **Step 1: Write the validation test**

`sim/validation_test.go`:

```go
package sim

import "testing"

// TestFanoutMatchesModelStructure validates the Tier-2 reflector_fwd formula's
// (M-1) fan-out term against the Tier-3 real-stack sim: realized commit
// deliveries per issued commit should track the mean subscriber count, which is
// what scaling.Project multiplies bytes_per_commit by. We assert the measured
// amplification is within the plausible band [1, maxMembers] — i.e. every issued
// commit reaches multiple members and never more than the whole group.
func TestFanoutMatchesModelStructure(t *testing.T) {
	sc := Nominal() // 5 clients, 2 VNIs, dual replica ⇒ small bounded membership
	r := Run(sc, 1)
	amp := r.Metrics.FanoutAmplification()

	// Realized deliveries per issued commit: fan-out reaches multiple members so
	// amp > 1. The upper band is loose — reflector re-reflects on any resend
	// (heartbeat-driven), so deliveries per *newly issued* commit can exceed the
	// live member count; 3× Clients is a generous sanity ceiling, not a tight
	// bound. The point is structural: fan-out happens and is member-scaled.
	if amp <= 1.0 || amp > float64(sc.Clients)*3 {
		t.Fatalf("fanout amplification %v outside (1, %d] — model (M-1) term not matched by real fan-out",
			amp, sc.Clients*3)
	}
}

// TestReflectorForwardsScaleWithMembership sanity-checks that a larger member
// set yields more realized deliveries per commit than a smaller one — the
// monotonicity the reflector_fwd ∝ (M-1) term predicts.
func TestReflectorForwardsScaleWithMembership(t *testing.T) {
	small := Run(withClients(Nominal(), 3), 1)
	large := Run(withClients(Nominal(), 8), 1)
	if large.Metrics.FanoutAmplification() <= small.Metrics.FanoutAmplification() {
		t.Fatalf("expected fan-out to grow with membership: small=%v large=%v",
			small.Metrics.FanoutAmplification(), large.Metrics.FanoutAmplification())
	}
}

func withClients(s Scenario, clients int) Scenario {
	s.Clients = clients
	s.Churn = churnPlan(clients, s.VNIs)
	return s
}
```

- [ ] **Step 2: Run the test**

Run: `nix develop -c go test ./sim/ -run 'TestFanoutMatchesModelStructure|TestReflectorForwardsScaleWithMembership' -v`
Expected: PASS.

If `TestReflectorForwardsScaleWithMembership` is flaky across the churn schedule, adjust by comparing at a fixed seed only (it already fixes seed 1); if genuinely non-monotone, investigate whether `churnPlan` actually adds more members at `clients=8` (it should — one join per non-founder per VNI).

- [ ] **Step 3: Commit**

```bash
git add sim/validation_test.go
git commit -m "sim: validate model (M-1) fan-out term against real-stack realized deliveries"
```

---

## Task 10: Results write-up + Makefile targets

**Files:**
- Create: `docs/scaling-results.md`
- Modify: `Makefile`

- [ ] **Step 1: Add Makefile targets**

The Makefile uses `NIX ?= nix develop -c` (line 15) and a single `.PHONY:` line (line 20) plus `target: ## help` convention. Add `bench` and `scalebench` to the `.PHONY` list, then add two targets mirroring the `sim:` target's style:

```makefile
bench: ## Run the Tier-1 MLS crypto micro-benchmarks (commit/apply, all suites)
	$(NIX) go test ./bench/ -run '^$$' -bench . -benchmem

scalebench: ## Project the datacenter scaling sweep + verdict (classical + X-Wing)
	$(NIX) go run ./cmd/scalebench -suite 0x0001
	$(NIX) go run ./cmd/scalebench -suite 0xF001
```

Edit the existing `.PHONY: help test kat race vet fmt fmt-check lint conformance generate check-zero-dep e2e-openmls sim clean` line to append ` bench scalebench`.

- [ ] **Step 2: Verify the targets run**

Run: `nix develop -c make scalebench`
Expected: two CSV blocks (classical then X-Wing) each ending in a `VERDICT:` line.

Run: `nix develop -c make bench`
Expected: benchmark output for both suites across M.

- [ ] **Step 3: Write the results doc**

Create `docs/scaling-results.md` capturing:
- The measured Tier-1 constants table: `bytes_per_commit(M)` and `bytes_per_welcome(M)` for classical + X-Wing at M ∈ {2,8,32,128} (fill from `nix develop -c go test ./bench/ -run '^$' -bench . -benchmem` and a short throwaway that prints `bench.MeasureCommitBytes`), and representative `ns/op` for commit/apply.
- The Tier-2 verdict numbers from `make scalebench`: the V-knee at S=1 for both suites at the default budget, and the host density D at the datacenter corner (H=10⁴, V=10⁵, M=20 ⇒ D=200).
- The three fit-verdict numbers from the design spec: host load density-bounded (flat in V), reflector load linear in V with its knee, and the sim's `max-converge-ticks` vs churn inter-arrival from `nix develop -c go run ./cmd/metalsim -scenario migration_churn`.
- A short paragraph connecting back to `comment.md`'s scaling section: the measured constants that replace the `O()` terms, and whether the datacenter envelope sits below or above the single-reflector knee.

Keep it factual and sourced from actual command output (use `verification-before-completion` — paste real numbers, do not estimate).

- [ ] **Step 4: Commit**

```bash
git add docs/scaling-results.md Makefile
git commit -m "docs: scaling benchmark results + make bench/scalebench targets"
```

---

## Final verification (after all tasks)

Run the full gate to confirm no regressions:

```bash
nix develop -c make test          # root module suite (incl. sim, scaling, bench)
nix develop -c make check-zero-dep # root stays stdlib-only (bench/scaling/scalebench included)
nix develop -c go vet ./...
nix develop -c make scalebench    # produces the headline verdict
```

Expected: all green; `scalebench` prints the datacenter verdict for both suites.

Then dispatch the final whole-implementation code review and use `superpowers:finishing-a-development-branch`.
