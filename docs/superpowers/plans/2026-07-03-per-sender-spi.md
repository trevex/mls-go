# Per-Sender SPI & Multi-Sender Anti-Replay — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give each VNI sender its own ESP SPI (derived from the MLS leaf index) so every sender gets an independent RFC 4303 anti-replay window — the GDOI/G-IKEv2 group-SA model — and validate it in the sim with a shared-SPI negative control.

**Architecture:** Additive `ironcore` SA changes (`SenderSPI(leaf)`, `OwnSPI`, `InboundSAs`) leaving the existing group `SA.SPI` intact; then the `sim` data plane migrates to per-sender SPIs + per-SPI replay windows, with a shared-SPI negative control proving replay drops appear when senders collide.

**Tech Stack:** Go, stdlib-only root module, `nix develop -c`. Design spec: `docs/superpowers/specs/2026-07-03-per-sender-spi-design.md`.

## Conventions (all tasks)
- Run every Go command via `nix develop -c <cmd>`. Root module is stdlib-only.
- Keep changes additive where noted so each task's tests (and the whole suite) stay green.

---

## Task 1: ironcore — per-sender SPI derivation (`SenderSPI`, `OwnSPI`)

**Files:** Modify `ironcore/sa.go`; Test: `ironcore/sa_test.go` (append).

Context: `ironcore/sa.go` already has `deriveSPI(suite, kGroup, vni, epoch)` (group SPI, low byte = epoch, MSB set) and `SenderSalt(leaf)`. `DeriveSAKeys` builds the `SA{VNI,Epoch,SPI,Key,OwnLeaf,OwnSalt,saltMask,suite}`. `cipher.Suite.ExpandWithLabel(secret, label, context, length)` is available.

- [ ] **Step 1: Write the failing test** — append to `ironcore/sa_test.go`:

```go
func TestSenderSPIPerSender(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}
	const vni = uint32(0xF001)
	alice, bob, carol := build3MemberGroup(t, suite, ironcore.GroupID(vni))
	sa, err := ironcore.DeriveSAKeys(alice, vni)
	if err != nil {
		t.Fatal(err)
	}
	// (a) distinct senders → distinct SPIs; all > 255 and MSB set (epoch low byte retained).
	spis := map[uint32]uint32{}
	for _, leaf := range []uint32{0, 1, 2} {
		s, err := sa.SenderSPI(leaf)
		if err != nil {
			t.Fatalf("SenderSPI(%d): %v", leaf, err)
		}
		if s <= 255 {
			t.Fatalf("SenderSPI(%d)=%d not > 255", leaf, s)
		}
		if uint8(s) != uint8(sa.Epoch) {
			t.Fatalf("SenderSPI(%d) low byte %d != epoch low byte %d", leaf, uint8(s), uint8(sa.Epoch))
		}
		spis[leaf] = s
	}
	if spis[0] == spis[1] || spis[0] == spis[2] || spis[1] == spis[2] {
		t.Fatalf("SenderSPI not distinct across senders: %v", spis)
	}
	// (b) all members compute the SAME SPI for a given sender leaf (shared K_group).
	saBob, _ := ironcore.DeriveSAKeys(bob, vni)
	saCarol, _ := ironcore.DeriveSAKeys(carol, vni)
	for _, leaf := range []uint32{0, 1, 2} {
		b, _ := saBob.SenderSPI(leaf)
		c, _ := saCarol.SenderSPI(leaf)
		if b != spis[leaf] || c != spis[leaf] {
			t.Fatalf("SenderSPI(%d) disagrees across members: alice=%d bob=%d carol=%d", leaf, spis[leaf], b, c)
		}
	}
	// (c) OwnSPI == SenderSPI(OwnLeaf).
	own, _ := sa.SenderSPI(sa.OwnLeaf)
	if sa.OwnSPI != own {
		t.Fatalf("OwnSPI=%d != SenderSPI(OwnLeaf)=%d", sa.OwnSPI, own)
	}
	// (d) the retained group SPI still exists and is leaf-independent.
	if sa.SPI <= 255 {
		t.Fatalf("group SPI %d not > 255", sa.SPI)
	}
}

func TestSenderSPIChangesWithEpoch(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	const vni = uint32(7)
	alice, bob, carol := build3MemberGroup(t, suite, ironcore.GroupID(vni))
	sa1, _ := ironcore.DeriveSAKeys(alice, vni)
	s1, _ := sa1.SenderSPI(1)
	commit, _, _ := alice.Commit(group.CommitOptions{})
	_ = bob.ProcessCommit(nil, commit)
	_ = carol.ProcessCommit(nil, commit)
	sa2, _ := ironcore.DeriveSAKeys(alice, vni)
	s2, _ := sa2.SenderSPI(1)
	if s1 == s2 {
		t.Fatal("SenderSPI did not change across epochs")
	}
}
```

- [ ] **Step 2: Run to confirm fail** — `nix develop -c go test ./ironcore/ -run TestSenderSPI -v` → FAIL (`SenderSPI`/`OwnSPI` undefined).

- [ ] **Step 3: Implement** in `ironcore/sa.go`:

Add a field to `SA` (after `OwnSalt`):
```go
	OwnSPI   uint32 // this member's own outbound ESP SPI = SenderSPI(OwnLeaf)
```

Add a leaf-aware SPI derivation + accessor:
```go
// spiContext encodes VNI‖epoch‖leaf as the 16-byte context for a per-sender SPI.
func spiContext(vni uint32, epoch uint64, leaf uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:4], vni)
	binary.BigEndian.PutUint64(b[4:12], epoch)
	binary.BigEndian.PutUint32(b[12:16], leaf)
	return b
}

// deriveSenderSPI derives sender `leaf`'s 32-bit ESP SPI from K_group. Like the
// group SPI it embeds the epoch low byte (make-before-break overlap demux) and
// forces the MSB (keep SPI > 255, RFC 4303 §2.1). The remaining 23 bits are a
// function of the leaf, so distinct senders get distinct SPIs w.h.p. (birthday
// bound ≈ M²/2²⁴ per epoch — negligible for realistic M; collisions among active
// members are detected in InboundSAs and resolved by a rekey).
func deriveSenderSPI(suite cipher.Suite, kGroup []byte, vni uint32, epoch uint64, leaf uint32) (uint32, error) {
	raw, err := suite.ExpandWithLabel(kGroup, "esp-spi-sender", spiContext(vni, epoch, leaf), 4)
	if err != nil {
		return 0, fmt.Errorf("ironcore: derive sender SPI: %w", err)
	}
	spi := binary.BigEndian.Uint32(raw)
	spi = (spi &^ 0xFF) | uint32(uint8(epoch))
	spi |= 0x80000000
	return spi, nil
}

// SenderSPI returns the per-sender outbound/inbound ESP SPI for sender leafIndex
// at this SA's epoch. All members compute identical values (shared K_group), so a
// receiver can install one inbound SA per sender keyed by this SPI.
func (sa SA) SenderSPI(leafIndex uint32) (uint32, error) {
	if len(sa.Key) == 0 {
		return 0, fmt.Errorf("ironcore: SA key not initialized (use DeriveSAKeys)")
	}
	return deriveSenderSPI(sa.suite, sa.Key, sa.VNI, sa.Epoch, leafIndex)
}
```

In `DeriveSAKeys`, after `sa.OwnSalt` is set, set `OwnSPI`:
```go
	if sa.OwnSPI, err = sa.SenderSPI(g.OwnLeaf()); err != nil {
		return SA{}, err
	}
```

Update the `SA.SPI` field comment to: `// group ESP SPI (leaf-independent; per-sender data planes use OwnSPI/SenderSPI)`.

- [ ] **Step 4: Run** — `nix develop -c go test ./ironcore/ -run 'TestSenderSPI|TestDeriveSAKeys' -v` → PASS (existing group-SPI test unaffected). Then `nix develop -c go test ./ironcore/ -count=1`, `nix develop -c go vet ./ironcore/`, `nix develop -c gofmt -l ironcore/sa.go` (no output).

- [ ] **Step 5: Commit** — `git add ironcore/sa.go ironcore/sa_test.go && git commit -m "ironcore: per-sender ESP SPI derivation (SenderSPI/OwnSPI)"`

---

## Task 2: ironcore — inbound SA set (`InboundSA`, `InboundSAs`) + collision detection

**Files:** Modify `ironcore/sa.go`, `ironcore/controller.go`; Test: `ironcore/sa_test.go` (append).

- [ ] **Step 1: Write the failing test** — append to `ironcore/sa_test.go`:

```go
func TestInboundSAsPerSender(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	const vni = uint32(0xF001)
	alice, _, _ := build3MemberGroup(t, suite, ironcore.GroupID(vni))
	sa, _ := ironcore.DeriveSAKeys(alice, vni)

	in, err := sa.InboundSAs([]uint32{0, 1, 2})
	if err != nil {
		t.Fatalf("InboundSAs: %v", err)
	}
	if len(in) != 3 {
		t.Fatalf("want 3 inbound SAs, got %d", len(in))
	}
	seenSPI := map[uint32]bool{}
	for _, s := range in {
		if len(s.Key) != 32 || len(s.Salt) != 4 {
			t.Fatalf("inbound SA leaf=%d bad key/salt len", s.Leaf)
		}
		if seenSPI[s.SPI] {
			t.Fatalf("duplicate inbound SPI %d", s.SPI)
		}
		seenSPI[s.SPI] = true
		wantSPI, _ := sa.SenderSPI(s.Leaf)
		wantSalt, _ := sa.SenderSalt(s.Leaf)
		if s.SPI != wantSPI || !bytes.Equal(s.Salt, wantSalt) || !bytes.Equal(s.Key, sa.Key) {
			t.Fatalf("inbound SA leaf=%d mismatch", s.Leaf)
		}
	}
}

func TestControllerInboundSAs(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	const vni = uint32(3)
	// founderNode (ironcore/controller_test.go) yields a joined 1-member *Controller.
	// Mirror an existing caller's args for `seq`/`resolve` (see TestControllerScaffold).
	ctrl := founderNode(t, suite, vni, "founder", <seq>, <resolve>)
	in, err := ctrl.InboundSAs()
	if err != nil {
		t.Fatalf("Controller.InboundSAs: %v", err)
	}
	if len(in) != 1 {
		t.Fatalf("founder InboundSAs len=%d, want 1", len(in))
	}
}
```

NOTE: `founderNode(t, suite, vni, name, seq, resolve, privacy...)` already exists in `ironcore/controller_test.go` and returns a joined `*ironcore.Controller`. Read an existing caller (e.g. `TestControllerScaffold`) to copy the exact `seq` (a `group.Ordering`) and `resolve` (`ironcore.KeyPackageResolver`) arguments — substitute them for the `<seq>`/`<resolve>` placeholders above. The assertion is only that a 1-member group yields exactly 1 inbound SA. If wiring `founderNode` is noisy, it is acceptable to instead cover `Controller.InboundSAs()` by adding two lines to an existing multi-member controller test (assert `len(InboundSAs()) == numMembers`); keep `TestInboundSAsPerSender` regardless.

- [ ] **Step 2: Run to confirm fail** — `nix develop -c go test ./ironcore/ -run 'TestInboundSAs|TestControllerInboundSAs' -v` → FAIL.

- [ ] **Step 3: Implement.** In `ironcore/sa.go`:

```go
// InboundSA is one per-sender ESP inbound security association: the data plane
// installs one of these per active member leaf so every sender occupies its own
// SPI and hence its own RFC 4303 anti-replay window.
type InboundSA struct {
	Leaf uint32 // sender's MLS leaf index
	SPI  uint32 // sender's per-sender SPI
	Key  []byte // shared K_group (32-byte AES-256-GCM key)
	Salt []byte // sender's 4-byte GCM nonce salt
}

// InboundSAs returns one InboundSA per leaf in leaves (typically the group's
// active member leaves). It returns an error if two leaves map to the same SPI
// (a birthday collision in the 23-bit SPI space); the caller resolves this by
// forcing a rekey, which reshuffles every SPI.
func (sa SA) InboundSAs(leaves []uint32) ([]InboundSA, error) {
	out := make([]InboundSA, 0, len(leaves))
	seen := make(map[uint32]uint32, len(leaves)) // spi -> leaf
	for _, leaf := range leaves {
		spi, err := sa.SenderSPI(leaf)
		if err != nil {
			return nil, err
		}
		if other, dup := seen[spi]; dup {
			return nil, fmt.Errorf("ironcore: SPI collision %#x between leaves %d and %d (rekey to resolve)", spi, other, leaf)
		}
		seen[spi] = leaf
		salt, err := sa.SenderSalt(leaf)
		if err != nil {
			return nil, err
		}
		out = append(out, InboundSA{Leaf: leaf, SPI: spi, Key: sa.Key, Salt: salt})
	}
	return out, nil
}
```

In `ironcore/controller.go`, add (near `CurrentSA`):
```go
// InboundSAs returns the per-sender inbound SAs for the current epoch — one per
// active member leaf. The data plane installs these so each sender has its own
// anti-replay window (design spec §10.4 / 2026-07-03-per-sender-spi).
func (c *Controller) InboundSAs() ([]InboundSA, error) {
	if c.g == nil {
		return nil, fmt.Errorf("ironcore: no group")
	}
	sa, err := c.CurrentSA()
	if err != nil {
		return nil, err
	}
	return sa.InboundSAs(c.g.ActiveLeaves())
}
```

- [ ] **Step 4: Run** — `nix develop -c go test ./ironcore/ -count=1`, vet, gofmt clean.

- [ ] **Step 5: Commit** — `git add ironcore/sa.go ironcore/controller.go ironcore/sa_test.go && git commit -m "ironcore: per-sender inbound SA set with collision detection"`

---

## Task 3: sim — per-sender sequence numbers + per-SPI anti-replay windows

**Files:** Modify `sim/event.go`, `sim/client.go`, `sim/metrics.go`, `sim/sim.go`, `sim/sim_test.go`; Test: `sim/replay_test.go` (new).

Context: `sim/client.go` `sendData`/`sendToReceiver` publish `Envelope{Type: MsgData, Src, Dst, Base: sendEpoch, SPI: sa.SPI}`. `onData` marks decryptable if any held `saCache[e].SPI == env.SPI`, else `checker.packetLoss`. `vniState` holds `saCache map[uint64]ironcore.SA`. Each client is a member (`st.ctrl.Group().ActiveLeaves()`), and `st.ctrl.CurrentSA()` yields an `ironcore.SA` with `OwnSPI`.

- [ ] **Step 1: Write the failing test** — `sim/replay_test.go`:

```go
package sim

import "testing"

// Per-sender SPIs ⇒ every sender has its own anti-replay window ⇒ no legitimate
// packet is ever dropped as a replay, even with many concurrent senders.
func TestPerSenderNoReplayDrops(t *testing.T) {
	r := Run(Nominal(), 1)
	if r.Metrics.ReplayDrops != 0 {
		t.Fatalf("per-sender SPI must yield 0 replay drops, got %d", r.Metrics.ReplayDrops)
	}
	if r.Metrics.DataDecryptable == 0 {
		t.Fatal("scenario delivered no decryptable data")
	}
	if !r.InvariantsHeld {
		t.Fatalf("invariants failed: %s", failureSummary(r))
	}
}
```

- [ ] **Step 2: Run to confirm fail** — `nix develop -c go test ./sim/ -run TestPerSenderNoReplayDrops -v` → FAIL (`ReplayDrops` undefined).

- [ ] **Step 3: Implement.**

(a) `sim/event.go` — add a field to `Envelope` (after `SPI`):
```go
	DataSeq uint64         // for MsgData: the sender's per-sender ESP sequence number
```

(b) `sim/metrics.go` — add `ReplayDrops int` to `Metrics` (after `DataDecryptable`), and a Report row after the `data-decryptable` line:
```go
	_, _ = fmt.Fprintf(w, "replay-drops\t%d\n", m.ReplayDrops)
```

(c) `sim/client.go` — replay window + per-sender send/receive.

Add a small window type (top-level, near the other helpers):
```go
// replayWin is an RFC 4303 anti-replay sliding window (size replayWindow) over a
// single inbound SPI's sequence stream. accept reports whether seq is fresh
// (advancing the window and recording it) or a replay/too-old duplicate.
const replayWindow = 64

type replayWin struct {
	high uint64
	seen map[uint64]bool
}

func newReplayWin() *replayWin { return &replayWin{seen: map[uint64]bool{}} }

func (w *replayWin) accept(seq uint64) bool {
	if w.high >= replayWindow && seq <= w.high-replayWindow {
		return false // below the window ⇒ too old
	}
	if w.seen[seq] {
		return false // duplicate
	}
	if seq > w.high {
		w.high = seq
	}
	w.seen[seq] = true
	for s := range w.seen { // prune entries that fell below the window (order-independent)
		if w.high >= replayWindow && s < w.high-replayWindow {
			delete(w.seen, s)
		}
	}
	return true
}
```

Add fields to `vniState` (in its struct + `newVNIState`):
```go
	sendSeq map[uint64]uint64      // epoch -> next outbound ESP seq (this sender)
	inSPIs  map[uint64]map[uint32]bool // epoch -> set of inbound SPIs we hold (group + per-sender)
	replay  map[uint32]*replayWin  // inbound SPI -> anti-replay window
```
initialize all three to empty maps in `newVNIState`.

In `cacheCurrentSA`, after `st.saCache[sa.Epoch] = sa`, build the inbound-SPI set for this epoch:
```go
	spis := map[uint32]bool{sa.SPI: true} // retained group SPI (used by the negative control)
	if st.ctrl.Group() != nil {
		for _, leaf := range st.ctrl.Group().ActiveLeaves() {
			if s, err := sa.SenderSPI(leaf); err == nil {
				spis[s] = true
			}
		}
	}
	st.inSPIs[sa.Epoch] = spis
```

Add a helper for the SPI a sender stamps (per-sender by default; the negative control overrides — Task 4):
```go
// sendSPI returns the SPI this client stamps on outbound data for the given SA.
// Per-sender by default (each sender its own window); the shared-SPI negative
// control (Task 4) overrides this to the group SPI.
func (c *Client) sendSPI(sa ironcore.SA) uint32 {
	if c.sharedSPIReplay {
		return sa.SPI
	}
	return sa.OwnSPI
}
```
Add `sharedSPIReplay bool` to the `Client` struct (defaults false).

In `sendData`, the candidate's SPI must come from `sendSPI`. Change the `dataCand` construction to use `sa` and set `spi: c.sendSPI(sa)`. (The `dataCand` already carries `sa.SPI`; replace with `c.sendSPI(sa)`.) In `sendToReceiver`, stamp the sequence number: before publishing, `seq := st.sendSeq[cd.se]; st.sendSeq[cd.se] = seq + 1` and add `DataSeq: seq` to the published `Envelope`. (Fetch `st := c.vnis[cd.ch]` there.)

Rewrite `onData` to demux by inbound SPI + replay window:
```go
func (c *Client) onData(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return
	}
	if env.Base < st.joinEpoch {
		return // pre-join epoch: never held that key (forward secrecy, not a loss)
	}
	// Do we hold an inbound SA matching this SPI in some held epoch ≥ joinEpoch?
	held := false
	for _, e := range sortedEpochs(st.saCache) {
		if e < st.joinEpoch {
			continue
		}
		if st.inSPIs[e] != nil && st.inSPIs[e][env.SPI] {
			held = true
			break
		}
	}
	if !held {
		c.checker.packetLoss(uint64(env.VNI), env.Base, st.ctrl.Epoch(), c.sched.Now())
		return
	}
	// Anti-replay: one window per inbound SPI.
	win := st.replay[env.SPI]
	if win == nil {
		win = newReplayWin()
		st.replay[env.SPI] = win
	}
	if win.accept(env.DataSeq) {
		c.metrics.DataDecryptable++
	} else {
		c.metrics.ReplayDrops++
	}
}
```

NOTE on the make-before-break/SA-trim interaction: `trimSAs` deletes old `saCache` epochs; also delete the matching `inSPIs`/`replay` entries there is NOT required for correctness (stale windows are harmless and bounded by epoch count), but to avoid unbounded growth, in `trimSAs` when deleting `saCache[e]` also `delete(st.inSPIs, e)`. Leave `replay` keyed by SPI (it self-prunes seqs); do not delete replay windows mid-run (a late in-window packet may still arrive). This is acceptable for the sim's bounded run.

(d) `sim/sim.go` — the `ReplayDrops` invariant. In `Run`, after computing `r`, add (mirroring the plaintext-exposure invariant), gated so the negative control can expect drops (the gate field lands in Task 4; for now use the metric directly):
```go
	if metrics.ReplayDrops > 0 {
		r.InvariantsHeld = false
	}
```
(Task 4 will refine this to exempt the shared-SPI negative control.)

(e) `sim/sim_test.go` — add `ReplayDrops int` to `TestDeterminism`'s `deterministicMetrics` struct and `snap` return.

- [ ] **Step 4: Run** — `nix develop -c go test ./sim/ -run 'TestPerSenderNoReplayDrops|TestDeterminism' -v` → PASS. Then the whole suite `nix develop -c go test ./sim/ -count=1` (~90s) → PASS. vet + gofmt clean on changed files.

If `TestPerSenderNoReplayDrops` shows nonzero drops: investigate reorder depth vs `replayWindow` (raise the window, or confirm the scheduler's reorder is bounded). Do NOT mask by disabling the check. If drops come from cross-epoch seq reuse, confirm `sendSeq` is keyed by epoch and SPIs differ per epoch.

- [ ] **Step 5: Commit** — `git add sim/event.go sim/client.go sim/metrics.go sim/sim.go sim/sim_test.go sim/replay_test.go && git commit -m "sim: per-sender ESP sequence numbers + per-SPI anti-replay windows"`

---

## Task 4: sim — shared-SPI negative control (proves the checker has teeth)

**Files:** Modify `sim/scenario.go`, `sim/client.go`, `sim/sim.go`; Test: `sim/replay_test.go` (append).

- [ ] **Step 1: Write the failing test** — append to `sim/replay_test.go`:

```go
// Negative control: force all senders onto the single group SPI (one shared
// window). Concurrent senders then collide on sequence numbers, so the receiver
// MUST drop some legitimate packets as replays — proving the anti-replay checker
// has teeth. This is an EXPECTED failure mode, so InvariantsHeld may be false;
// we assert the drops occurred.
func TestSharedSPIProducesReplayDrops(t *testing.T) {
	r := Run(SharedSPIReplayControl(), 1)
	if r.Metrics.ReplayDrops == 0 {
		t.Fatal("shared-SPI control produced 0 replay drops — checker has no teeth")
	}
}
```

- [ ] **Step 2: Run to confirm fail** — `nix develop -c go test ./sim/ -run TestSharedSPIProducesReplayDrops -v` → FAIL (`SharedSPIReplayControl` undefined).

- [ ] **Step 3: Implement.**

(a) `sim/scenario.go` — add a field to `Scenario` (near `MBBDisabled`):
```go
	SharedSPIReplay bool // negative control: senders use the single group SPI (shared anti-replay window)
```
and a scenario constructor (near `NegativeControl`):
```go
// SharedSPIReplayControl is the anti-replay negative control: multiple senders
// share one group SPI ⇒ one shared replay window ⇒ concurrent senders collide
// and the receiver drops legitimate packets as replays (ReplayDrops > 0).
func SharedSPIReplayControl() Scenario {
	s := base("shared_spi_replay", 5, 2)
	s.Churn = churnPlan(5, 2)
	s.SharedSPIReplay = true
	return s
}
```
Register it in `ByName` (append `SharedSPIReplayControl()` to the lookup list, mirroring `MigrationChurn()`).

(b) `sim/client.go` — wire the flag: `newClient` already receives the scenario indirectly via `Run`. In `Run` (`sim/sim.go`) set `clients[i].sharedSPIReplay = sc.SharedSPIReplay` alongside the existing `clients[i].encryptHandshakes = ...` line.

(c) `sim/sim.go` — refine the invariant to exempt the negative control:
```go
	if !sc.SharedSPIReplay && metrics.ReplayDrops > 0 {
		r.InvariantsHeld = false
	}
```
(replace the unconditional check added in Task 3).

- [ ] **Step 4: Run** — `nix develop -c go test ./sim/ -run 'TestSharedSPIProducesReplayDrops|TestPerSenderNoReplayDrops' -v` → PASS. Full suite `nix develop -c go test ./sim/ -count=1` → PASS (existing scenarios still 0 drops / green). vet + gofmt clean.

- [ ] **Step 5: Commit** — `git add sim/scenario.go sim/client.go sim/sim.go sim/replay_test.go && git commit -m "sim: shared-SPI anti-replay negative control"`

---

## Task 5: docs — SA comments + design spec threat model

**Files:** Modify `ironcore/sa.go` (doc only), `docs/superpowers/specs/2026-06-26-mls-go-design.md`.

- [ ] **Step 1: `ironcore/sa.go` doc** — ensure the `SA` type comment notes that `SPI` is the group SPI and `OwnSPI`/`SenderSPI`/`InboundSAs` provide the per-sender anti-replay model. (Comment-only; no logic.)

- [ ] **Step 2: Design spec §10.4 + threat table.** In `docs/superpowers/specs/2026-06-26-mls-go-design.md`:
  - Near the GCM-nonce-safety bullet (§ around line 219), add a sentence: per-sender SPIs (`SenderSPI(leaf)`, `InboundSAs`) give each sender its **own RFC 4303 anti-replay window** — the group key does not force a single shared window; the data plane installs O(M) inbound SAs per VNI (GDOI-style group SA).
  - Update the threat-table replay row (§ around line 236) from "ESP anti-replay" to "**per-sender-SPI** ESP anti-replay (one window per sender leaf)".

- [ ] **Step 3: Verify + commit** — `nix develop -c gofmt -l ironcore/sa.go` (no output); `git add ironcore/sa.go docs/superpowers/specs/2026-06-26-mls-go-design.md && git commit -m "docs: per-sender-SPI anti-replay in SA comments + threat model"`

---

## Final verification (after all tasks)

```bash
nix develop -c make test           # incl. ironcore + sim
nix develop -c make lint           # 0 issues
nix develop -c make fmt-check      # clean
nix develop -c make check-zero-dep # stdlib-only
nix develop -c go vet ./...
nix develop -c go run ./cmd/metalsim -scenario shared_spi_replay   # shows replay-drops > 0
nix develop -c go run ./cmd/metalsim -scenario nominal             # replay-drops = 0
```

Then dispatch a final whole-implementation review and use superpowers:finishing-a-development-branch.
