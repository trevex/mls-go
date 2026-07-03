# Per-Sender SPI & Multi-Sender Anti-Replay — Design

**Date:** 2026-07-03
**Status:** Design approved (in-conversation), pending implementation plan.

## Problem

MLS gives a VNI a **group key** shared by all M members. Two issues arise when
that key drives ESP:

1. **AES-GCM nonce reuse** (catastrophic): two senders using the same key+nonce
   → forgery / key recovery. **Already solved** by per-sender GCM salt:
   `SenderSalt(leaf) = saltMask XOR BE32(leaf)` (bijective ⇒ disjoint nonce
   spaces). See `ironcore/sa.go`.
2. **ESP anti-replay window collision** (this work): RFC 4303's replay window is
   **per-SA (per-SPI)**. Today `deriveSPI(vni, epoch)` yields **one group SPI**
   shared by all senders, so N senders each starting at sequence 1 collide in the
   receiver's single window → legitimate packets dropped as replays. It also
   breaks receive-side demux: with one SPI the receiver can't tell which sender's
   salt to use.

## Fix: per-sender SPI (the GDOI / G-IKEv2 group-SA model)

Give **each sender its own SPI** so each gets its own key stream *and* its own
anti-replay window. Key material stays group-shared; only SPI and salt become
per-sender. Each receiver installs **M inbound SAs per VNI** (same `K_group`,
distinct SPI+salt per sender leaf), each with an independent RFC 4303 window.

### Design decisions

1. **SPI derivation gains the leaf (additive — `SA.SPI` is unchanged).**
   `SenderSPI(leaf) = ExpandWithLabel(K_group, "esp-spi-sender", VNI‖epoch‖leaf, 4)`
   (label distinct from the group SPI's `"esp-spi"` — domain separation),
   then **low byte := epoch low byte** (retains make-before-break overlap demux
   across the W window) and **MSB forced set** (keeps SPI > 255, RFC 4303 §2.1).
   New `SA.OwnSPI = SenderSPI(OwnLeaf)` is this member's outbound SPI. The
   existing `SA.SPI` is **retained as the group SPI** (the leaf-independent
   derivation) — kept for backward compatibility and reused as the negative
   control's single shared SPI; per-sender data planes use `OwnSPI` + `InboundSAs`.
   Keeping it additive means no existing test or the sim breaks until each opts in.
   - **Uniqueness is probabilistic** (23 free KDF bits after the epoch low byte
     and MSB), unlike the salt (which is an injective XOR bijection). Birthday
     collision among M senders in one epoch ≈ `M²/2²⁴` — negligible for realistic
     M (≈6e-4 at M=100), non-trivial only at very large M.
   - **Collision handling:** the inbound-SA builder detects any two active leaves
     mapping to the same SPI and returns an error; the caller resolves it by
     forcing a rekey (epoch++ reshuffles every SPI). No silent merge.

2. **Inbound SA set accessor.** `SA.InboundSAs(leaves []uint32) ([]InboundSA, error)`
   returns one `InboundSA{Leaf, SPI, Salt, Key}` per active member leaf (the data
   plane programs these as XFRM inbound states). Collision ⇒ error. Cost: host
   inbound-SA count is **O(M) per VNI** (still O(M), not O(M²) — topology-bound).

3. **Key stays group-shared.** Only SPI + salt are per-sender. This is cheaper
   than per-sender keys and equally nonce-safe; anti-replay correctness comes from
   the distinct SA (SPI), not from distinct key material.

4. **Sim models per-sender anti-replay explicitly.**
   - Sender: a per-`(channel, epoch)` outbound ESP sequence counter; each data
     packet carries `{SPI = own per-sender SPI, DataSeq, Src}`.
   - Receiver: a per-`(channel, SPI)` RFC-4303 sliding window (size 64,
     reorder-tolerant): reject `seq` already seen or below `high-64`.
   - New metric `ReplayDrops`; invariant **`ReplayDrops == 0`** under per-sender
     SPI.
   - **Negative control** (`SharedSPI` mode): all senders use the single group
     SPI into one shared window ⇒ concurrent senders collide ⇒ `ReplayDrops > 0`,
     proving the checker has teeth (mirrors the existing zero-loss negative
     control).

## Scope / non-goals

- No change to the MLS core (`mls/…`) — this is `ironcore` SA derivation + the
  `sim` data-plane model only.
- Not real XFRM/dpservice programming — the sim models the replay window; the
  inbound-SA *set* is exposed for the eventual data-plane integration.
- The GCM nonce-salt mechanism is unchanged (already correct).

## Docs to update

- `ironcore/sa.go` doc comments (SPI is now per-sender).
- Design spec `2026-06-26-mls-go-design.md` §10.4 + threat table: replay is
  handled by per-sender-SPI anti-replay windows, not a single group window.
