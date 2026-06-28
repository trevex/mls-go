# mls-go

**A zero-dependency Go implementation of MLS (RFC 9420) with a post-quantum
X-Wing (X25519 + ML-KEM-768) hybrid suite, built to drive IronCore per-VNI key
exchange.**

| | |
|---|---|
| **Conformance** | 15 official MLS Known-Answer Tests pass (RFC 9420 vectors) |
| **Interop** | Validated against **OpenMLS** on suite 1 (PublicMessage) via the official mlswg test-runner |
| **Gate** | 21-subtest gRPC self-conformance gate (suites 0x0001, 0x0002, 0xF001) |
| **Dependencies** | Root module is **stdlib-only** — zero third-party Go deps |
| **Toolchain** | Go via Nix (`nix develop`); `GOTOOLCHAIN=local` |

The engine is a full RFC 9420 MLS implementation (passive **and** active: it can
create groups, propose, commit, welcome, update, remove, and external-join). On
top of it, the `ironcore/` layer turns the domain-agnostic MLS engine into a
per-VNI key-agreement service with a provable single-linearization-point
sequencer (B1 fencing + fork detection), ESP SA derivation, SPIFFE/PKI
credentials, external-commit recovery, and a membership controller.

---

## Architecture

Three concentric layers in one repo, with a hard dependency rule between them:

```
mls/        ← the RFC 9420 engine (STDLIB-ONLY, domain-agnostic)
  syntax/        wire encoding: varints (§2.1.2) + opaque<V> vectors
  cipher/        ciphersuite registry + crypto (§5): HKDF, signatures,
                 labeled KDF, HPKE; suites 0x0001 / 0x0002 / 0xF001 (X-Wing)
  tree/          left-balanced binary tree math + TreeKEM, leaves, credentials
  keyschedule/   key schedule (§8), secret tree (§9), transcript hashes, PSKs
  framing/       message framing/protection (§6): PublicMessage / PrivateMessage
  group/         protocol objects (KeyPackage/Proposal/Commit/GroupInfo/Welcome)
                 + the group state machine (§10/§12)

ironcore/   ← IronCore integration (STDLIB-ONLY; imports only mls/)
  (root)         VNI↔GroupID mapping, ESP SA derivation, credentials,
                 membership controller, external-commit recovery
  sequencer/     single-linearizable-register ordering authority:
                 B1 fencing, fork detection, tie-break (design spec §5)

interop/    ← gRPC conformance harness (SEPARATE nested module; grpc+protobuf)
  cmd/mls-interop/   standalone MLSClient gRPC server binary
  server/            MLSClient service implementation
  proto/mlspb/       committed generated stubs (mls_client.{pb,_grpc.pb}.go)
  conformance_test.go  in-process 21-subtest self-conformance gate

sim/        ← deterministic metalnet/metalbond simulation (root module, STDLIB-ONLY)
  scheduler/event/bus  single-seeded discrete-event engine (no goroutines)
  ds/client            reflector + metalnet-host actors driving the REAL ironcore stack
  invariant/metrics    per-replica convergence, data-plane zero-loss, fan-out cost
  scenario             the built-in fault scenarios + the negative control
cmd/metalsim/   ← CLI runner for the simulation (-scenario all | <name> -seed N)
```

| Layer | Module | Dependencies | Purpose |
|---|---|---|---|
| `mls/…` | `github.com/trevex/mls-go` | **stdlib only** | The RFC 9420 MLS engine |
| `ironcore`, `ironcore/sequencer` | same root module | **stdlib only** | IronCore per-VNI integration + ordering |
| `sim`, `cmd/metalsim` | same root module | **stdlib only** | Deterministic metalnet/metalbond simulation |
| `interop/…` | `github.com/trevex/mls-go/interop` (nested, `replace ../`) | grpc + protobuf | Conformance harness only |

**The zero-dependency rule.** The root module
(`github.com/trevex/mls-go`) has **no `require` block** and pulls in **no
third-party packages** — only the Go standard library. Every dependency
(gRPC, protobuf) lives exclusively in the nested `interop/` module, which
`replace`s the root locally. This is enforced by
[`interop/check-zero-dep.sh`](interop/check-zero-dep.sh) (`make check-zero-dep`).

---

## Quick start

Everything runs inside the Nix dev shell (Go is not on the bare PATH):

```sh
nix develop            # enter the dev shell (go + protoc + plugins + make)
make test              # run the root module test suite

# …or without entering the shell, let make wrap each command in Nix:
nix develop -c make test
```

Run `make help` for the full target list.

---

## Testing conformance

```sh
make kat               # the 15 official MLS Known-Answer Tests (RFC 9420 vectors)
make conformance       # the 21-subtest gRPC self-conformance gate (interop module)
make check-zero-dep    # prove the root module stays stdlib-only
```

The KAT vectors are vendored under [`mls/testdata/`](mls/testdata/) from
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations); the
conformance gate runs 7 scenarios × 3 ciphersuites in-process over `bufconn`
(see [`interop/README.md`](interop/README.md)).

## e2e vs OpenMLS

```sh
make e2e-openmls       # clone + build OpenMLS and the mlswg runner, run interop
```

This builds OpenMLS's `interop_client` (Rust) and the official mlswg
`test-runner`, starts our gRPC server alongside OpenMLS, and runs a set of
known-interoperable scenarios on **suite 1**
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) with PublicMessage handshakes.
It is reproducible from a clean checkout (clone-if-absent, idempotent rebuilds)
and exits 0 only if every scenario passes across all role assignments. It
requires the Rust toolchain, so `make e2e-openmls` runs it in the `e2e` Nix
shell; you can also invoke it directly:

```sh
nix develop .#e2e -c bash scripts/e2e-openmls.sh
```

The X-Wing suite `0xF001` is **ours-only** and is not used against OpenMLS.

## Simulation

```sh
make sim                                            # go test ./sim/... + the all-scenarios CLI smoke
nix develop -c go run ./cmd/metalsim -scenario all  # run the 5-scenario property suite
nix develop -c go run ./cmd/metalsim -scenario partition_recover -seed 7
```

[`sim/`](sim/) + [`cmd/metalsim/`](cmd/metalsim/) are a **deterministic
discrete-event simulation** (single seeded RNG, no goroutines — reproducible by
seed) that drives the **real** `ironcore`/`mls` library to model metalnet under
faults: **two MetalBond reflectors + N metalnet hosts + M VNIs** under packet
drops, reflector-down, and partition.

The model is **dual-group pure redundancy**: each VNI runs **two independent MLS
groups**, one per reflector, each ordered by that reflector's **own local
accept-once register** (never shared — the two reflectors never coordinate); the
data plane installs **both** replicas' ESP SAs and demuxes by SPI. The headline
finding, validated across the 5 scenarios over seeds 1..20:

> **dual-group redundancy ⇒ zero tenant data-plane packet loss when a reflector
> is down or partitioned** — the other replica's SA carries traffic, so no rekey
> or reflector failover ever makes a packet undecryptable.

Because each group is serialized by a single local register, **no replica ever
forks** (so `CanonicalCommit`/fork-resolution is off the path). The trade is
~2× control-plane and SA state. Scenarios:

| Scenario | What it stresses |
|---|---|
| `nominal` | churn, no faults — baseline convergence + fan-out cost |
| `drops` | 20% per-delivery drops — log-replay catch-up |
| `ds_down` | a reflector stops mid-run — **zero loss** on the surviving replica |
| `partition_recover` | client subset cut from one reflector — **zero loss** via cross-replica failover |
| `both_rekey` | concurrent rekeys in both replicas — make-before-break |

A **negative control** (`-scenario negative_control`: single replica, no
make-before-break) deliberately **fails** the zero-loss check, proving it has
teeth. This is a deterministic *model* / property test — not a production
deployment. See the design spec:
[`docs/superpowers/specs/2026-06-28-metalnet-simulation-design.md`](docs/superpowers/specs/2026-06-28-metalnet-simulation-design.md).

## Developing

See **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** for the contributor guide:
the Nix workflow, the zero-dependency rule, the codec convention, how the KAT
vectors are run, regenerating the proto, adding a ciphersuite, and the test
layering.

---

## Feature / limitation matrix

**Supported**

| Ciphersuite | Name | Status |
|---|---|---|
| `0x0001` | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 | full, OpenMLS-interop-validated |
| `0x0002` | MLS_128_DHKEMP256_AES128GCM_SHA256_P256 | full, advertised for cross-stack interop |
| `0xF001` | XWING_AES256GCM_SHA256_Ed25519 (X25519 + ML-KEM-768) | **private-use** post-quantum hybrid; self-conformance only |

- Full RFC 9420 group lifecycle: create, Add / Update / Remove proposals,
  Commit (by-value and by-reference), Welcome/join, external-commit join.
- **PublicMessage** handshake framing; application data via PrivateMessage
  (`Protect`/`Unprotect`).
- All 15 official MLS KAT categories.

**Not yet implemented** (the harness reports `Unimplemented`/rejects these)

- **PSK** proposals (`StorePSK`, external & resumption PSK).
- **PrivateMessage** handshake framing (`encrypt_handshake = true` is rejected;
  handshakes are framed as PublicMessage).
- **Prior-epoch application-message decryption window** (out-of-order
  Unprotect *across* epochs).
- **ReInit**, **Branch**, **external-signer**, `NewMemberAddProposal`,
  `GroupContextExtensionsProposal`.

These limitations are why the e2e gate uses curated supported-only scenario
configs (the upstream mlswg `application.json`/`commit.json` also contain PSK,
GroupContextExtensions, and across-epoch scenarios; see
[`scripts/e2e-configs/`](scripts/e2e-configs/) and the e2e section of the dev
guide).

---

## Design docs

- MLS+IronCore design spec, including the **§5 DS-ordering / failover
  correctness proof** (single-linearization-point, B1 fencing, fork detection):
  [`docs/superpowers/specs/2026-06-26-mls-go-design.md`](docs/superpowers/specs/2026-06-26-mls-go-design.md).
- Simulation design spec (dual-group pure redundancy):
  [`docs/superpowers/specs/2026-06-28-metalnet-simulation-design.md`](docs/superpowers/specs/2026-06-28-metalnet-simulation-design.md).
- Implementation roadmap (16 plans):
  [`docs/superpowers/plans/`](docs/superpowers/plans/).

**Recommended metalbond ordering model.** The `ironcore/sequencer` B1
fencing / fork-detection primitives assume a strongly-consistent lease store,
which real metalbond (an independent route-reflector pair) does not have. The
design §5 refinement and the simulation therefore recommend **dual-group
redundancy** (validated above) — or **static-precedence local registers** — for
metalbond as it actually is, **not** the leased CP store. The library code
supports all three; metalbond selects the model.
