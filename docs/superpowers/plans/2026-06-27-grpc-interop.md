# gRPC Interop Conformance Harness (Plan 14) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a gRPC **interop conformance harness** for the MLS (RFC 9420) engine that implements the official `mls_client.proto` `MLSClient` service over our group engine, plus a self-conformance Go test that drives two/three participants *through the gRPC API* (bufconn) across the standard scenarios (1:1 welcome-join, 3-party join, Add/Update/Remove, Protect→Unprotect, Export equality, external-join) and asserts `StateAuth` (epoch-authenticator) equality at every step. The deliverable also makes the server runnable against the official `mls-implementations` test-runner (and OpenMLS / mls-rs).

**Architecture:** The core library `github.com/trevex/mls-go` is **stdlib-only / zero third-party dependencies and MUST STAY THAT WAY**. The harness therefore lives in a **separate NESTED Go module** at `interop/` (module path `github.com/trevex/mls-go/interop`) that (a) `require`s `google.golang.org/grpc` + `google.golang.org/protobuf`, and (b) depends on the core via `replace github.com/trevex/mls-go => ../`, building against the working tree. The root `go.mod` is **never touched**; `go list -deps ./mls/... ./ironcore/...` continues to show no grpc/protobuf. The generated protobuf stubs are **committed** so the harness builds without re-running `protoc`; regeneration is a documented `//go:generate` + `justfile`/README command using the Nix-provided `protoc`.

The server holds a `map[uint32]*state` of opaque group handles (proto uses `uint32` `state_id` / `transaction_id`). Each RPC either maps to an engine call or returns `status.Errorf(codes.Unimplemented, …)`. Unsupported RPCs are obtained for free by embedding the generated `UnimplementedMLSClientServer`.

**Tech Stack:** Go 1.26.4 (via `nix develop -c go`); `google.golang.org/grpc` (seed `@v1.66.0`; `go mod tidy` resolves the compatible `v1.81.1` pulled in by `genproto`), `google.golang.org/protobuf v1.36.11`; Nix-provided `protoc` (libprotoc 32.1), `protoc-gen-go` (1.36.10), `protoc-gen-go-grpc` (1.5.1) from nixpkgs; `google.golang.org/grpc/test/bufconn` for in-memory transport in the conformance test.

**Spec reference:** Official proto `https://raw.githubusercontent.com/mlswg/mls-implementations/main/interop/proto/mls_client.proto` (409 lines); reference Go client `interop/go-mock-client/main.go` in `mlswg/mls-implementations`.

---

## Confirmed feasibility (empirically probed for this plan — do not re-litigate)

- **Module downloads work** in this env (`GOPROXY=https://proxy.golang.org,direct`, `GOTOOLCHAIN=local`). `go get google.golang.org/grpc` succeeds.
- **Nix toolchain works**: `nix shell nixpkgs#protobuf nixpkgs#protoc-gen-go nixpkgs#protoc-gen-go-grpc -c protoc …` → `libprotoc 32.1`, `protoc-gen-go 1.36.10`, `protoc-gen-go-grpc 1.5.1`. Go is `1.26.4` via `nix develop`.
- **Stubs generated + compiled**: with the vendored proto's `go_package` overridden to `github.com/trevex/mls-go/interop/proto/mlspb;mlspb` and `paths=source_relative`, `protoc` emits `mls_client.pb.go` + `mls_client_grpc.pb.go`; both compile in the nested module. The generated server interface embeds `UnimplementedMLSClientServer` (every method has a default `Unimplemented` impl) and `RegisterMLSClientServer(s grpc.ServiceRegistrar, srv MLSClientServer)` exists.
- **bufconn server call returns**: a minimal `MLSClientServer` embedding `UnimplementedMLSClientServer` with real `CreateGroup`/`StateAuth` builds and answers over a `bufconn` in-memory listener via `grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(...))`.
- **2-state convergence through gRPC PASSES** (the gate): `CreateGroup(alice)` → `CreateKeyPackage(bob)` → `Commit(by_value Add bob)` → `HandlePendingCommit(alice)` → `JoinGroup(bob, welcome)` → `StateAuth` byte-equal, under **suite 0x0001** *and* **suite 0xF001 (X-Wing)**. Converged epoch authenticators reproduced over the real gRPC stubs.
- **Core stays zero-dep**: `go list -deps ./mls/... ./ironcore/...` lists no third-party packages (only stdlib + own module). The nested module + `replace` guarantees grpc/protobuf never enter the root module graph.

### Engine constraint discovered while probing (load-bearing for the server)

> **Adds that generate a Welcome MUST be committed BY VALUE.** `(*group.Group).Commit` collects `addedKPs` only from `opt.ByValue` (see `mls/group/commit_gen.go`); a by-*reference* Add yields `newlyAdded len 1 != addedKPs len 0` and `buildWelcome` fails. Therefore the `Commit` RPC maps proto **`by_value` `ProposalDescription{type:"add"}`** entries to engine by-value `group.ProposeAdd(kp)`. The official runner's basic welcome scenarios issue the joining Add by value, so this is compatible; `AddProposal`-then-Commit-by-reference Adds are documented as a known limitation (they commit fine but produce no Welcome).

---

## Engine API surface the server wraps (verified signatures — use exactly these)

From `mls/cipher`:
- `cipher.Lookup(id CipherSuite) (Suite, bool)`; suites `X25519_AES128GCM_SHA256_Ed25519 = 0x0001`, `P256_AES128GCM_SHA256_P256 = 0x0002`, `XWING_AES256GCM_SHA256_Ed25519 = 0xF001` (registered via `init()` in `suite_pq.go`).
- `(Suite).SignaturePublicKey(signer crypto.Signer) ([]byte, error)`.

From `mls/tree`:
- `tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte}`; `tree.Lifetime{NotBefore, NotAfter uint64}` (max span = `{0, ^uint64(0)}`).

From `mls/group`:
- `NewGroup(suite cipher.Suite, groupID []byte, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (*Group, error)`
- `NewKeyPackage(suite, cred, signer, lifetime) (kp KeyPackage, initPriv []byte, leafPriv []byte, err error)`
- `EncodeKeyPackageMessage(kp KeyPackage) ([]byte, error)` / `DecodeKeyPackageMessage(data []byte) (KeyPackage, error)`
- `JoinFromWelcome(suite cipher.Suite, welcome []byte, opt JoinOptions) (*Group, error)`; `JoinOptions{KeyPackage, InitPriv, EncryptionPriv []byte; Signer crypto.Signer; RatchetTree []byte; ExternalPSKs map[string][]byte}`
- `(*Group).Commit(opt CommitOptions) (commit []byte, welcome []byte, err error)`; `CommitOptions{ByValue []Proposal; ByReference [][]byte}`
- `(*Group).ProcessCommit(proposals [][]byte, commit []byte) error` (dispatches `SenderTypeNewMemberCommit` to external-commit handling automatically)
- `ProposeAdd(kp KeyPackage) Proposal`; `ProposeRemove(leaf uint32) Proposal`; `(*Group).ProposeUpdate() (Proposal, error)`; `(*Group).FrameProposal(p Proposal) ([]byte, error)` (frames a bare proposal as a member PublicMessage for by-reference delivery)
- `(*Group).PublishGroupInfo() (*GroupInfo, error)`; `(GroupInfo).MarshalMLS() ([]byte, error)`; `(*GroupInfo).UnmarshalMLS([]byte) error`; `(GroupInfo).GroupContext` exposes `.CipherSuite`
- `ExternalCommit(suite cipher.Suite, gi GroupInfo, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (*Group, []byte, error)` (joiner side; auto-includes Remove of a stale prior leaf with the same signature key → covers `remove_prior`)
- `(*Group).EpochAuthenticator() []byte`; `(*Group).Epoch() uint64`; `(*Group).Exporter(label string, context []byte, length int) ([]byte, error)`
- `(*Group).ProtectApplication(plaintext, authenticatedData []byte) ([]byte, error)`; `(*Group).UnprotectApplication(msg []byte) (plaintext, authenticatedData []byte, err error)`
- `(*Group).ActiveLeaves() []uint32`; `(*Group).LeafCredential(leaf uint32) (tree.Credential, []byte, error)` (used to resolve a `removed_id` identity → leaf index)

Signer construction (server-side; the proto's `CreateGroup`/`CreateKeyPackage` provide only an identity):
- `0x0001` / `0xF001` (Ed25519): `pub, priv, _ := ed25519.GenerateKey(rand.Reader)`; `signature_priv = priv.Seed()`.
- `0x0002` (ECDSA P-256): `sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`; `signature_priv = sk.D` filled to 32 bytes (round-trips via `ecdsa.ParseRawPrivateKey`).

---

## RPC support matrix

| RPC | Status | Mapping / reason |
|---|---|---|
| `Name` | ✅ | returns `"mls-go"` |
| `SupportedCiphersuites` | ✅ | `{0x0001, 0x0002}` (0xF001 omitted: private-use, self-interop only) |
| `CreateGroup` | ✅ | `NewGroup`; rejects `encrypt_handshake=true` (engine handshakes are PublicMessage) |
| `CreateKeyPackage` | ✅ | gen signer + `NewKeyPackage` + `EncodeKeyPackageMessage`; stores privs under `transaction_id` |
| `JoinGroup` | ✅ | `JoinFromWelcome` using the stored transaction record |
| `ExternalJoin` | ✅ | `ExternalCommit` (suite read from `group_info`); `remove_prior` is automatic; rejects non-empty `psks` |
| `GroupInfo` | ✅ | `PublishGroupInfo` + `MarshalMLS`; ratchet_tree is in the GroupInfo extension |
| `StateAuth` | ✅ | `EpochAuthenticator()` → `state_auth_secret` |
| `Export` | ✅ | `Exporter(label, context, key_length)` |
| `Protect` | ✅ | `ProtectApplication` |
| `Unprotect` | ✅ | `UnprotectApplication` |
| `AddProposal` | ✅ | `DecodeKeyPackageMessage` + `ProposeAdd` + `FrameProposal` (by-reference) |
| `UpdateProposal` | ✅ | `ProposeUpdate` + `FrameProposal` |
| `RemoveProposal` | ✅ | resolve `removed_id` identity → leaf via `ActiveLeaves`/`LeafCredential` + `ProposeRemove` + `FrameProposal` |
| `Commit` | ✅ | `Commit(opt)`; `by_value` `add`/`remove` → engine by-value; `by_reference` passed through; stashes pending epoch auth |
| `HandleCommit` | ✅ | `ProcessCommit(proposal, commit)` |
| `HandlePendingCommit` | ✅ | returns the epoch auth stashed by `Commit` (engine advances the committer in-place — see below) |
| `Free` | ✅ | drops the state handle |
| `StorePSK` | ⛔ Unimplemented | no server-side PSK store plumbing in v1; engine resolves external PSKs only at join time |
| `ExternalPSKProposal` | ⛔ Unimplemented | depends on `StorePSK` |
| `ResumptionPSKProposal` | ⛔ Unimplemented | engine has resumption-PSK *resolution* but no proposal-builder exposed |
| `GroupContextExtensionsProposal` | ⛔ Unimplemented | `ProposeGroupContextExtensions` exists but GCE commit path is not end-to-end validated; defer |
| `ReInitProposal` / `ReInitCommit` / `HandlePendingReInitCommit` / `HandleReInitCommit` / `ReInitWelcome` / `HandleReInitWelcome` | ⛔ Unimplemented | reinitialization not implemented in the engine |
| `CreateBranch` / `HandleBranch` | ⛔ Unimplemented | subgroup branching not implemented in the engine |
| `NewMemberAddProposal` | ⛔ Unimplemented | external (non-member) Add proposals not exposed by the engine |
| `CreateExternalSigner` / `AddExternalSigner` / `ExternalSignerProposal` | ⛔ Unimplemented | external signers not implemented in the engine |

All ⛔ rows are obtained for free by embedding `pb.UnimplementedMLSClientServer` (no code to write).

### Pending-commit semantics (important modeling decision)

The proto model is: `Commit` returns the commit+welcome **without advancing the committer**; `HandlePendingCommit` then advances it. Our engine's `(*Group).Commit` **advances the committer in place atomically** (it must, to return the commit/welcome bytes). The server therefore: on `Commit`, calls `g.Commit(opt)` (group now at `n+1`) and **stashes `g.EpochAuthenticator()` in `state.pendingEpochAuth`**; on `HandlePendingCommit`, returns that stashed value and clears it. This is correct for all official scenarios (the committer commits, then immediately handles its pending commit, then everyone compares). Limitation: issuing further operations at the *old* epoch on that handle between `Commit` and `HandlePendingCommit` is unsupported — documented in the README.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `interop/go.mod` | Create | Nested module `…/interop`; `require` grpc + protobuf; `replace …/mls-go => ../` |
| `interop/go.sum` | Create | Checksums (via `go mod tidy`) |
| `interop/proto/mls_client.proto` | Create | Vendored upstream proto, `go_package` overridden to `…/interop/proto/mlspb;mlspb` |
| `interop/proto/mlspb/mls_client.pb.go` | Create (generated, committed) | Message types |
| `interop/proto/mlspb/mls_client_grpc.pb.go` | Create (generated, committed) | Service stubs + `UnimplementedMLSClientServer` |
| `interop/proto/gen.go` | Create | `//go:generate` directive documenting/driving regeneration |
| `interop/server/server.go` | Create | `*Server` implementing `MLSClientServer` over the engine |
| `interop/cmd/mls-interop/main.go` | Create | Binary: `MLSClient` gRPC server on a TCP port for the official runner |
| `interop/conformance_test.go` | Create | In-process bufconn self-conformance test (the gate) |
| `interop/justfile` | Create | `gen`, `test`, `run` targets |
| `interop/README.md` | Create | Regen command; how to run vs the official runner / OpenMLS / mls-rs; X-Wing caveat |
| `flake.nix` | Modify | Add `protobuf`, `protoc-gen-go`, `protoc-gen-go-grpc` to the devShell so `protoc` + plugins are on PATH inside `nix develop` |

> **Zero-dep guarantee:** nothing under `mls/` or `ironcore/` is touched; the only root-repo edit is `flake.nix` (tooling, not Go deps). After this plan, `nix develop -c go list -deps ./mls/... ./ironcore/...` MUST still print no third-party module.

---

## Proto generation approach (Nix protoc + committed stubs)

1. **Vendor** `mls_client.proto` into `interop/proto/`, changing only the `go_package` line:
   ```
   option go_package = "github.com/trevex/mls-go/interop/proto/mlspb;mlspb";
   ```
2. **Generate** with the Nix-provided toolchain (plugins must be on PATH; the `nix shell` line below makes them available; once `flake.nix` is updated, `nix develop` provides them too):
   ```sh
   nix shell nixpkgs#protobuf nixpkgs#protoc-gen-go nixpkgs#protoc-gen-go-grpc -c \
     protoc --proto_path=interop/proto \
       --go_out=interop/proto/mlspb       --go_opt=paths=source_relative \
       --go-grpc_out=interop/proto/mlspb  --go-grpc_opt=paths=source_relative \
       mls_client.proto
   ```
3. **Commit** the two generated `.go` files so `go build ./...` works without `protoc`. `interop/proto/gen.go` carries the `//go:generate` form for regen, and the `justfile` `gen` target wraps the command above.

`interop/proto/gen.go`:
```go
// Package mlspb hosts the generated MLSClient gRPC stubs. Regenerate with `just gen`.
package proto

//go:generate protoc --proto_path=. --go_out=mlspb --go_opt=paths=source_relative --go-grpc_out=mlspb --go-grpc_opt=paths=source_relative mls_client.proto
```

---

## How the nested module keeps the core zero-dep

- Root `go.mod` (`module github.com/trevex/mls-go`, `go 1.26.4`) has **no `require` block** and is not edited by this plan.
- `interop/go.mod` is a *separate module*; its `require google.golang.org/grpc …` and `google.golang.org/protobuf …` live only in the interop module graph.
- `replace github.com/trevex/mls-go => ../` makes the harness compile against the working-tree engine without publishing.
- Verification (Definition of Done): `nix develop -c go list -deps ./mls/... ./ironcore/...` from the repo root prints no `google.golang.org/...` package; `nix develop -c go vet ./...` at the root is unaffected by the nested module (Go treats `interop/` as a distinct module and excludes it from root `./...`).

---

## Task breakdown (bite-sized, TDD-ish; the gate test is the acceptance criterion)

### Task 1 — Devshell tooling
- [ ] Edit `flake.nix`: add `protobuf`, `protoc-gen-go`, `protoc-gen-go-grpc` to `devShells.default.packages` (alongside `go`). Keep `GOTOOLCHAIN = "local"`.
- [ ] Verify inside `nix develop`: `protoc --version` (≥ libprotoc 32.1), `protoc-gen-go` and `protoc-gen-go-grpc` on PATH.
- [ ] Confirm `nix develop -c go list -deps ./mls/... ./ironcore/...` still shows no third-party deps (regression guard before adding the module).

### Task 2 — Nested module + vendored proto
- [ ] Create `interop/go.mod`:
  ```
  module github.com/trevex/mls-go/interop

  go 1.26.4

  require github.com/trevex/mls-go v0.0.0

  replace github.com/trevex/mls-go => ../
  ```
- [ ] Vendor `interop/proto/mls_client.proto` (upstream content, `go_package` overridden as above).
- [ ] Add `interop/proto/gen.go` (the `//go:generate` form).

### Task 3 — Generate + commit stubs
- [ ] Run the `protoc` command (Task in "Proto generation approach"); confirm `interop/proto/mlspb/mls_client.pb.go` and `mls_client_grpc.pb.go` are produced.
- [ ] `cd interop && nix develop ../ -c go get google.golang.org/grpc@v1.66.0 google.golang.org/protobuf@latest && nix develop ../ -c go mod tidy` (resolves grpc `v1.81.1`, protobuf `v1.36.11`).
- [ ] `nix develop ../ -c go build ./proto/...` compiles (the gate's first empirical check — already verified).

### Task 4 — Server skeleton + the easy RPCs (TDD: Name/SupportedCiphersuites/CreateGroup/StateAuth)
- [ ] Create `interop/server/server.go` with `type Server struct { pb.UnimplementedMLSClientServer; mu sync.Mutex; states map[uint32]*state; txns map[uint32]*pendingKP; nextID uint32 }`, `New()`, the signer/suite helpers, and `Name`, `SupportedCiphersuites`, `CreateGroup`, `StateAuth`, `Free`.
- [ ] Bring up a `bufconn` server in a throwaway sub-test, call `CreateGroup` + `StateAuth`, assert no error (empirically verified to return). Embedding `UnimplementedMLSClientServer` makes every other RPC compile and return `Unimplemented`.

### Task 5 — Membership RPCs
- [ ] Add `CreateKeyPackage` (store privs+signer under `transaction_id`), `JoinGroup` (`JoinFromWelcome` from the transaction record), `AddProposal`, `UpdateProposal`, `RemoveProposal` (identity→leaf resolver).

### Task 6 — Commit pipeline
- [ ] Add `Commit` (translate `by_value` add/remove → engine by-value, pass `by_reference` through, stash `pendingEpochAuth`), `HandleCommit` (`ProcessCommit`), `HandlePendingCommit` (return stash).

### Task 7 — App + Export + GroupInfo + ExternalJoin
- [ ] Add `Export`, `Protect`, `Unprotect`, `GroupInfo` (`PublishGroupInfo`+`MarshalMLS`), `ExternalJoin` (decode `group_info` → suite → `ExternalCommit`; reject non-empty `psks`).

### Task 8 — Conformance test (THE GATE)
- [ ] Create `interop/conformance_test.go` with the bufconn harness and scenarios below; run under suites `0x0001` and `0xF001`. Assert `StateAuth` byte-equality across all participants after every epoch change, and `Export` equality.

### Task 9 — Binary + docs
- [ ] `interop/cmd/mls-interop/main.go`: listen on `-port` (default `:50051`), `grpc.NewServer()`, `RegisterMLSClientServer(s, server.New())`, `s.Serve(lis)`.
- [ ] `interop/justfile` (`gen`, `test`, `run`) and `interop/README.md` (regen command, official-runner instructions, OpenMLS/mls-rs cross-runs, X-Wing private-suite caveat).

### Task 10 — Zero-dep + vet gate
- [ ] From repo root: `nix develop -c go list -deps ./mls/... ./ironcore/...` shows no third-party package; `nix develop -c go vet ./...` passes. From `interop/`: `nix develop ../ -c go vet ./...` and `go test ./...` pass.

---

## Complete reference code

### `interop/server/server.go`

> Validated end-to-end over bufconn (suites 0x0001 + 0xF001). Lift verbatim.

```go
package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/trevex/mls-go/interop/proto/mlspb"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/tree"
)

type state struct {
	suite            cipher.Suite
	g                *group.Group
	pendingEpochAuth []byte // stashed by Commit; returned by HandlePendingCommit
}

type pendingKP struct {
	suite    cipher.Suite
	kpMsg    []byte
	initPriv []byte
	encPriv  []byte
	signer   crypto.Signer
}

// Server implements pb.MLSClientServer over the MLS engine. Embedding
// UnimplementedMLSClientServer makes every unsupported RPC return codes.Unimplemented.
type Server struct {
	pb.UnimplementedMLSClientServer
	mu     sync.Mutex
	states map[uint32]*state
	txns   map[uint32]*pendingKP
	nextID uint32
}

func New() *Server {
	return &Server{states: map[uint32]*state{}, txns: map[uint32]*pendingKP{}, nextID: 1}
}

func (s *Server) alloc() uint32 { id := s.nextID; s.nextID++; return id }

func lookupSuite(cs uint32) (cipher.Suite, error) {
	suite, ok := cipher.Lookup(cipher.CipherSuite(cs))
	if !ok {
		return cipher.Suite{}, status.Errorf(codes.InvalidArgument, "unsupported ciphersuite 0x%04x", cs)
	}
	return suite, nil
}

// newSigner generates a fresh signing key for the suite and returns the raw
// signature_priv the proto wants echoed back (Ed25519 seed / ECDSA scalar).
func newSigner(cs cipher.CipherSuite) (crypto.Signer, []byte, error) {
	switch cs {
	case cipher.X25519_AES128GCM_SHA256_Ed25519, cipher.XWING_AES256GCM_SHA256_Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, priv.Seed(), nil
	case cipher.P256_AES128GCM_SHA256_P256:
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		raw := make([]byte, 32)
		sk.D.FillBytes(raw)
		return sk, raw, nil
	default:
		return nil, nil, fmt.Errorf("no signer for suite 0x%04x", cs)
	}
}

func maxLifetime() tree.Lifetime { return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)} }

func (s *Server) getState(id uint32) (*state, error) {
	st, ok := s.states[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown state_id %d", id)
	}
	return st, nil
}

func (st *state) resolveIdentity(identity []byte) (uint32, error) {
	for _, leaf := range st.g.ActiveLeaves() {
		cred, _, err := st.g.LeafCredential(leaf)
		if err != nil {
			continue
		}
		if bytes.Equal(cred.Identity, identity) {
			return leaf, nil
		}
	}
	return 0, status.Errorf(codes.NotFound, "no member with identity %q", identity)
}

func (s *Server) Name(_ context.Context, _ *pb.NameRequest) (*pb.NameResponse, error) {
	return &pb.NameResponse{Name: "mls-go"}, nil
}

func (s *Server) SupportedCiphersuites(_ context.Context, _ *pb.SupportedCiphersuitesRequest) (*pb.SupportedCiphersuitesResponse, error) {
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: []uint32{
		uint32(cipher.X25519_AES128GCM_SHA256_Ed25519),
		uint32(cipher.P256_AES128GCM_SHA256_P256),
		// 0xF001 (X-Wing) intentionally omitted: private-use, self-interop only.
	}}, nil
}

func (s *Server) CreateGroup(_ context.Context, req *pb.CreateGroupRequest) (*pb.CreateGroupResponse, error) {
	if req.EncryptHandshake {
		return nil, status.Error(codes.Unimplemented, "encrypted (PrivateMessage) handshake not supported")
	}
	suite, err := lookupSuite(req.CipherSuite)
	if err != nil {
		return nil, err
	}
	signer, _, err := newSigner(cipher.CipherSuite(req.CipherSuite))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "newSigner: %v", err)
	}
	cred := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: req.Identity}
	g, err := group.NewGroup(suite, req.GroupId, cred, signer, maxLifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NewGroup: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.alloc()
	s.states[id] = &state{suite: suite, g: g}
	return &pb.CreateGroupResponse{StateId: id}, nil
}

func (s *Server) CreateKeyPackage(_ context.Context, req *pb.CreateKeyPackageRequest) (*pb.CreateKeyPackageResponse, error) {
	suite, err := lookupSuite(req.CipherSuite)
	if err != nil {
		return nil, err
	}
	signer, sigSeed, err := newSigner(cipher.CipherSuite(req.CipherSuite))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "newSigner: %v", err)
	}
	cred := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: req.Identity}
	kp, initPriv, leafPriv, err := group.NewKeyPackage(suite, cred, signer, maxLifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NewKeyPackage: %v", err)
	}
	kpMsg, err := group.EncodeKeyPackageMessage(kp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "EncodeKeyPackageMessage: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tid := s.alloc()
	s.txns[tid] = &pendingKP{suite: suite, kpMsg: kpMsg, initPriv: initPriv, encPriv: leafPriv, signer: signer}
	return &pb.CreateKeyPackageResponse{
		TransactionId:  tid,
		KeyPackage:     kpMsg,
		InitPriv:       initPriv,
		EncryptionPriv: leafPriv,
		SignaturePriv:  sigSeed,
	}, nil
}

func (s *Server) JoinGroup(_ context.Context, req *pb.JoinGroupRequest) (*pb.JoinGroupResponse, error) {
	if req.EncryptHandshake {
		return nil, status.Error(codes.Unimplemented, "encrypted handshake not supported")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txns[req.TransactionId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown transaction_id %d", req.TransactionId)
	}
	g, err := group.JoinFromWelcome(tx.suite, req.Welcome, group.JoinOptions{
		KeyPackage:     tx.kpMsg,
		InitPriv:       tx.initPriv,
		EncryptionPriv: tx.encPriv,
		Signer:         tx.signer,
		RatchetTree:    req.RatchetTree, // optional external tree
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "JoinFromWelcome: %v", err)
	}
	id := s.alloc()
	s.states[id] = &state{suite: tx.suite, g: g}
	return &pb.JoinGroupResponse{StateId: id, EpochAuthenticator: g.EpochAuthenticator()}, nil
}

func (s *Server) ExternalJoin(_ context.Context, req *pb.ExternalJoinRequest) (*pb.ExternalJoinResponse, error) {
	if req.EncryptHandshake {
		return nil, status.Error(codes.Unimplemented, "encrypted handshake not supported")
	}
	if len(req.Psks) > 0 {
		return nil, status.Error(codes.Unimplemented, "PSKs in external join not supported")
	}
	var gi group.GroupInfo
	if err := gi.UnmarshalMLS(req.GroupInfo); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse group_info: %v", err)
	}
	suite, err := lookupSuite(uint32(gi.GroupContext.CipherSuite))
	if err != nil {
		return nil, err
	}
	signer, _, err := newSigner(gi.GroupContext.CipherSuite)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "newSigner: %v", err)
	}
	cred := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: req.Identity}
	g, commit, err := group.ExternalCommit(suite, gi, cred, signer, maxLifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ExternalCommit: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.alloc()
	s.states[id] = &state{suite: suite, g: g}
	return &pb.ExternalJoinResponse{StateId: id, Commit: commit, EpochAuthenticator: g.EpochAuthenticator()}, nil
}

func (s *Server) GroupInfo(_ context.Context, req *pb.GroupInfoRequest) (*pb.GroupInfoResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	gi, err := st.g.PublishGroupInfo()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "PublishGroupInfo: %v", err)
	}
	giBytes, err := gi.MarshalMLS()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal group_info: %v", err)
	}
	// The ratchet_tree is carried inside the GroupInfo's 0x0002 extension; we mirror
	// it in the response's ratchet_tree field too (callers may pass external_tree).
	return &pb.GroupInfoResponse{GroupInfo: giBytes, RatchetTree: gi.RatchetTreeExtension()}, nil
}

func (s *Server) StateAuth(_ context.Context, req *pb.StateAuthRequest) (*pb.StateAuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	return &pb.StateAuthResponse{StateAuthSecret: st.g.EpochAuthenticator()}, nil
}

func (s *Server) Export(_ context.Context, req *pb.ExportRequest) (*pb.ExportResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	out, err := st.g.Exporter(req.Label, req.Context, int(req.KeyLength))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Exporter: %v", err)
	}
	return &pb.ExportResponse{ExportedSecret: out}, nil
}

func (s *Server) Protect(_ context.Context, req *pb.ProtectRequest) (*pb.ProtectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	ct, err := st.g.ProtectApplication(req.Plaintext, req.AuthenticatedData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ProtectApplication: %v", err)
	}
	return &pb.ProtectResponse{Ciphertext: ct}, nil
}

func (s *Server) Unprotect(_ context.Context, req *pb.UnprotectRequest) (*pb.UnprotectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	pt, ad, err := st.g.UnprotectApplication(req.Ciphertext)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "UnprotectApplication: %v", err)
	}
	return &pb.UnprotectResponse{Plaintext: pt, AuthenticatedData: ad}, nil
}

func (s *Server) AddProposal(_ context.Context, req *pb.AddProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	kp, err := group.DecodeKeyPackageMessage(req.KeyPackage)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "DecodeKeyPackageMessage: %v", err)
	}
	msg, err := st.g.FrameProposal(group.ProposeAdd(kp))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "FrameProposal: %v", err)
	}
	return &pb.ProposalResponse{Proposal: msg}, nil
}

func (s *Server) UpdateProposal(_ context.Context, req *pb.UpdateProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	prop, err := st.g.ProposeUpdate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ProposeUpdate: %v", err)
	}
	msg, err := st.g.FrameProposal(prop)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "FrameProposal: %v", err)
	}
	return &pb.ProposalResponse{Proposal: msg}, nil
}

func (s *Server) RemoveProposal(_ context.Context, req *pb.RemoveProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	leaf, err := st.resolveIdentity(req.RemovedId)
	if err != nil {
		return nil, err
	}
	msg, err := st.g.FrameProposal(group.ProposeRemove(leaf))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "FrameProposal: %v", err)
	}
	return &pb.ProposalResponse{Proposal: msg}, nil
}

func (s *Server) Commit(_ context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	opt := group.CommitOptions{ByReference: req.ByReference}
	for _, pd := range req.ByValue {
		switch string(pd.ProposalType) {
		case "add":
			// Engine constraint: Welcome-producing Adds MUST be by-value.
			kp, err := group.DecodeKeyPackageMessage(pd.KeyPackage)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "by_value add: %v", err)
			}
			opt.ByValue = append(opt.ByValue, group.ProposeAdd(kp))
		case "remove":
			leaf, err := st.resolveIdentity(pd.RemovedId)
			if err != nil {
				return nil, err
			}
			opt.ByValue = append(opt.ByValue, group.ProposeRemove(leaf))
		default:
			return nil, status.Errorf(codes.Unimplemented, "by_value proposal_type %q not supported", pd.ProposalType)
		}
	}
	commit, welcome, err := st.g.Commit(opt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Commit: %v", err)
	}
	// Engine advances the committer in place; stash the new epoch auth for
	// HandlePendingCommit to report (proto's pending-commit semantics).
	st.pendingEpochAuth = st.g.EpochAuthenticator()
	return &pb.CommitResponse{Commit: commit, Welcome: welcome}, nil
}

func (s *Server) HandleCommit(_ context.Context, req *pb.HandleCommitRequest) (*pb.HandleCommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	if err := st.g.ProcessCommit(req.Proposal, req.Commit); err != nil {
		return nil, status.Errorf(codes.Internal, "ProcessCommit: %v", err)
	}
	return &pb.HandleCommitResponse{StateId: req.StateId, EpochAuthenticator: st.g.EpochAuthenticator()}, nil
}

func (s *Server) HandlePendingCommit(_ context.Context, req *pb.HandlePendingCommitRequest) (*pb.HandleCommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	if st.pendingEpochAuth == nil {
		return nil, status.Error(codes.FailedPrecondition, "no pending commit")
	}
	ea := st.pendingEpochAuth
	st.pendingEpochAuth = nil
	return &pb.HandleCommitResponse{StateId: req.StateId, EpochAuthenticator: ea}, nil
}

func (s *Server) Free(_ context.Context, req *pb.FreeRequest) (*pb.FreeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, req.StateId)
	return &pb.FreeResponse{}, nil
}
```

### `interop/cmd/mls-interop/main.go`

```go
package main

import (
	"flag"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/trevex/mls-go/interop/proto/mlspb"
	"github.com/trevex/mls-go/interop/server"
)

func main() {
	port := flag.String("port", ":50051", "listen address")
	flag.Parse()
	lis, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterMLSClientServer(s, server.New())
	log.Printf("mls-interop MLSClient serving on %s", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
```

### `interop/conformance_test.go` (the gate — validated for the 2-state case)

> Task 8 extends the validated 2-state core (below) with the 3-party, Update, Remove, Protect/Unprotect, Export, and external-join scenarios; each asserts `StateAuth` equality across live participants. The 2-state block is the proven minimum gate.

```go
package interop_test

import (
	"bytes"
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/trevex/mls-go/interop/proto/mlspb"
	"github.com/trevex/mls-go/interop/server"
	"github.com/trevex/mls-go/mls/cipher"
)

func dial(t *testing.T) (pb.MLSClientClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterMLSClientServer(srv, server.New())
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return pb.NewMLSClientClient(conn), func() { conn.Close(); srv.Stop() }
}

// TestTwoStateConvergence is the gate: a full welcome-join through the gRPC API.
func TestTwoStateConvergence(t *testing.T) {
	suites := []uint32{
		uint32(cipher.X25519_AES128GCM_SHA256_Ed25519),
		uint32(cipher.XWING_AES256GCM_SHA256_Ed25519), // 0xF001 — self-interop only
	}
	for _, cs := range suites {
		t.Run("", func(t *testing.T) {
			cli, done := dial(t)
			defer done()
			ctx := context.Background()

			cg, err := cli.CreateGroup(ctx, &pb.CreateGroupRequest{GroupId: []byte("g"), CipherSuite: cs, Identity: []byte("alice")})
			if err != nil {
				t.Fatal(err)
			}
			alice := cg.StateId

			kp, err := cli.CreateKeyPackage(ctx, &pb.CreateKeyPackageRequest{CipherSuite: cs, Identity: []byte("bob")})
			if err != nil {
				t.Fatal(err)
			}

			// Welcome-producing Add must be by-value (engine constraint).
			com, err := cli.Commit(ctx, &pb.CommitRequest{StateId: alice, ByValue: []*pb.ProposalDescription{
				{ProposalType: []byte("add"), KeyPackage: kp.KeyPackage},
			}})
			if err != nil {
				t.Fatal(err)
			}
			ha, err := cli.HandlePendingCommit(ctx, &pb.HandlePendingCommitRequest{StateId: alice})
			if err != nil {
				t.Fatal(err)
			}
			jg, err := cli.JoinGroup(ctx, &pb.JoinGroupRequest{TransactionId: kp.TransactionId, Welcome: com.Welcome})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ha.EpochAuthenticator, jg.EpochAuthenticator) {
				t.Fatalf("epoch_authenticator mismatch:\n alice %x\n bob   %x", ha.EpochAuthenticator, jg.EpochAuthenticator)
			}
			sa1, _ := cli.StateAuth(ctx, &pb.StateAuthRequest{StateId: alice})
			sa2, _ := cli.StateAuth(ctx, &pb.StateAuthRequest{StateId: jg.StateId})
			if !bytes.Equal(sa1.StateAuthSecret, sa2.StateAuthSecret) {
				t.Fatal("StateAuth mismatch")
			}
		})
	}
}
```

Scenarios for Task 8 (each = one `t.Run`, all asserting `StateAuth` equality across live members):
1. **1:1 welcome-join** (above).
2. **3-party join**: alice creates; commits by-value `Add(bob)`; bob joins; alice commits by-value `Add(carol)`; bob `HandleCommit`; carol joins; assert alice≡bob≡carol.
3. **Update**: bob `UpdateProposal` → alice `Commit(by_reference=[prop])` → alice `HandlePendingCommit`, bob/carol `HandleCommit`; assert convergence.
4. **Remove**: alice `Commit(by_value Remove{removed_id:"carol"})` → `HandlePendingCommit`; bob `HandleCommit`; assert alice≡bob (carol evicted).
5. **Protect/Unprotect**: alice `Protect(ad, pt)` → bob `Unprotect` returns `(ad, pt)`.
6. **Export equality**: alice & bob `Export(label, ctx, 32)` byte-equal.
7. **External-join**: alice `GroupInfo(state)` → carol `ExternalJoin(group_info)` returns `(commit, state)`; alice & bob `HandleCommit(commit)`; assert alice≡bob≡carol.

### `interop/justfile`

```make
gen:
    protoc --proto_path=proto \
      --go_out=proto/mlspb --go_opt=paths=source_relative \
      --go-grpc_out=proto/mlspb --go-grpc_opt=paths=source_relative \
      proto/mls_client.proto

test:
    go test ./...

run port=":50051":
    go run ./cmd/mls-interop -port {{port}}
```

---

## Definition of Done

- [ ] `flake.nix` devShell provides `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`; `nix develop -c protoc --version` works.
- [ ] `interop/` is a separate module (`replace … => ../`); committed generated stubs build: `cd interop && nix develop ../ -c go build ./...`.
- [ ] `nix develop ../ -c go test ./...` in `interop/` passes, including `TestTwoStateConvergence` under suites `0x0001` and `0xF001`, plus the 3-party / Update / Remove / Protect-Unprotect / Export / external-join scenarios.
- [ ] **Core stays zero-dep**: from repo root `nix develop -c go list -deps ./mls/... ./ironcore/...` prints no third-party module; `nix develop -c go vet ./...` passes. Root `go.mod` unchanged.
- [ ] `interop/cmd/mls-interop` binary builds and serves `MLSClient` on a TCP port.
- [ ] `interop/README.md` documents regen, the official-runner invocation, OpenMLS/mls-rs cross-runs, and the X-Wing caveat.
- [ ] `git status` shows only the intended new files under `interop/` and the `flake.nix` edit — **no `zz_*` / `throwaway_*` stragglers**.

---

## Notes

- **Running vs the official runner / OpenMLS / mls-rs.** Build the binary (`go build -o mls-interop ./interop/cmd/mls-interop`) and start it on a port; point the `mlswg/mls-implementations` test-runner at `localhost:<port>` as one client, and OpenMLS's or mls-rs's interop server as another. Our `SupportedCiphersuites` advertises `{0x0001, 0x0002}`, the suites those stacks share, so cross-stack scenarios negotiate a common suite. The structural deliverable is the runnable server + the self-conformance test that proves the binding; cross-stack runs are a follow-up CI job.
- **X-Wing (0xF001) is private-use.** It is omitted from `SupportedCiphersuites` (the official runner would otherwise try to pair it with stacks that lack it). It is exercised **only** in our self-conformance test, which is valid: self-vs-self convergence proves the gRPC binding and the engine for the PQ suite. It will not interop with OpenMLS/mls-rs (they don't implement X-Wing).
- **Pending-commit modeling.** The engine advances the committer in place during `Commit`; the server stashes the resulting epoch authenticator and returns it from `HandlePendingCommit`. Do not issue old-epoch operations on a handle between `Commit` and `HandlePendingCommit`.
- **By-value Add requirement.** Welcome-producing Adds must go through `Commit.by_value` (engine collects `addedKPs` only from by-value proposals). `AddProposal` (by-reference) is still useful for Update/Remove-style by-reference commits and is implemented, but a by-reference Add will not generate a Welcome.
- **`encrypt_handshake`.** The engine frames handshakes as PublicMessage; `encrypt_handshake=true` is rejected with `Unimplemented`. Application messages (`Protect`/`Unprotect`) are always PrivateMessage regardless.
- **`removed_id` semantics.** Resolved as the basic-credential **identity** bytes (matched against `LeafCredential`), consistent with how identities are supplied at `CreateGroup`/`CreateKeyPackage`.
- **grpc version.** Seed with `go get google.golang.org/grpc@v1.66.0`; `go mod tidy` resolves the compatible `v1.81.1` pulled transitively by `genproto`. Both build the harness; pin whatever `tidy` settles on in the committed `go.sum`.
- **Unimplemented RPCs** (ReInit*, Branch*, external-signer*, `NewMemberAddProposal`, PSK proposals, `StorePSK`, `GroupContextExtensionsProposal`) return `codes.Unimplemented` for free via the embedded `UnimplementedMLSClientServer`; see the support matrix for the per-RPC reason. They become real work only if/when the engine grows those features.
```

