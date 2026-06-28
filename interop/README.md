# mls-go interop harness

gRPC conformance harness for the MLS (RFC 9420) engine, implementing the
official [`MLSClient` service](https://github.com/mlswg/mls-implementations/blob/main/interop/proto/mls_client.proto).

## Module layout

```
interop/           ← nested Go module (github.com/trevex/mls-go/interop)
  cmd/mls-interop/ ← standalone gRPC server binary
  proto/           ← vendored mls_client.proto + committed generated stubs
  proto/mlspb/     ← generated Go bindings (mls_client.pb.go, mls_client_grpc.pb.go)
  server/          ← MLSClient server implementation
  conformance_test.go ← in-process self-conformance gate (the gate)
```

The root module (`github.com/trevex/mls-go`) remains **stdlib-only**;
all gRPC / protobuf dependencies are scoped to this nested module.

## Self-conformance test (the gate)

```sh
# From the repo root, using the Nix devshell Go toolchain:
nix develop -c bash -c 'cd interop && go test ./... -v'
```

Runs 7 scenarios × 3 ciphersuites (0x0001 + 0x0002 + 0xF001) entirely in-process
over a `bufconn` listener.  All 21 sub-tests must pass.

Scenarios covered:
1. **1:1 welcome-join** — `CreateGroup` → `CreateKeyPackage` → `Commit(by_value Add)` → `HandlePendingCommit` → `JoinGroup` → `StateAuth` equal
2. **3-party join** — Alice adds Bob, then Carol; all three `StateAuth`-equal
3. **Update commit** — Bob proposes `Update`, Alice commits by reference; all converge
4. **Remove commit** — Alice removes Carol; Alice and Bob converge
5. **Protect / Unprotect** — Alice protects application data; Bob unprotects it
6. **Export equality** — Alice and Bob derive the same exported secret
7. **External join** — Carol external-joins via `GroupInfo`; all three converge

## Running the gRPC server

Build the binary from the `interop/` directory:

```sh
nix develop ../ -c go build -o mls-interop ./cmd/mls-interop
./mls-interop -port :50051
```

Or use `just`:

```sh
cd interop && just run             # starts on :50051
cd interop && just run port=":9000"
```

## Running against the official mls-implementations test runner

1. Start this server:
   ```sh
   ./mls-interop -port :50051
   ```

2. Start another MLS implementation's interop server (e.g. OpenMLS on `:50052`,
   mls-rs on `:50053`).

3. Clone [mlswg/mls-implementations](https://github.com/mlswg/mls-implementations)
   and run its test runner from **inside that cloned repository's `interop/`
   subdirectory** (not this repo's `interop/`):
   ```sh
   # Inside the mlswg/mls-implementations clone:
   cd interop
   go run . --client "localhost:50051" --client "localhost:50052"
   ```

   The test runner discovers supported ciphersuites via `SupportedCiphersuites`
   and runs every cross-client scenario for the intersection of their suites.

### Supported ciphersuites

| Suite | Name | Status |
|---|---|---|
| 0x0001 | X25519_AES128GCM_SHA256_Ed25519 | ✅ advertised |
| 0x0002 | P256_AES128GCM_SHA256_P256 | ✅ advertised |
| 0xF001 | XWING_AES256GCM_SHA256_Ed25519 | ⚠ self-only (see below) |

### OpenMLS / mls-rs cross-runs

Both OpenMLS and mls-rs advertise suites 0x0001 and 0x0002, so cross-stack
runs on those suites are fully supported.  Point their interop servers at the
test runner alongside this server.

## X-Wing (0xF001) caveat

Ciphersuite `0xF001` (`XWING_AES256GCM_SHA256_Ed25519`) is a **private-use**
post-quantum hybrid suite.  It is **not advertised** via `SupportedCiphersuites`
because the official test runner would otherwise attempt to pair it with
implementations that do not support X-Wing.

`0xF001` is tested exclusively in the self-conformance test
(`conformance_test.go`), which proves the gRPC binding and the engine for the
PQ suite via self-vs-self convergence.  Cross-stack X-Wing interop is deferred
to when other stacks adopt the suite.

## Proto regeneration

The generated stubs (`proto/mlspb/*.pb.go`) are committed so the module builds
without `protoc`.  To regenerate after editing `proto/mls_client.proto`:

```sh
# Inside the nix devshell (protoc + plugins are on PATH):
nix develop ../ -c bash -c 'cd interop && just gen'
```

Or run `protoc` directly:
```sh
protoc --proto_path=proto \
  --go_out=proto/mlspb --go_opt=paths=source_relative \
  --go-grpc_out=proto/mlspb --go-grpc_opt=paths=source_relative \
  proto/mls_client.proto
```

## Known limitations

- **`encrypt_handshake`**: handshake encryption is supported for member
  Commit/Proposal/Update (framed as `PrivateMessage`, AEAD-encrypted for the
  delivery service), but **external-commit joins and recovery remain
  `PublicMessage` per RFC 9420** and cannot be encrypted.
  Application data (`Protect`/`Unprotect`) is always `PrivateMessage`.
- **By-reference Add proposals** (via `AddProposal` RPC) do not generate a
  Welcome when committed.  Welcome-producing Adds must go through
  `Commit.by_value`.  The official test runner's welcome scenarios use
  `by_value`, so this is compatible.
- **PSK proposals** (`StorePSK`, `ExternalPSKProposal`, `ResumptionPSKProposal`)
  are `Unimplemented`: no server-side PSK store in v1.
- **ReInit**, **Branch**, **external-signer**, `NewMemberAddProposal`,
  `GroupContextExtensionsProposal` are `Unimplemented`: these engine features
  are not yet exposed.
- **Pending-commit window**: between a `Commit` call and the corresponding
  `HandlePendingCommit`, the engine has already advanced the committer's epoch.
  Issuing old-epoch operations on that handle in this window is unsupported.
