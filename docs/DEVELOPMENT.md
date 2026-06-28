# Developing mls-mlkem-go

This is the contributor guide. For the project overview and feature matrix, see
the [README](../README.md).

## The Nix workflow

Go is **not** on the bare `PATH` — the toolchain (Go 1.26.x, `protoc`,
`protoc-gen-go`, `protoc-gen-go-grpc`, `make`, `git`) is provided by the Nix
flake with `GOTOOLCHAIN=local` (never auto-downloads a toolchain).

```sh
nix develop            # enter the default dev shell, then run go / make directly
go test ./...
make test
```

Or wrap a single command without entering the shell:

```sh
nix develop -c make test
```

Two shells are defined in [`flake.nix`](../flake.nix):

| Shell | Enter with | Adds |
|---|---|---|
| `default` | `nix develop` | Go, protoc + plugins, make, git |
| `e2e` | `nix develop .#e2e` | the above **plus** `cargo` + `rustc` (to build OpenMLS for the e2e gate) |

If you use `direnv`, the repo's `.envrc` (`use flake`) loads the default shell
automatically.

### Make targets

Run `make help` for the list. Every target wraps its command in the Nix shell
(via `NIX ?= nix develop -c`), so `make <target>` works from a bare shell. Inside
`nix develop` you can run the inner `go` commands directly, or override the
wrapper: `make test NIX=`.

| Target | What it does |
|---|---|
| `make test` | root module `go test ./...` |
| `make kat` | the official MLS Known-Answer Tests (`go test ./mls/... -run KAT`) |
| `make race` | IronCore layer under `-race` |
| `make vet` / `make fmt` / `make fmt-check` | `go vet` / `gofmt -w` / gofmt lint |
| `make conformance` | the gRPC interop gate (`cd interop && go test ./...`) |
| `make generate` | regenerate the interop proto stubs (needs `protoc`) |
| `make check-zero-dep` | prove the root module is stdlib-only |
| `make e2e-openmls` | the reproducible end-to-end test vs OpenMLS |
| `make clean` | remove build outputs + the `.e2e/` workdir |

## The zero-dependency rule

The root module `github.com/trevex/mls-mlkem-go` (everything under `mls/` and
`ironcore/`) is **standard-library only**. `go.mod` has **no `require` block**.
All third-party dependencies (gRPC, protobuf) live in the **separate nested
module** under `interop/` (`github.com/trevex/mls-mlkem-go/interop`), which
`replace`s the root with `../`.

When adding code under `mls/` or `ironcore/`, do not import anything outside the
Go standard library. The invariant is enforced by
[`interop/check-zero-dep.sh`](../interop/check-zero-dep.sh) (`make
check-zero-dep`), which checks the empty `require` block, runs `go list -deps`
to confirm no third-party packages, and runs `go vet`/`go test` on both modules.

## Codec convention

All wire (de)serialization uses the helpers in
[`mls/syntax`](../mls/syntax) (`*syntax.Builder` for encoding, `*syntax.Cursor`
for decoding) and follows a fixed three-method shape per type:

1. `func (T) marshal(b *syntax.Builder) error` — appends the type's fields to a
   shared builder (composable; nested types call each other's `marshal`).
2. `func decodeT(c *syntax.Cursor) (T, error)` — reads exactly the type's fields
   from a shared cursor (composable; advances the cursor).
3. The public boundary methods:
   - `func (T) MarshalMLS() ([]byte, error)` — `NewBuilder()` → `marshal` →
     `Bytes()`.
   - `func (t *T) UnmarshalMLS(data []byte) error` — `NewCursor(data)` →
     `decodeT` → **reject trailing bytes** with `cur.Empty()`.

The trailing-byte check is mandatory: `UnmarshalMLS` must error if the cursor is
not empty after decoding. Example (`mls/tree/credential.go`):

```go
func (c *Credential) UnmarshalMLS(data []byte) error {
    cur := syntax.NewCursor(data)
    v, err := decodeCredential(cur)
    if err != nil {
        return err
    }
    if !cur.Empty() {
        return fmt.Errorf("tree: trailing bytes after Credential")
    }
    *c = v
    return nil
}
```

`syntax` provides `WriteUint{8,16,32,64}`, `WriteVarint`, `WriteOpaqueV`,
`WriteRaw` and the corresponding `Read…`/`ReadOpaqueV` on the cursor — these map
directly to the RFC 9420 presentation language (§2.1).

## KAT vectors

The official RFC 9420 test vectors are vendored as JSON under
[`mls/testdata/`](../mls/testdata) (sourced from
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations)),
e.g. `tree-math.json`, `key-schedule.json`, `treekem.json`,
`message-protection.json`, `welcome.json`, `passive-client-*.json`.

Each category has a `*_kat_test.go` (or `kat_test.go`) loader that drives the
engine against the vectors; the test functions are named `Test…KAT`, so:

```sh
make kat                       # = go test ./mls/... -run KAT
go test ./mls/tree -run KAT -v # one package
```

To refresh the vectors, replace the JSON files from the upstream repo and re-run
`make kat`.

## Regenerating the proto

The interop module commits its generated gRPC stubs
(`interop/proto/mlspb/*.pb.go`) so it builds without `protoc`. After editing
`interop/proto/mls_client.proto`, regenerate them:

```sh
make generate          # wraps protoc with the source-relative go / go-grpc plugins
```

(Equivalent to `cd interop && just gen` — the [`interop/justfile`](../interop/justfile)
holds the same command.)

## Adding a ciphersuite

Ciphersuites live in the registry in [`mls/cipher/suite.go`](../mls/cipher/suite.go):

1. Add the `CipherSuite` constant (the 2-byte RFC 9420 §17.1 id).
2. Add an entry to the `registry` map wiring the primitive constructors
   (`NewHash`, `Sig`, `kem`, `kdf`, `aead`, and `curve` for DHKEM suites).
   Non-DHKEM suites (e.g. X-Wing) leave `curve` nil and supply their own KEM —
   see [`suite_pq.go`](../mls/cipher/suite_pq.go) and
   [`xwing.go`](../mls/cipher/xwing.go).
3. Add coverage: a unit test in `mls/cipher`, and — if it should be exercised by
   the gRPC gate — wire it into `interop/conformance_test.go`.

Private-use suites (like `0xF001` X-Wing) are intentionally **not** advertised
via `SupportedCiphersuites` in the interop server, so the public test-runner
never pairs them with stacks that don't implement them; they are validated only
in the self-conformance gate.

## Test layering

| Layer | Command | Scope |
|---|---|---|
| Known-Answer Tests | `make kat` | RFC 9420 vectors, per primitive/sub-protocol |
| Unit + convergence | `make test` | engine correctness, self-vs-self convergence |
| Race | `make race` | IronCore concurrency (sequencer, controller) |
| Conformance gate | `make conformance` | 21-subtest in-process gRPC self-conformance |
| End-to-end | `make e2e-openmls` | cross-stack interop vs OpenMLS (suite 1) |

### The e2e gate in detail

[`scripts/e2e-openmls.sh`](../scripts/e2e-openmls.sh) is reproducible from a
clean checkout: it clones (or reuses) `mlswg/mls-implementations` and `openmls`
into a workdir (`./.e2e` by default, gitignored; override with `E2E_WORKDIR`,
force rebuilds with `E2E_REBUILD=1`), builds the runner (it protoc-generates the
runner's proto, bumps gRPC to a `SupportPackageIsVersion9`-capable release, and
`go mod tidy`s), builds OpenMLS's `interop_client` (cargo release), builds our
server, starts both on free ports, and runs the scenarios on suite 1 with
PublicMessage handshakes — exiting 0 only if every role assignment passes.

The scenario configs in [`scripts/e2e-configs/`](../scripts/e2e-configs) are
curated to the subset both stacks support on suite 1. They are faithful subsets
of the upstream mlswg configs: `application.json` keeps `in_order` /
`out_of_order_within_epoch` (dropping `out_of_order_across_epochs`, which needs
the prior-epoch decryption window we don't implement); `commit.json` keeps
`empty` / `add` / `remove` / `update` (dropping the PSK and
GroupContextExtensions scripts). The runner fails a whole config if any single
script fails, so a green gate requires supported-only configs. As the
unimplemented features land, extend these configs (and the README matrix)
accordingly.

## Design & roadmap

- **Design spec** — including the **§5 DS-ordering / failover correctness
  proof** (the single-linearization-point argument, B1 fencing, fork
  detection): [`docs/superpowers/specs/`](superpowers/specs/).
- **Implementation plans** (15): [`docs/superpowers/plans/`](superpowers/plans/).
