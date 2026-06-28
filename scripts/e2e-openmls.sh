#!/usr/bin/env bash
# e2e-openmls.sh — reproducible end-to-end interop test of this MLS engine
# against OpenMLS, driven by the official mlswg/mls-implementations test-runner.
#
# It clones (or reuses) the runner + OpenMLS, builds every binary, starts our
# gRPC server and OpenMLS's interop_client on free ports, and runs a set of
# known-interoperable scenarios on MLS ciphersuite 1
# (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) in two passes: PublicMessage
# handshakes, then encrypted (PrivateMessage) member handshakes.
#
# Run it inside the Rust-enabled dev shell (cargo + rustc are required to build
# OpenMLS):
#
#     nix develop .#e2e -c bash scripts/e2e-openmls.sh
#     # or:  make e2e-openmls
#
# Environment:
#   E2E_WORKDIR   working directory for clones + build outputs (default ./.e2e)
#   E2E_REBUILD   set to 1 to force re-clone/re-build of everything
#
# Exit code 0 = every scenario passed against OpenMLS; non-zero = a failure.

set -euo pipefail

# --- locate the repo root (this script lives in scripts/) --------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WORKDIR="${E2E_WORKDIR:-$REPO_ROOT/.e2e}"
REBUILD="${E2E_REBUILD:-0}"

MLS_IMPL_REPO="https://github.com/mlswg/mls-implementations"
OPENMLS_REPO="https://github.com/openmls/openmls"

MLS_IMPL_DIR="$WORKDIR/mls-implementations"
OPENMLS_DIR="$WORKDIR/openmls"
BIN_DIR="$WORKDIR/bin"

RUNNER_BIN="$BIN_DIR/test-runner"
SERVER_BIN="$BIN_DIR/mls-interop"
OPENMLS_BIN="$OPENMLS_DIR/target/release/interop_client"

mkdir -p "$WORKDIR" "$BIN_DIR"

# --- pretty logging ----------------------------------------------------------
log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }

# --- preflight: required tools ----------------------------------------------
for tool in go cargo rustc protoc git; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    fail "required tool '$tool' not on PATH — run inside 'nix develop .#e2e'"
    exit 1
  fi
done

# --- clone-or-update helper --------------------------------------------------
clone_or_update() {
  local repo="$1" dir="$2"
  if [ -d "$dir/.git" ]; then
    log "reusing existing clone: $dir"
  elif [ -e "$dir" ]; then
    # A symlink or pre-populated dir (used to speed up local verification).
    log "reusing existing path: $dir"
  else
    log "cloning $repo -> $dir"
    git clone --depth 1 "$repo" "$dir"
  fi
}

# --- 1. fetch sources --------------------------------------------------------
clone_or_update "$MLS_IMPL_REPO" "$MLS_IMPL_DIR"
clone_or_update "$OPENMLS_REPO" "$OPENMLS_DIR"

# --- 2. build the mlswg test-runner -----------------------------------------
# The upstream repo gitignores the generated proto .go, so we protoc-generate
# them. The fresh gRPC stubs require a recent grpc runtime (SupportPackageIs-
# Version9), so we bump grpc + protobuf to latest and tidy before building.
if [ "$REBUILD" = "1" ] || [ ! -x "$RUNNER_BIN" ]; then
  log "building test-runner"
  (
    cd "$MLS_IMPL_DIR"
    protoc --proto_path=interop/proto \
      --go_out=interop/proto --go_opt=paths=source_relative \
      --go-grpc_out=interop/proto --go-grpc_opt=paths=source_relative \
      interop/proto/mls_client.proto
    go get google.golang.org/grpc@latest google.golang.org/protobuf@latest
    go mod tidy
    go build -o "$RUNNER_BIN" ./interop/test-runner
  )
  ok "test-runner -> $RUNNER_BIN"
else
  log "reusing test-runner: $RUNNER_BIN"
fi

# --- 3. build OpenMLS interop_client (cargo release) -------------------------
if [ "$REBUILD" = "1" ] || [ ! -x "$OPENMLS_BIN" ]; then
  log "building OpenMLS interop_client (cargo build --release; this is slow)"
  (
    cd "$OPENMLS_DIR"
    cargo build --release -p interop_client
  )
  ok "interop_client -> $OPENMLS_BIN"
else
  log "reusing OpenMLS interop_client: $OPENMLS_BIN"
fi

# --- 4. build our gRPC server (nested interop module) ------------------------
if [ "$REBUILD" = "1" ] || [ ! -x "$SERVER_BIN" ]; then
  log "building our mls-interop server"
  (
    cd "$REPO_ROOT/interop"
    go build -o "$SERVER_BIN" ./cmd/mls-interop
  )
  ok "mls-interop -> $SERVER_BIN"
else
  log "reusing mls-interop server: $SERVER_BIN"
fi

# --- 5. pick two free TCP ports ---------------------------------------------
port_in_use() {
  # Returns 0 (true) if something is listening on 127.0.0.1:$1.
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&-; return 0; } || return 1
}
free_port() {
  local p
  while :; do
    p=$(( (RANDOM % 20000) + 20000 ))
    port_in_use "$p" || { echo "$p"; return 0; }
  done
}

OUR_PORT="$(free_port)"
OPENMLS_PORT="$(free_port)"
while [ "$OPENMLS_PORT" = "$OUR_PORT" ]; do OPENMLS_PORT="$(free_port)"; done

# --- 6. start the two servers; clean up on exit ------------------------------
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

log "starting our server on :$OUR_PORT"
"$SERVER_BIN" -port ":$OUR_PORT" >"$WORKDIR/our-server.log" 2>&1 &
PIDS+=("$!")

log "starting OpenMLS interop_client on :$OPENMLS_PORT"
"$OPENMLS_BIN" --host 127.0.0.1 -p "$OPENMLS_PORT" >"$WORKDIR/openmls.log" 2>&1 &
PIDS+=("$!")

# Wait for both ports to come up (max ~15s each).
wait_port() {
  local p="$1" name="$2" i
  for i in $(seq 1 60); do
    port_in_use "$p" && { log "$name is up on :$p"; return 0; }
    sleep 0.25
  done
  fail "$name did not come up on :$p"
  return 1
}
wait_port "$OUR_PORT" "our server"
wait_port "$OPENMLS_PORT" "OpenMLS"

# --- 7. run the scenarios ----------------------------------------------------
# Each config is run twice — once with PublicMessage handshakes, once with
# encrypted (PrivateMessage) member handshakes — across both clients (the runner
# exercises every alice/bob role assignment). Exit code 0 = all combos passed.
#
# We ship repo-local configs under scripts/e2e-configs/ that contain exactly the
# scenarios both stacks support on suite 1: by-reference Add welcomes + 3-party
# (welcome.json), in-/within-epoch Protect/Unprotect (application.json), and
# empty/add/remove/update commits (commit.json). These are faithful subsets of
# the upstream mlswg `application.json` and `commit.json`, trimmed to drop the
# scenarios this server intentionally does not implement yet (PSK,
# GroupContextExtensions, prior-epoch application decryption) — the runner fails
# a whole config if any one script fails, so a green gate needs supported-only
# configs. See docs/DEVELOPMENT.md and the README limitation matrix.
CONFIG_DIR="$REPO_ROOT/scripts/e2e-configs"
declare -a CONFIGS=(
  "$CONFIG_DIR/welcome.json"
  "$CONFIG_DIR/application.json"
  "$CONFIG_DIR/commit.json"
)

declare -a RESULTS=()
overall=0

# run_pass LABEL EXTRA_RUNNER_FLAGS...
# Runs every config against both clients for the given handshake-framing mode.
# Pass `-public=true` for PublicMessage handshakes, `-public=false` for encrypted
# (PrivateMessage) member handshakes — the runner sets encrypt_handshake on
# createGroup/joinGroup accordingly. (External-commit joins stay PublicMessage
# per RFC 9420 regardless; the runner handles that.)
run_pass() {
  local label="$1"; shift
  local cfg name
  for cfg in "${CONFIGS[@]}"; do
    name="$(basename "$cfg") [$label]"
    log "scenario: $name (suite 1, $label)"
    if "$RUNNER_BIN" \
        -config "$cfg" \
        -suite 1 "$@" \
        -client "127.0.0.1:$OUR_PORT" \
        -client "127.0.0.1:$OPENMLS_PORT" 2>&1 | sed 's/^/    /'; then
      ok "$name"
      RESULTS+=("PASS  $name")
    else
      fail "$name"
      RESULTS+=("FAIL  $name")
      overall=1
    fi
  done
}

# Pass 1: PublicMessage handshakes (the original gate).
run_pass public -public=true
# Pass 2: encrypted member handshakes (PrivateMessage) — exercises our
# encrypt_handshake support end-to-end against OpenMLS on suite 1.
run_pass encrypted -public=false

# --- 8. summary --------------------------------------------------------------
echo ""
echo "========== e2e vs OpenMLS summary (suite 1, public + encrypted) =========="
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo "========================================================================="
if [ "$overall" -eq 0 ]; then
  ok "all scenarios interoperate with OpenMLS"
else
  fail "one or more scenarios failed (see logs in $WORKDIR)"
fi
exit "$overall"
