#!/usr/bin/env bash
# check-zero-dep.sh — verifies that the root mls-go module has no
# third-party Go dependencies and that both the root and interop modules
# pass `go vet` and `go test`.
#
# Run from the repo root:
#   nix develop -c bash interop/check-zero-dep.sh
#
# Exit code: 0 = all checks pass, non-zero = failure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== 1. Root go.mod has no require directives ==="
if grep -q "^require" go.mod; then
  echo "FAIL: root go.mod contains require directives"
  grep "^require" go.mod
  exit 1
fi
echo "PASS: go.mod has no require block"

echo ""
echo "=== 2. go list -deps ./mls/... ./ironcore/... — no third-party packages ==="
THIRD_PARTY=$(go list -deps ./mls/... ./ironcore/... 2>&1 \
  | grep "\." \
  | grep -v "^github\.com/trevex/mls-go" \
  | grep -v "^golang\.org/x/crypto" \
  | grep -v "^golang\.org/x/sys/cpu" \
  | grep -v "^vendor/" \
  | grep -v "^crypto/internal/" \
  || true)
if [ -n "$THIRD_PARTY" ]; then
  echo "FAIL: third-party packages found in root module:"
  echo "$THIRD_PARTY"
  exit 1
fi
echo "PASS: no third-party packages"

echo ""
echo "=== 3. Root go vet ==="
go vet ./...
echo "PASS"

echo ""
echo "=== 4. Root go test ==="
go test ./...
echo "PASS"

echo ""
echo "=== 5. Interop go vet ==="
cd "$REPO_ROOT/interop"
go vet ./...
echo "PASS"

echo ""
echo "=== 6. Interop go test (conformance gate) ==="
go test ./...
echo "PASS"

echo ""
echo "=== All checks passed ==="
