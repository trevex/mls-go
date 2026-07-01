# Makefile for mls-go
#
# Every target wraps its command in the Nix dev shell so it works from a bare
# shell where Go is not on PATH. If you'd rather not pay the wrapper cost on
# each call, enter the shell once and run the inner commands (or `make`) directly:
#
#     nix develop          # then: go test ./...  /  make test  / ...
#
# Go targets use the default shell; the e2e target needs the Rust toolchain and
# uses the `e2e` shell.

# Wrappers. Override NIX=… to run a target without Nix (e.g. inside the shell).
# NOTE: the `#` in `.#e2e` must be escaped as `\#`, or Make treats the rest of
# the line as a comment and NIX_E2E silently collapses to `nix develop .`.
NIX     ?= nix develop -c
NIX_E2E ?= nix develop .\#e2e -c

.DEFAULT_GOAL := help

.PHONY: help test kat race vet fmt fmt-check lint conformance generate check-zero-dep e2e-openmls sim clean bench scalebench

help: ## List available targets
	@echo "mls-go — make targets (all run inside the Nix dev shell):"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort \
	  | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Tip: 'nix develop' once, then run 'go test ./...' or 'make <target>' directly."

test: ## Run the root module test suite (go test ./...)
	$(NIX) go test ./...

sim: ## Run the MetalNet dual-redundancy simulation suite (5 scenarios + CLI smoke)
	$(NIX) go test ./sim/...
	$(NIX) go run ./cmd/metalsim -scenario all

bench: ## Run the Tier-1 MLS crypto micro-benchmarks (commit/apply, all suites)
	$(NIX) go test ./bench/ -run '^$$' -bench . -benchmem

scalebench: ## Project the datacenter scaling sweep + verdict (classical + X-Wing)
	$(NIX) go run ./cmd/scalebench -suite 0x0001
	$(NIX) go run ./cmd/scalebench -suite 0xF001

kat: ## Run the official MLS Known-Answer Tests (RFC 9420 test vectors)
	$(NIX) go test ./mls/... -run KAT -v

race: ## Run the IronCore layer under the race detector
	$(NIX) go test -race ./ironcore/...

vet: ## Run go vet on the root module
	$(NIX) go vet ./...

fmt: ## Format all Go sources in place (gofmt -w)
	$(NIX) gofmt -w mls ironcore sim cmd
	$(NIX) bash -c 'cd interop && gofmt -w cmd server *.go'

fmt-check: ## Fail if any Go source is not gofmt-clean
	$(NIX) bash -c 'out=$$(gofmt -l mls ironcore sim cmd interop); if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi'

lint: ## Run golangci-lint (root + interop are separate modules, so two invocations)
	$(NIX) golangci-lint run ./...
	$(NIX) bash -c 'cd interop && golangci-lint run ./...'

conformance: ## Run the gRPC interop conformance gate (interop module)
	$(NIX) bash -c 'cd interop && go test ./...'

generate: ## Regenerate the interop protobuf/gRPC stubs (needs protoc)
	$(NIX) bash -c 'cd interop && protoc --proto_path=proto \
	  --go_out=proto/mlspb --go_opt=paths=source_relative \
	  --go-grpc_out=proto/mlspb --go-grpc_opt=paths=source_relative \
	  proto/mls_client.proto'

check-zero-dep: ## Verify the root module stays stdlib-only (zero third-party deps)
	$(NIX) bash interop/check-zero-dep.sh

e2e-openmls: ## Build + run the reproducible end-to-end interop vs OpenMLS (suite 1)
	$(NIX_E2E) bash scripts/e2e-openmls.sh

clean: ## Remove build outputs and the e2e workdir
	rm -rf .e2e interop/mls-interop
