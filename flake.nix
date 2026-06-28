{
  description = "Go development environment for mls-mlkem-go";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    go-overlay.url = "github:purpleclay/go-overlay";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      go-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ go-overlay.overlays.default ];
        };

        # Go version is resolved from ./go.mod, bundled with a curated
        # toolchain (gopls, golangci-lint, govulncheck, delve) pinned to it.
        go = (pkgs.go-bin.fromGoMod ./go.mod).withDefaultTools;

        # Shared base tooling for both shells: the Go toolchain, the protobuf
        # compiler + Go/gRPC plugins (for `make generate`), and the bare-shell
        # essentials `make`/`git` so `make <target>` and the e2e script run.
        basePackages = [
          go
          pkgs.protobuf
          pkgs.protoc-gen-go
          pkgs.protoc-gen-go-grpc
          pkgs.gnumake
          pkgs.git
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          packages = basePackages;

          # Use the Nix-provided toolchain; never auto-download another one.
          GOTOOLCHAIN = "local";

          shellHook = ''
            echo "Entered Go dev shell: $(go version)"
          '';
        };

        # The `e2e` shell adds the Rust toolchain so `scripts/e2e-openmls.sh`
        # can build OpenMLS's `interop_client` crate (cargo) and the official
        # mlswg test-runner. Enter with: `nix develop .#e2e`.
        devShells.e2e = pkgs.mkShell {
          packages = basePackages ++ [
            pkgs.cargo
            pkgs.rustc
          ];

          GOTOOLCHAIN = "local";

          shellHook = ''
            echo "Entered e2e dev shell: $(go version), $(rustc --version)"
          '';
        };
      }
    );
}
