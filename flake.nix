{
  description = "Go development environment";

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
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            go
            pkgs.protobuf
            pkgs.protoc-gen-go
            pkgs.protoc-gen-go-grpc
          ];

          # Use the Nix-provided toolchain; never auto-download another one.
          GOTOOLCHAIN = "local";

          shellHook = ''
            echo "Entered Go dev shell: $(go version)"
          '';
        };
      }
    );
}
