{
  description = "EasyEnclave VM image build environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.mkosi
            pkgs.systemd
            pkgs.qemu-utils
            pkgs.bubblewrap
            pkgs.coreutils
            pkgs.util-linux
            pkgs.binutils-unwrapped  # objcopy for UKI extraction
          ];

          shellHook = ''
            echo "EasyEnclave image build environment"
            echo "  mkosi $(mkosi --version 2>/dev/null || echo 'available')"
            echo ""
            echo "Build: make build"
            echo "Clean: make clean"
          '';
        };
      });
}
