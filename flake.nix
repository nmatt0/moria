{
  description = "moria (firmware extract)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
          system:
          f {
            pkgs = nixpkgs.legacyPackages.${system};
            inherit system;
          }
        );
    in
    {
      packages = forAllSystems (
        {
          pkgs,
          system,
        }:
        let
          moria = pkgs.callPackage ./package.nix { };
        in
        {
          inherit moria;
          default = moria;
        }
      );

      devShells = forAllSystems (
        {
          pkgs,
          system,
        }:
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.moria ];
            packages = with pkgs; [ python3 ];
          };
        }
      );

      formatter = forAllSystems ({ pkgs, ... }: pkgs.nixfmt-tree);
    };
}
