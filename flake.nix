{
  description = "Python dev environment from requirements.txt (No venv)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    pyproject-nix.url = "github:nix-community/pyproject.nix";
    pyproject-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, pyproject-nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        # Define the interpreter explicitly
        python = pkgs.python3;

        # 1. Load requirements.txt
        project = pyproject-nix.lib.project.loadRequirementsTxt {
          projectRoot = ./.;
        };

        # 2. Build the Python Environment
        # FIX: explicitly pass { inherit python; } (not python3)
        # FIX: use withPackages, which accepts the function returned by the renderer
        pythonEnv = pkgs.python3.withPackages (project.renderers.withPackages {
          inherit python;
        });
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pythonEnv
            pkgs.ruff
          ];

          shellHook = ''
            echo "🐍 Python $(python --version) environment loaded (Pure Nix)"
            echo "   Packages loaded from requirements.txt"
          '';
        };
      }
    );
}
