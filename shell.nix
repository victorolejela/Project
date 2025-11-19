{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "hospital-portal";

  buildInputs = [
    pkgs.python311
    pkgs.python311Packages.pip
    pkgs.python311Packages.virtualenv
    pkgs.nodejs_22
    pkgs.git
  ];

  shellHook = ''
    # Create and activate virtual environment if missing
    if [ ! -d ".venv" ]; then
      python -m venv .venv
    fi
    source .venv/bin/activate

    echo "✅ Flask & Python environment ready — run: python app.py"
  '';
}

