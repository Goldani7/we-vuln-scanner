#!/usr/bin/env bash
# Goldani Scanner (web-vuln-scanner) installer: creates the venv, installs everything and, if you
# want, opens the interactive menu right away. Idempotent — safe to rerun to update dependencies.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 not found. Install Python 3.10+ and run this script again." >&2
    exit 1
fi

if [ ! -f pyproject.toml ]; then
    echo "Error: run this script from inside the cloned repository (pyproject.toml not found)." >&2
    exit 1
fi

if [ ! -d .venv ]; then
    echo "==> Creating the virtual environment (.venv)..."
    python3 -m venv .venv
fi

echo "==> Installing dependencies..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -e . -q

echo
echo "Done! From now on:"
echo "    source .venv/bin/activate"
echo "    goldani              # interactive menu"
echo "    wvs --help           # full command line"
echo

read -r -p "Open the interactive menu now? [Y/n] " resp || resp="n"
case "$resp" in
    [nN]*) ;;
    *) exec .venv/bin/goldani ;;
esac
