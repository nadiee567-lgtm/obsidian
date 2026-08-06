#!/usr/bin/env bash
# OBSIDIAN -- one-shot local startup (F7 step 100).
# Creates the venv if missing, installs deps and runs the web UI.
#   ./run.sh                    # local bind, password from OBSIDIAN_PASSWORD or generated
#   OBSIDIAN_PASSWORD=x ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
if [ ! -d "$VENV" ]; then
    echo "[obsidian] creating venv…"
    python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
. "$VENV/bin/activate"

echo "[obsidian] installing dependencies…"
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "[obsidian] starting at http://localhost:${OBSIDIAN_PORT:-8767}/v2"
exec python obsidian_web.py
