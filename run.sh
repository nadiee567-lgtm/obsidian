#!/usr/bin/env bash
# OBSIDIAN — arranque local de un jalón (F7 paso 100).
# Crea el venv si falta, instala deps y corre la web.
#   ./run.sh                    # bind local, password de OBSIDIAN_PASSWORD o generada
#   OBSIDIAN_PASSWORD=x ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
if [ ! -d "$VENV" ]; then
    echo "[obsidian] creando venv…"
    python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
. "$VENV/bin/activate"

echo "[obsidian] instalando dependencias…"
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "[obsidian] arrancando en http://localhost:${OBSIDIAN_PORT:-8767}/v2"
exec python obsidian_web.py
