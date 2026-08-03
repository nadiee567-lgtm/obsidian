"""Configuración central de OBSIDIAN — paso 9 del roadmap.

Rutas, puertos y constantes en un solo lugar en vez de regadas por el código.
Puerto y host se pueden sobreescribir por variable de entorno."""
import os

HOME       = os.path.expanduser('~')
HOME_INIT  = HOME
CASES_DIR  = os.path.join(HOME, 'obsidian-cases')
STATIC_DIR = os.path.join(HOME, 'obsidian-static')
CASES_DB   = os.path.join(CASES_DIR, 'casos.db')

PORT       = int(os.environ.get('OBSIDIAN_PORT', 8767))
HOST       = os.environ.get('OBSIDIAN_HOST', '127.0.0.1')
VIS_FILE   = 'vis-network.min.js'

# F3: cada workspace (caso) es una base SQLite aislada dentro de esta carpeta.
WORKSPACES_DIR = os.path.join(HOME, '.obsidian', 'workspaces')
