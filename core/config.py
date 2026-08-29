"""OBSIDIAN central configuration -- roadmap step 9.

Paths, ports and constants in a single place instead of scattered through the
code. Port and host can be overridden by environment variable."""
import os

HOME       = os.path.expanduser('~')
HOME_INIT  = HOME
CASES_DIR  = os.path.join(HOME, 'obsidian-cases')
STATIC_DIR = os.path.join(HOME, 'obsidian-static')
CASES_DB   = os.path.join(CASES_DIR, 'casos.db')

PORT       = int(os.environ.get('OBSIDIAN_PORT', 8767))
HOST       = os.environ.get('OBSIDIAN_HOST', '127.0.0.1')
VIS_FILE   = 'vis-network.min.js'

WORKSPACES_DIR = os.path.join(HOME, '.obsidian', 'workspaces')
