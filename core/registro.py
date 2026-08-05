"""OBSIDIAN central logging -- roadmap step 10.

Replaces the print(..., file=sys.stderr) calls scattered through the code.
Everything goes to a file with levels (~/.obsidian/obsidian.log); only what
matters (WARNING+) reaches the console, so the terminal isn't cluttered by every
OSINT source that fails."""
import logging, os
from core.config import HOME

LOG_DIR  = os.path.join(HOME, '.obsidian')
LOG_FILE = os.path.join(LOG_DIR, 'obsidian.log')
os.makedirs(LOG_DIR, exist_ok=True)

_FMT = logging.Formatter('%(asctime)s %(levelname)-7s %(message)s', '%Y-%m-%d %H:%M:%S')


def get_logger(nombre='obsidian'):
    """Returns the OBSIDIAN logger, configured only once.
    File = DEBUG (everything, for diagnostics); console = WARNING (only serious)."""
    log = logging.getLogger(nombre)
    if not log.handlers:
        log.setLevel(logging.DEBUG)
        fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_FMT)
        log.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setLevel(logging.WARNING)
        sh.setFormatter(_FMT)
        log.addHandler(sh)
    return log
