"""Logging central de OBSIDIAN — paso 10 del roadmap.

Reemplaza los print(..., file=sys.stderr) regados por el código. Todo va a un
archivo con niveles (~/.obsidian/obsidian.log); a la consola solo lo importante
(WARNING+), para no ensuciar la terminal con cada fuente OSINT que falla."""
import logging, os
from core.config import HOME

LOG_DIR  = os.path.join(HOME, '.obsidian')
LOG_FILE = os.path.join(LOG_DIR, 'obsidian.log')
os.makedirs(LOG_DIR, exist_ok=True)

_FMT = logging.Formatter('%(asctime)s %(levelname)-7s %(message)s', '%Y-%m-%d %H:%M:%S')


def get_logger(nombre='obsidian'):
    """Devuelve el logger de OBSIDIAN, configurado una sola vez.
    Archivo = DEBUG (todo, para diagnóstico); consola = WARNING (solo lo grave)."""
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
