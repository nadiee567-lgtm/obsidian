"""Validadores y sanitizadores de seguridad de OBSIDIAN — paso 8 (core/).

Funciones PURAS: no tocan `case`, `SESSION` ni Flask. Su única dependencia es
CASES_DIR (para contener las rutas de caso). Cierran command injection,
argument injection, path traversal y SSRF. Testeadas en test_seguridad.py.
"""
import os, re, socket, ipaddress
from urllib.parse import urlparse

from core.config import CASES_DIR

# Metacaracteres de shell — usados por el check genérico _objetivo_seguro.
_SHELL_PELIGROSOS = set(' \t\n\r;&|`$<>(){}[]!*?~"\'\\')

# Un módulo → qué tipo de objetivo espera (para validar con el patrón correcto).
_MODULO_TIPO = {
    'usuario': 'usuario', 'dominio': 'dominio', 'ip': 'ip', 'email': 'email',
    'ssl': 'dominio', 'typosquatting': 'dominio', 'takeover': 'dominio',
}

_RE_DOMINIO = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$')
_RE_USUARIO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}$')
_RE_EMAIL   = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$')


def _es_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _validar(arg, tipo):
    """True solo si `arg` encaja EXACTAMENTE en la forma esperada de `tipo`.
    Allowlist: cierra command injection Y argument injection de una vez."""
    arg = (arg or '').strip()
    if not arg or len(arg) > 253:
        return False
    if tipo == 'dominio':  return bool(_RE_DOMINIO.match(arg))
    if tipo == 'ip':       return _es_ip(arg)
    if tipo == 'usuario':  return bool(_RE_USUARIO.match(arg))
    if tipo == 'email':    return bool(_RE_EMAIL.match(arg))
    # tipo desconocido → check genérico
    return _objetivo_seguro(arg)


def _objetivo_seguro(arg):
    """Check genérico para objetivos sin tipo fijo (distrobox, shodan).
    Rechaza vacío, '-' inicial (argument injection) y metacaracteres de shell."""
    arg = (arg or '').strip()
    if not arg or arg.startswith('-'):
        return False
    return not any(c in _SHELL_PELIGROSOS for c in arg)


def _slug_caso(nombre):
    """Nombre de caso saneado para usar como archivo. Solo deja [A-Za-z0-9 _.-],
    sin separadores de ruta ni '..'. Devuelve '' si queda inválido — así un
    nombre como '../../.bashrc' no escribe/lee fuera de CASES_DIR."""
    nombre = (nombre or '').strip()
    # Rechazar de plano cualquier cosa con pinta de ruta, no "arreglarla".
    if '/' in nombre or '\\' in nombre or '..' in nombre:
        return ''
    limpio = re.sub(r'[^A-Za-z0-9 _.-]', '', nombre).strip()[:80]
    if not limpio or set(limpio) <= {'.'}:   # vacío, '.', '...'
        return ''
    return limpio


def _ruta_caso_segura(nombre, sufijo='.json'):
    """Ruta dentro de CASES_DIR para un caso saneado, o None si es inválido o
    intentara escaparse del directorio (defensa en profundidad con realpath)."""
    slug = _slug_caso(nombre)
    if not slug:
        return None
    path = os.path.join(CASES_DIR, slug + sufijo)
    if not os.path.realpath(path).startswith(os.path.realpath(CASES_DIR) + os.sep):
        return None
    return path


def _url_publica(url):
    """True solo si `url` es http/https hacia un host que resuelve a IP(s)
    PÚBLICAS. Bloquea SSRF: localhost, LAN (10/172.16/192.168), link-local
    (169.254.x, incluida la metadata de la nube), reservadas y multicast."""
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ('http', 'https') or not p.hostname:
        return False
    try:
        port = p.port or (443 if p.scheme == 'https' else 80)
        infos = socket.getaddrinfo(p.hostname, port, proto=socket.IPPROTO_TCP)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False
    return True
