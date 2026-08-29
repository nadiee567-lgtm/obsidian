"""OBSIDIAN security validators and sanitizers -- step 8 (core/).

PURE functions: they don't touch `case`, `SESSION` or Flask. Their only
dependency is CASES_DIR (to contain case paths). They close command injection,
argument injection, path traversal and SSRF. Tested in test_seguridad.py.
"""
import os, re, socket, ipaddress
from urllib.parse import urlparse

from core.config import CASES_DIR

_SHELL_DANGEROUS = set(' \t\n\r;&|`$<>(){}[]!*?~"\'\\')

_MODULE_TYPE = {
    'user': 'user', 'domain': 'domain', 'ip': 'ip', 'email': 'email',
    'ssl': 'domain', 'typosquatting': 'domain', 'takeover': 'domain',
}

_RE_DOMAIN = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$')
_RE_USER = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}$')
_RE_EMAIL   = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$')


def _is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _validate(arg, type):
    """True only if `arg` matches EXACTLY the expected shape of `type`.
    Allowlist: closes command injection AND argument injection at once."""
    arg = (arg or '').strip()
    if not arg or len(arg) > 253:
        return False
    if type == 'domain':  return bool(_RE_DOMAIN.match(arg))
    if type == 'ip':       return _is_ip(arg)
    if type == 'user':  return bool(_RE_USER.match(arg))
    if type == 'email':    return bool(_RE_EMAIL.match(arg))
    return _safe_target(arg)


def _safe_target(arg):
    """Generic check for targets with no fixed type (distrobox, shodan).
    Rejects empty, leading '-' (argument injection) and shell metacharacters."""
    arg = (arg or '').strip()
    if not arg or arg.startswith('-'):
        return False
    return not any(c in _SHELL_DANGEROUS for c in arg)


def _case_slug(name):
    """Case name sanitized for use as a filename. Keeps only [A-Za-z0-9 _.-],
    no path separators or '..'. Returns '' if it ends up invalid -- so a name
    like '../../.bashrc' does not write/read outside CASES_DIR."""
    name = (name or '').strip()
    if '/' in name or '\\' in name or '..' in name:
        return ''
    limpio = re.sub(r'[^A-Za-z0-9 _.-]', '', name).strip()[:80]
    if not limpio or set(limpio) <= {'.'}:
        return ''
    return limpio


def _safe_case_path(name, sufijo='.json'):
    """Path inside CASES_DIR for a sanitized case, or None if invalid or it would
    try to escape the directory (defense in depth with realpath)."""
    slug = _case_slug(name)
    if not slug:
        return None
    path = os.path.join(CASES_DIR, slug + sufijo)
    if not os.path.realpath(path).startswith(os.path.realpath(CASES_DIR) + os.sep):
        return None
    return path


def _public_url(url):
    """True only if `url` is http/https to a host that resolves to PUBLIC IP(s).
    Blocks SSRF: localhost, LAN (10/172.16/192.168), link-local (169.254.x,
    including cloud metadata), reserved and multicast."""
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
