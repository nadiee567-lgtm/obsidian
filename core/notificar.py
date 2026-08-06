"""Push notifications via ntfy.sh -- F7 step 96.

When the monitor detects a change, it pings the user's phone (ntfy). With no topic
configured it does nothing (degrades silently).

`build_ntfy` is PURE (builds url/headers/body), hence testable; `send_ntfy`
just sends it with requests, isolating any network failure."""
from __future__ import annotations
import requests

DEFAULT_SERVER = 'https://ntfy.sh'


def build_ntfy(topic: str, message: str, titulo: str = 'OBSIDIAN',
                   server: str = DEFAULT_SERVER, prioridad: str = 'default',
                   tags: str = 'satellite') -> tuple:
    """Returns (url, headers, body_bytes) for the ntfy POST. Sends nothing."""
    url = f"{server.rstrip('/')}/{topic.lstrip('/')}"
    headers = {'Title': titulo, 'Priority': prioridad, 'Tags': tags}
    return url, headers, message.encode('utf-8')


def send_ntfy(topic: str, message: str, titulo: str = 'OBSIDIAN',
                server: str = DEFAULT_SERVER, prioridad: str = 'default',
                tags: str = 'satellite', timeout: int = 6) -> bool:
    """Sends the notification. Returns True if it went out, False otherwise (no raise)."""
    if not topic:
        return False
    url, headers, cuerpo = build_ntfy(topic, message, titulo, server, prioridad, tags)
    try:
        r = requests.post(url, data=cuerpo, headers=headers, timeout=timeout)
        return r.ok
    except Exception:
        return False
