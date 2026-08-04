"""Notificaciones push por ntfy.sh — F7 paso 96.

Cuando el monitor detecta un cambio, avisa al celular de Sebastian (ya usa ntfy,
topic tiger-sebastian). Sin topic configurado no hace nada (degrada en silencio).

`construir_ntfy` es PURO (arma url/headers/cuerpo) y por eso testeable; `enviar_ntfy`
solo lo manda con requests, aislando cualquier fallo de red."""
from __future__ import annotations
import requests

DEFAULT_SERVER = 'https://ntfy.sh'


def construir_ntfy(topic: str, mensaje: str, titulo: str = 'OBSIDIAN',
                   server: str = DEFAULT_SERVER, prioridad: str = 'default',
                   tags: str = 'satellite') -> tuple:
    """Devuelve (url, headers, cuerpo_bytes) para el POST a ntfy. No manda nada."""
    url = f"{server.rstrip('/')}/{topic.lstrip('/')}"
    headers = {'Title': titulo, 'Priority': prioridad, 'Tags': tags}
    return url, headers, mensaje.encode('utf-8')


def enviar_ntfy(topic: str, mensaje: str, titulo: str = 'OBSIDIAN',
                server: str = DEFAULT_SERVER, prioridad: str = 'default',
                tags: str = 'satellite', timeout: int = 6) -> bool:
    """Manda la notificación. Devuelve True si salió, False si no (sin lanzar)."""
    if not topic:
        return False
    url, headers, cuerpo = construir_ntfy(topic, mensaje, titulo, server, prioridad, tags)
    try:
        r = requests.post(url, data=cuerpo, headers=headers, timeout=timeout)
        return r.ok
    except Exception:
        return False
