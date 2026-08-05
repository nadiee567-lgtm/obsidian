"""Extracción de entidades tipadas de texto libre — F14 paso 161.

Pegas un artículo/dump y salen entidades tipadas para el grafo. Se hace con REGEX
(determinista, sin alucinaciones de IA — importante para no meter falsos positivos),
con un filtro anti-FP para dominios (no confundir nombres de archivo con dominios).

Módulo PURO."""
from __future__ import annotations
import re

# extensiones comunes que NO son dominios (anti-falso-positivo)
_NO_TLD = {'txt', 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'html', 'htm', 'js', 'css',
          'py', 'exe', 'zip', 'doc', 'docx', 'xml', 'json', 'csv', 'md', 'php'}

_RX = [
    ('email', re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')),
    ('url', re.compile(r'https?://[^\s"\'<>]+')),
    ('wallet', re.compile(r'\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b')),
    ('ip', re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    ('dominio', re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b', re.I)),
]


def extraer_entidades(texto: str) -> list:
    """Devuelve [(tipo, valor), ...] sin duplicados. Los dominios que sean claramente
    nombres de archivo (extensión conocida) se descartan."""
    texto = texto or ''
    out, vistos = [], set()
    for tipo, rx in _RX:
        for m in rx.findall(texto):
            v = m.strip().rstrip('.,);:')
            if tipo == 'ip':
                if any(int(o) > 255 for o in v.split('.')):
                    continue                     # octeto inválido
            if tipo == 'dominio' and v.rsplit('.', 1)[-1].lower() in _NO_TLD:
                continue                         # es un archivo, no un dominio
            key = (tipo, v.lower())
            if v and key not in vistos:
                vistos.add(key)
                out.append((tipo, v))
    return out
