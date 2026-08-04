"""Utilidades de imagen para OSINT — F9.

Búsqueda inversa multi-motor (paso 118): cada motor indexa cosas distintas.
Yandex es el mejor para rostros y Europa del Este; TinEye para rastrear el origen
y ediciones; Google/Bing para contexto general. Aquí se arman los deep-links de
búsqueda inversa POR URL de imagen — keyless, el analista hace click.

Módulo PURO."""
from __future__ import annotations
from urllib.parse import quote


def enlaces_reverse(url_imagen: str) -> dict:
    """{motor: url_de_busqueda_inversa} para la imagen dada."""
    u = quote(url_imagen, safe='')
    return {
        'yandex':  f'https://yandex.com/images/search?rpt=imageview&url={u}',
        'google':  f'https://lens.google.com/uploadbyurl?url={u}',
        'tineye':  f'https://tineye.com/search?url={u}',
        'bing':    f'https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}',
    }
