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


# Motores de reconocimiento FACIAL (paso 119). 'modo':
#   url    = busca por la URL de la imagen directamente (automático)
#   upload = requiere subir la imagen a mano (no aceptan URL)
_FACE = {
    'yandex':    ('url',    'https://yandex.com/images/search?rpt=imageview&url={u}'),
    'facecheck': ('upload', 'https://facecheck.id/'),
    'pimeyes':   ('upload', 'https://pimeyes.com/en'),
}


def enlaces_facial(url_imagen: str) -> dict:
    """{motor: {'url', 'modo'}} para búsqueda facial. Yandex es el mejor gratis
    (sobre todo Europa del Este) y funciona por URL; FaceCheck/PimEyes son por
    subida manual — se devuelve su landing para que el analista suba la imagen."""
    u = quote(url_imagen, safe='')
    return {motor: {'url': tpl.format(u=u), 'modo': modo} for motor, (modo, tpl) in _FACE.items()}
