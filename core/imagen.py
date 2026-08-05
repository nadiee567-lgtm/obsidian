"""Utilidades de imagen para OSINT — F9.

Búsqueda inversa multi-motor (paso 118): cada motor indexa cosas distintas.
Yandex es el mejor para rostros y Europa del Este; TinEye para rastrear el origen
y ediciones; Google/Bing para contexto general. Aquí se arman los deep-links de
búsqueda inversa POR URL de imagen — keyless, el analista hace click.

Módulo PURO."""
from __future__ import annotations
import re
from urllib.parse import quote


def parse_gps(texto: str):
    """Convierte GPS de exiftool (DMS, '40 deg 26\\' 46\" N, 79 deg 58\\' 56\" W')
    a decimal (lat, lon). Devuelve None si no se puede."""
    m = re.findall(r"(\d+(?:\.\d+)?)\s*deg\s*(\d+(?:\.\d+)?)'?\s*(\d+(?:\.\d+)?)?\"?\s*([NSEW])",
                   texto or '')
    if len(m) < 2:
        return None
    def dec(d, mi, s, h):
        v = float(d) + float(mi) / 60 + (float(s) if s else 0) / 3600
        return -v if h in ('S', 'W') else v
    return (round(dec(*m[0]), 6), round(dec(*m[1]), 6))


def enlaces_cronolocalizacion(lat=None, lon=None) -> dict:
    """Herramientas de sol/sombra (técnica Bellingcat). Con coords si se conocen."""
    if lat is not None and lon is not None:
        return {'suncalc': f'https://www.suncalc.org/#/{lat},{lon},15',
                'shadowmap': f'https://shadowmap.org/?lat={lat}&lng={lon}'}
    return {'suncalc': 'https://www.suncalc.org/', 'shadowmap': 'https://shadowmap.org/'}


def enlaces_satelital(lat, lon) -> dict:
    """Vistas satelitales/aéreas para verificar una ubicación."""
    return {
        'google_earth': f'https://earth.google.com/web/@{lat},{lon},0a,1000d',
        'sentinel': f'https://apps.sentinel-hub.com/eo-browser/?lat={lat}&lng={lon}&zoom=15',
        'bing_aerial': f'https://www.bing.com/maps?cp={lat}~{lon}&style=h&lvl=17',
    }


def enlaces_landmark(url_imagen: str) -> dict:
    """Reconocimiento de puntos de referencia (edificios/señales) por imagen."""
    u = quote(url_imagen, safe='')
    return {'google_lens': f'https://lens.google.com/uploadbyurl?url={u}',
            'mapillary': 'https://www.mapillary.com/app/',
            'wikimapia': 'https://wikimapia.org/'}


def phash(ruta: str):
    """Hash perceptual dHash (16 hex) de la imagen — paso 127. Agrupa la MISMA
    imagen aunque cambie de tamaño o formato. None si falta Pillow o la imagen es mala."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        img = Image.open(ruta).convert('L').resize((9, 8))
    except Exception:
        return None
    px = list(img.getdata())
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (1 if px[row * 9 + col] > px[row * 9 + col + 1] else 0)
    return f'{bits:016x}'


def ela(ruta: str, salida: str, calidad: int = 90):
    """Error Level Analysis — paso 126. Guarda una imagen ELA en `salida` y devuelve
    el max diff (0-255): regiones editadas muestran un nivel de error distinto al
    re-comprimir (heurístico, para inspección visual del analista). None si falta Pillow."""
    try:
        import io
        from PIL import Image, ImageChops, ImageEnhance
    except ImportError:
        return None
    try:
        orig = Image.open(ruta).convert('RGB')
    except Exception:
        return None
    buf = io.BytesIO()
    orig.save(buf, 'JPEG', quality=calidad)
    buf.seek(0)
    diff = ImageChops.difference(orig, Image.open(buf))
    max_diff = max((e[1] for e in diff.getextrema()), default=0) or 1
    ImageEnhance.Brightness(diff).enhance(255.0 / max_diff).save(salida, 'PNG')
    return max_diff


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
