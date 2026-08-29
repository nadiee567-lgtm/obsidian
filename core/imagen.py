"""Image utilities for OSINT -- F9.

Multi-engine reverse search (step 118): each engine indexes different things.
Yandex is best for faces and Eastern Europe; TinEye for tracing the origin and
edits; Google/Bing for general context. Here we build the reverse-search deep
links BY image URL -- keyless, the analyst clicks through.

PURE module."""
from __future__ import annotations
import re
from urllib.parse import quote


def parse_gps(text: str):
    """Converts exiftool GPS (DMS, '40 deg 26\\' 46\" N, 79 deg 58\\' 56\" W')
    to decimal (lat, lon). Returns None if it can't."""
    m = re.findall(r"(\d+(?:\.\d+)?)\s*deg\s*(\d+(?:\.\d+)?)'?\s*(\d+(?:\.\d+)?)?\"?\s*([NSEW])",
                   text or '')
    if len(m) < 2:
        return None
    def dec(d, mi, s, h):
        v = float(d) + float(mi) / 60 + (float(s) if s else 0) / 3600
        return -v if h in ('S', 'W') else v
    return (round(dec(*m[0]), 6), round(dec(*m[1]), 6))


def chronolocation_links(lat=None, lon=None) -> dict:
    """Sun/shadow tools (Bellingcat technique). With coords if known."""
    if lat is not None and lon is not None:
        return {'suncalc': f'https://www.suncalc.org/#/{lat},{lon},15',
                'shadowmap': f'https://shadowmap.org/?lat={lat}&lng={lon}'}
    return {'suncalc': 'https://www.suncalc.org/', 'shadowmap': 'https://shadowmap.org/'}


def satellite_links(lat, lon) -> dict:
    """Satellite/aerial views to verify a location."""
    return {
        'google_earth': f'https://earth.google.com/web/@{lat},{lon},0a,1000d',
        'sentinel': f'https://apps.sentinel-hub.com/eo-browser/?lat={lat}&lng={lon}&zoom=15',
        'bing_aerial': f'https://www.bing.com/maps?cp={lat}~{lon}&style=h&lvl=17',
    }


def landmark_links(url_imagen: str) -> dict:
    """Landmark recognition (buildings/signs) by image."""
    u = quote(url_imagen, safe='')
    return {'google_lens': f'https://lens.google.com/uploadbyurl?url={u}',
            'mapillary': 'https://www.mapillary.com/app/',
            'wikimapia': 'https://wikimapia.org/'}


def phash(ruta: str):
    """Perceptual dHash (16 hex) of the image -- step 127. Groups the SAME image
    even if it changes size or format. None if Pillow is missing or the image is bad."""
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
    """Error Level Analysis -- step 126. Saves an ELA image to `salida` and returns
    the max diff (0-255): edited regions show a different error level after
    re-compression (heuristic, for the analyst's visual review). None if Pillow is missing."""
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


def reverse_links(url_imagen: str) -> dict:
    """{engine: reverse_search_url} for the given image."""
    u = quote(url_imagen, safe='')
    return {
        'yandex':  f'https://yandex.com/images/search?rpt=imageview&url={u}',
        'google':  f'https://lens.google.com/uploadbyurl?url={u}',
        'tineye':  f'https://tineye.com/search?url={u}',
        'bing':    f'https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}',
    }


_FACE = {
    'yandex':    ('url',    'https://yandex.com/images/search?rpt=imageview&url={u}'),
    'facecheck': ('upload', 'https://facecheck.id/'),
    'pimeyes':   ('upload', 'https://pimeyes.com/en'),
}


def facial_links(url_imagen: str) -> dict:
    """{engine: {'url', 'modo'}} for facial search. Yandex is the best free one
    (especially Eastern Europe) and works by URL; FaceCheck/PimEyes are manual
    upload -- their landing page is returned so the analyst uploads the image."""
    u = quote(url_imagen, safe='')
    return {motor: {'url': tpl.format(u=u), 'modo': modo} for motor, (modo, tpl) in _FACE.items()}
