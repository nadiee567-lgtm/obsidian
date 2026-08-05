"""Multi-idioma y fuentes regionales — F15.

Un dato clave puede estar solo en chino o ruso. Estas utilidades PURAS ayudan a
buscarlo donde está: plataformas regionales, transliteración de nombres, detección
de idioma por alfabeto, motores locales y dorks por idioma."""
from __future__ import annotations
from urllib.parse import quote


def perfiles_regionales(usuario: str) -> dict:
    """Perfiles/búsquedas del usuario en plataformas regionales (paso 171)."""
    u = quote(usuario)
    return {
        'vk': f'https://vk.com/{usuario}',
        'ok': f'https://ok.ru/{usuario}',
        'weibo': f'https://s.weibo.com/user?q={u}',
        'douyin': f'https://www.douyin.com/search/{u}',
        'telegram': f'https://t.me/{usuario}',
    }


# ── Transliteración cirílico ↔ latino (paso 172) ─────────────────────────────
_CIR_LAT = {
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'e', 'ж': 'zh',
    'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm', 'н': 'n', 'о': 'o',
    'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u', 'ф': 'f', 'х': 'kh', 'ц': 'ts',
    'ч': 'ch', 'ш': 'sh', 'щ': 'shch', 'ъ': '', 'ы': 'y', 'ь': '', 'э': 'e',
    'ю': 'yu', 'я': 'ya',
}
_LAT_CIR = {'zh': 'ж', 'kh': 'х', 'ts': 'ц', 'ch': 'ч', 'shch': 'щ', 'sh': 'ш',
            'yu': 'ю', 'ya': 'я'}
_LAT_CIR1 = {'a': 'а', 'b': 'б', 'v': 'в', 'g': 'г', 'd': 'д', 'e': 'е', 'z': 'з',
             'i': 'и', 'y': 'й', 'k': 'к', 'l': 'л', 'm': 'м', 'n': 'н', 'o': 'о',
             'p': 'п', 'r': 'р', 's': 'с', 't': 'т', 'u': 'у', 'f': 'ф'}


def cirilico_a_latino(texto: str) -> str:
    return ''.join(_CIR_LAT.get(c, _CIR_LAT.get(c.lower(), c)) for c in texto)


def latino_a_cirilico(texto: str) -> str:
    t = texto.lower()
    out, i = [], 0
    while i < len(t):
        for k in ('shch', 'zh', 'kh', 'ts', 'ch', 'sh', 'yu', 'ya'):
            if t[i:i + len(k)] == k:
                out.append(_LAT_CIR[k])
                i += len(k)
                break
        else:
            out.append(_LAT_CIR1.get(t[i], t[i]))
            i += 1
    return ''.join(out)


def transliterar(nombre: str) -> dict:
    """Variantes del nombre en cada alfabeto para buscar a la misma persona (paso 172)."""
    return {'latino': cirilico_a_latino(nombre), 'cirilico': latino_a_cirilico(nombre)}


# ── Detección de idioma por alfabeto (paso 175) ──────────────────────────────
def detectar_idioma(texto: str) -> str:
    """Idioma probable por el rango Unicode dominante. Keyless, sin librerías."""
    conteo = {'ru': 0, 'zh': 0, 'ar': 0, 'ja': 0, 'ko': 0, 'es_en': 0}
    for c in texto or '':
        o = ord(c)
        if 0x0400 <= o <= 0x04FF:
            conteo['ru'] += 1
        elif 0x4E00 <= o <= 0x9FFF:
            conteo['zh'] += 1
        elif 0x0600 <= o <= 0x06FF:
            conteo['ar'] += 1
        elif 0x3040 <= o <= 0x30FF:
            conteo['ja'] += 1
        elif 0xAC00 <= o <= 0xD7A3:
            conteo['ko'] += 1
        elif c.isalpha():
            conteo['es_en'] += 1
    return max(conteo, key=conteo.get) if any(conteo.values()) else 'es_en'
