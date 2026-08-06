"""Multilingual and regional sources -- F15.

A key datum may exist only in Chinese or Russian. These PURE utilities help find
it where it lives: regional platforms, name transliteration, language detection by
alphabet, local engines and per-language dorks."""
from __future__ import annotations
import re
from urllib.parse import quote

_PAIS_PREFIJO = {'MX': '52', 'US': '1', 'RU': '7', 'CN': '86', 'ES': '34',
                 'AR': '54', 'CO': '57', 'BR': '55', 'PE': '51', 'CL': '56'}


def normalizar_telefono(numero: str, pais: str = 'US') -> str:
    """Normalizes a phone to +E.164 format based on the country (step 177)."""
    d = re.sub(r'\D', '', numero or '')
    if not d:
        return ''
    pref = _PAIS_PREFIJO.get((pais or '').upper(), '')
    if pref and not d.startswith(pref):
        d = pref + d.lstrip('0')
    return '+' + d


_PAIS_TZ = {
    'MX': 'America/Mexico_City', 'US': 'America/New_York', 'RU': 'Europe/Moscow',
    'CN': 'Asia/Shanghai', 'ES': 'Europe/Madrid', 'AR': 'America/Argentina/Buenos_Aires',
    'BR': 'America/Sao_Paulo', 'CO': 'America/Bogota', 'PE': 'America/Lima',
    'CL': 'America/Santiago', 'JP': 'Asia/Tokyo', 'KR': 'Asia/Seoul', 'GB': 'Europe/London',
    'DE': 'Europe/Berlin', 'FR': 'Europe/Paris', 'IN': 'Asia/Kolkata',
}


def zona_horaria(pais: str) -> dict:
    """Country time zone and local time, for chrono-location (step 178)."""
    import datetime
    tz = _PAIS_TZ.get((pais or '').upper(), 'UTC')
    hora = None
    try:
        from zoneinfo import ZoneInfo
        hora = datetime.datetime.now(ZoneInfo(tz)).strftime('%Y-%m-%d %H:%M %Z')
    except Exception:
        pass
    return {'tz': tz, 'hora_local': hora}


def perfiles_regionales(usuario: str) -> dict:
    """User profiles/searches on regional platforms (step 171)."""
    u = quote(usuario)
    return {
        'vk': f'https://vk.com/{usuario}',
        'ok': f'https://ok.ru/{usuario}',
        'weibo': f'https://s.weibo.com/user?q={u}',
        'douyin': f'https://www.douyin.com/search/{u}',
        'telegram': f'https://t.me/{usuario}',
    }


# ── Cyrillic <-> Latin transliteration (step 172) ────────────────────────────
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
    """Name variants in each alphabet to find the same person (step 172)."""
    return {'latino': cirilico_a_latino(nombre), 'cirilico': latino_a_cirilico(nombre)}


# ── Language detection by alphabet (step 175) ────────────────────────────────
_DORK_TERMS = {
    'ru': {'contacto': 'контакты', 'email': 'почта', 'phone': 'телефон', 'sites': ['vk.com', 'ok.ru']},
    'zh': {'contacto': '联系', 'email': '邮箱', 'phone': '电话', 'sites': ['weibo.com', 'zhihu.com']},
    'es_en': {'contacto': 'contact', 'email': 'email', 'phone': 'phone', 'sites': ['linkedin.com']},
}


def dorks_por_idioma(objetivo: str, idioma: str = 'es_en') -> list:
    """Dorks adapted to the language/region (step 176)."""
    t = _DORK_TERMS.get(idioma, _DORK_TERMS['es_en'])
    dorks = [f'"{objetivo}" {t["contacto"]}', f'"{objetivo}" {t["email"]}', f'"{objetivo}" {t["phone"]}']
    dorks += [f'"{objetivo}" site:{s}' for s in t['sites']]
    return dorks


def registros_regionales(org: str) -> dict:
    """Company/person registries by region (step 173)."""
    q = quote(org)
    return {
        'china_qcc': f'https://www.qcc.com/web/search?key={q}',
        'rusia_rusprofile': f'https://www.rusprofile.ru/search?query={q}',
        'opencorporates': f'https://opencorporates.com/companies?q={q}',   # global, incl. LatAm
    }


def motores_locales(consulta: str) -> dict:
    """Local search engines (step 174): they see a different internet than Google."""
    q = quote(consulta)
    return {'yandex': f'https://yandex.com/search/?text={q}',
            'baidu': f'https://www.baidu.com/s?wd={q}',
            'sogou': f'https://www.sogou.com/web?query={q}'}


def detectar_idioma(texto: str) -> str:
    """Likely language by the dominant Unicode range. Keyless, no libraries."""
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
