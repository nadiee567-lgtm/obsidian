"""Unified internet-search-engine layer -- F8 steps 106 and 117.

The West uses almost only Shodan; the Chinese engines (FOFA, ZoomEye, Quake) see
infrastructure Shodan does not. Here the SAME OBSIDIAN query is translated to each
engine's dialect and can be launched to all of them at once.

This module is PURE (registry + translator). The real calls with a key and the
parsing of each response are wired per engine in steps 107-113.

Unified fields OBSIDIAN understands:
    ip, dominio, favicon (mmh3 hash), cert (CN/subject), puerto,
    producto (software), org, pais (ISO code), titulo, asn
Each engine supports a subset; `traducir` ignores the fields that don't apply.
"""
from __future__ import annotations

# Per-engine metadata + template for each field in its own dialect.
# 'join' = the engine's AND operator. 'cn' marks the Chinese engines.
MOTORES = {
    'shodan': {
        'label': 'Shodan', 'requiere_key': True, 'cn': False, 'join': ' ',
        'campos': {
            'ip': 'ip:{v}', 'dominio': 'hostname:{v}', 'favicon': 'http.favicon.hash:{v}',
            'cert': 'ssl.cert.subject.cn:{v}', 'puerto': 'port:{v}', 'producto': 'product:{v}',
            'org': 'org:"{v}"', 'pais': 'country:{v}', 'titulo': 'http.title:"{v}"', 'asn': 'asn:{v}',
        }},
    'censys': {
        'label': 'Censys', 'requiere_key': True, 'cn': False, 'join': ' and ',
        'campos': {
            'ip': 'ip:{v}', 'dominio': 'names:{v}',
            'cert': 'services.tls.certificates.leaf_data.subject.common_name:{v}',
            'puerto': 'services.port:{v}', 'producto': 'services.software.product:{v}',
            'pais': 'location.country_code:{v}', 'asn': 'autonomous_system.asn:{v}',
        }},
    'zoomeye': {
        'label': 'ZoomEye', 'requiere_key': True, 'cn': True, 'join': ' ',
        'campos': {
            'ip': 'ip:"{v}"', 'dominio': 'hostname:{v}', 'favicon': 'iconhash:"{v}"',
            'cert': 'ssl:"{v}"', 'puerto': 'port:{v}', 'producto': 'app:"{v}"',
            'pais': 'country:"{v}"', 'titulo': 'title:"{v}"', 'asn': 'asn:{v}',
        }},
    'fofa': {
        'label': 'FOFA', 'requiere_key': True, 'cn': True, 'join': ' && ',
        'campos': {
            'ip': 'ip="{v}"', 'dominio': 'domain="{v}"', 'favicon': 'icon_hash="{v}"',
            'cert': 'cert="{v}"', 'puerto': 'port="{v}"', 'producto': 'app="{v}"',
            'org': 'org="{v}"', 'pais': 'country="{v}"', 'titulo': 'title="{v}"', 'asn': 'asn="{v}"',
        }},
    'quake': {
        'label': 'Quake', 'requiere_key': True, 'cn': True, 'join': ' AND ',
        'campos': {
            'ip': 'ip:"{v}"', 'dominio': 'domain:"{v}"', 'favicon': 'favicon:"{v}"',
            'cert': 'cert:"{v}"', 'puerto': 'port:"{v}"', 'producto': 'app:"{v}"',
            'pais': 'country:"{v}"', 'titulo': 'title:"{v}"',
        }},
    'hunter': {
        'label': 'Hunter.how', 'requiere_key': True, 'cn': True, 'join': '&&',
        'campos': {
            'ip': 'ip="{v}"', 'dominio': 'domain="{v}"', 'favicon': 'favicon.hash="{v}"',
            'cert': 'cert="{v}"', 'puerto': 'port="{v}"', 'producto': 'product="{v}"',
            'pais': 'country="{v}"', 'titulo': 'web.title="{v}"',
        }},
    'netlas': {
        'label': 'Netlas', 'requiere_key': True, 'cn': False, 'join': ' AND ',
        'campos': {
            'ip': 'ip:{v}', 'dominio': 'domain:{v}',
            'cert': 'certificate.subject.common_name:{v}', 'puerto': 'port:{v}',
            'pais': 'geo.country:{v}', 'titulo': 'http.title:{v}',
        }},
    'criminalip': {
        'label': 'Criminal IP', 'requiere_key': True, 'cn': False, 'join': ' ',
        'campos': {'ip': 'ip: {v}', 'puerto': 'open_port: {v}', 'producto': 'product: {v}',
                   'pais': 'country: {v}', 'titulo': 'title: {v}'}},
    'binaryedge': {
        'label': 'BinaryEdge', 'requiere_key': True, 'cn': False, 'join': ' ',
        'campos': {'ip': 'ip:{v}', 'puerto': 'port:{v}', 'producto': 'product:{v}',
                   'pais': 'country:{v}'}},
}

CAMPOS = ('ip', 'dominio', 'favicon', 'cert', 'puerto', 'producto', 'org', 'pais', 'titulo', 'asn')


def motores_disponibles(cn=None) -> list:
    """Engine names. cn=True only Chinese, cn=False only Western, None all."""
    return [m for m, info in MOTORES.items() if cn is None or info['cn'] == cn]


def traducir(motor: str, campos: dict) -> str:
    """Translates a unified query to `motor`'s dialect (step 117).

    campos: {field: value} with fields from CAMPOS. Fields the engine does not
    support and empty ones are ignored. Returns '' if nothing is left to query.
    """
    if motor not in MOTORES:
        raise KeyError(f'unknown engine: {motor}')
    info = MOTORES[motor]
    partes = []
    for campo in CAMPOS:
        val = campos.get(campo)
        if val in (None, '') or campo not in info['campos']:
            continue
        partes.append(info['campos'][campo].format(v=val))
    return info['join'].join(partes)


def traducir_todos(campos: dict, cn=None) -> dict:
    """The same query translated to EACH engine. {engine: query} (non-empty only)."""
    out = {}
    for motor in motores_disponibles(cn):
        q = traducir(motor, campos)
        if q:
            out[motor] = q
    return out
