"""Unified internet-search-engine layer -- F8 steps 106 and 117.

The West uses almost only Shodan; the Chinese engines (FOFA, ZoomEye, Quake) see
infrastructure Shodan does not. Here the SAME OBSIDIAN query is translated to each
engine's dialect and can be launched to all of them at once.

This module is PURE (registry + translator). The real calls with a key and the
parsing of each response are wired per engine in steps 107-113.

Unified fields OBSIDIAN understands:
    ip, domain, favicon (mmh3 hash), cert (CN/subject), port,
    producto (software), org, pais (ISO code), titulo, asn
Each engine supports a subset; `traducir` ignores the fields that don't apply.
"""
from __future__ import annotations

# Per-engine metadata + template for each field in its own dialect.
# 'join' = the engine's AND operator. 'cn' marks the Chinese engines.
MOTORES = {
    'shodan': {
        'label': 'Shodan', 'requires_key': True, 'cn': False, 'join': ' ',
        'campos': {
            'ip': 'ip:{v}', 'domain': 'hostname:{v}', 'favicon': 'http.favicon.hash:{v}',
            'cert': 'ssl.cert.subject.cn:{v}', 'port': 'port:{v}', 'producto': 'product:{v}',
            'org': 'org:"{v}"', 'country': 'country:{v}', 'titulo': 'http.title:"{v}"', 'asn': 'asn:{v}',
        }},
    'censys': {
        'label': 'Censys', 'requires_key': True, 'cn': False, 'join': ' and ',
        'campos': {
            'ip': 'ip:{v}', 'domain': 'names:{v}',
            'cert': 'services.tls.certificates.leaf_data.subject.common_name:{v}',
            'port': 'services.port:{v}', 'producto': 'services.software.product:{v}',
            'country': 'location.country_code:{v}', 'asn': 'autonomous_system.asn:{v}',
        }},
    'zoomeye': {
        'label': 'ZoomEye', 'requires_key': True, 'cn': True, 'join': ' ',
        'campos': {
            'ip': 'ip:"{v}"', 'domain': 'hostname:{v}', 'favicon': 'iconhash:"{v}"',
            'cert': 'ssl:"{v}"', 'port': 'port:{v}', 'producto': 'app:"{v}"',
            'country': 'country:"{v}"', 'titulo': 'title:"{v}"', 'asn': 'asn:{v}',
        }},
    'fofa': {
        'label': 'FOFA', 'requires_key': True, 'cn': True, 'join': ' && ',
        'campos': {
            'ip': 'ip="{v}"', 'domain': 'domain="{v}"', 'favicon': 'icon_hash="{v}"',
            'cert': 'cert="{v}"', 'port': 'port="{v}"', 'producto': 'app="{v}"',
            'org': 'org="{v}"', 'country': 'country="{v}"', 'titulo': 'title="{v}"', 'asn': 'asn="{v}"',
        }},
    'quake': {
        'label': 'Quake', 'requires_key': True, 'cn': True, 'join': ' AND ',
        'campos': {
            'ip': 'ip:"{v}"', 'domain': 'domain:"{v}"', 'favicon': 'favicon:"{v}"',
            'cert': 'cert:"{v}"', 'port': 'port:"{v}"', 'producto': 'app:"{v}"',
            'country': 'country:"{v}"', 'titulo': 'title:"{v}"',
        }},
    'hunter': {
        'label': 'Hunter.how', 'requires_key': True, 'cn': True, 'join': '&&',
        'campos': {
            'ip': 'ip="{v}"', 'domain': 'domain="{v}"', 'favicon': 'favicon.hash="{v}"',
            'cert': 'cert="{v}"', 'port': 'port="{v}"', 'producto': 'product="{v}"',
            'country': 'country="{v}"', 'titulo': 'web.title="{v}"',
        }},
    'netlas': {
        'label': 'Netlas', 'requires_key': True, 'cn': False, 'join': ' AND ',
        'campos': {
            'ip': 'ip:{v}', 'domain': 'domain:{v}',
            'cert': 'certificate.subject.common_name:{v}', 'port': 'port:{v}',
            'country': 'geo.country:{v}', 'titulo': 'http.title:{v}',
        }},
    'criminalip': {
        'label': 'Criminal IP', 'requires_key': True, 'cn': False, 'join': ' ',
        'campos': {'ip': 'ip: {v}', 'port': 'open_port: {v}', 'producto': 'product: {v}',
                   'country': 'country: {v}', 'titulo': 'title: {v}'}},
    'binaryedge': {
        'label': 'BinaryEdge', 'requires_key': True, 'cn': False, 'join': ' ',
        'campos': {'ip': 'ip:{v}', 'port': 'port:{v}', 'producto': 'product:{v}',
                   'country': 'country:{v}'}},
}

CAMPOS = ('ip', 'domain', 'favicon', 'cert', 'port', 'producto', 'org', 'country', 'titulo', 'asn')


def available_engines(cn=None) -> list:
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
    for motor in available_engines(cn):
        q = traducir(motor, campos)
        if q:
            out[motor] = q
    return out
