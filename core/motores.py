"""Capa unificada de buscadores de internet — F8 pasos 106 y 117.

Occidente usa casi solo Shodan; los motores chinos (FOFA, ZoomEye, Quake) ven
infraestructura que Shodan no. Aquí una MISMA consulta de OBSIDIAN se traduce al
dialecto de cada motor y se puede lanzar a todos a la vez.

Este módulo es PURO (registro + traductor). Las llamadas reales con key y el
parseo de cada respuesta se conectan por motor en los pasos 107-113.

Campos unificados que entiende OBSIDIAN:
    ip, dominio, favicon (mmh3 hash), cert (CN/subject), puerto,
    producto (software), org, pais (código ISO), titulo, asn
Cada motor soporta un subconjunto; `traducir` ignora los campos que no aplican.
"""
from __future__ import annotations

# Metadatos por motor + plantilla de cada campo en su dialecto propio.
# 'join' = operador AND del motor. 'cn' marca los motores chinos.
MOTORES = {
    'shodan': {
        'etiqueta': 'Shodan', 'requiere_key': True, 'cn': False, 'join': ' ',
        'campos': {
            'ip': 'ip:{v}', 'dominio': 'hostname:{v}', 'favicon': 'http.favicon.hash:{v}',
            'cert': 'ssl.cert.subject.cn:{v}', 'puerto': 'port:{v}', 'producto': 'product:{v}',
            'org': 'org:"{v}"', 'pais': 'country:{v}', 'titulo': 'http.title:"{v}"', 'asn': 'asn:{v}',
        }},
    'censys': {
        'etiqueta': 'Censys', 'requiere_key': True, 'cn': False, 'join': ' and ',
        'campos': {
            'ip': 'ip:{v}', 'dominio': 'names:{v}',
            'cert': 'services.tls.certificates.leaf_data.subject.common_name:{v}',
            'puerto': 'services.port:{v}', 'producto': 'services.software.product:{v}',
            'pais': 'location.country_code:{v}', 'asn': 'autonomous_system.asn:{v}',
        }},
    'zoomeye': {
        'etiqueta': 'ZoomEye', 'requiere_key': True, 'cn': True, 'join': ' ',
        'campos': {
            'ip': 'ip:"{v}"', 'dominio': 'hostname:{v}', 'favicon': 'iconhash:"{v}"',
            'cert': 'ssl:"{v}"', 'puerto': 'port:{v}', 'producto': 'app:"{v}"',
            'pais': 'country:"{v}"', 'titulo': 'title:"{v}"', 'asn': 'asn:{v}',
        }},
    'fofa': {
        'etiqueta': 'FOFA', 'requiere_key': True, 'cn': True, 'join': ' && ',
        'campos': {
            'ip': 'ip="{v}"', 'dominio': 'domain="{v}"', 'favicon': 'icon_hash="{v}"',
            'cert': 'cert="{v}"', 'puerto': 'port="{v}"', 'producto': 'app="{v}"',
            'org': 'org="{v}"', 'pais': 'country="{v}"', 'titulo': 'title="{v}"', 'asn': 'asn="{v}"',
        }},
    'quake': {
        'etiqueta': 'Quake', 'requiere_key': True, 'cn': True, 'join': ' AND ',
        'campos': {
            'ip': 'ip:"{v}"', 'dominio': 'domain:"{v}"', 'favicon': 'favicon:"{v}"',
            'cert': 'cert:"{v}"', 'puerto': 'port:"{v}"', 'producto': 'app:"{v}"',
            'pais': 'country:"{v}"', 'titulo': 'title:"{v}"',
        }},
    'hunter': {
        'etiqueta': 'Hunter.how', 'requiere_key': True, 'cn': True, 'join': '&&',
        'campos': {
            'ip': 'ip="{v}"', 'dominio': 'domain="{v}"', 'favicon': 'favicon.hash="{v}"',
            'cert': 'cert="{v}"', 'puerto': 'port="{v}"', 'producto': 'product="{v}"',
            'pais': 'country="{v}"', 'titulo': 'web.title="{v}"',
        }},
    'netlas': {
        'etiqueta': 'Netlas', 'requiere_key': True, 'cn': False, 'join': ' AND ',
        'campos': {
            'ip': 'ip:{v}', 'dominio': 'domain:{v}',
            'cert': 'certificate.subject.common_name:{v}', 'puerto': 'port:{v}',
            'pais': 'geo.country:{v}', 'titulo': 'http.title:{v}',
        }},
    'criminalip': {
        'etiqueta': 'Criminal IP', 'requiere_key': True, 'cn': False, 'join': ' ',
        'campos': {'ip': 'ip: {v}', 'puerto': 'open_port: {v}', 'producto': 'product: {v}',
                   'pais': 'country: {v}', 'titulo': 'title: {v}'}},
    'binaryedge': {
        'etiqueta': 'BinaryEdge', 'requiere_key': True, 'cn': False, 'join': ' ',
        'campos': {'ip': 'ip:{v}', 'puerto': 'port:{v}', 'producto': 'product:{v}',
                   'pais': 'country:{v}'}},
}

CAMPOS = ('ip', 'dominio', 'favicon', 'cert', 'puerto', 'producto', 'org', 'pais', 'titulo', 'asn')


def motores_disponibles(cn=None) -> list:
    """Nombres de motores. cn=True solo chinos, cn=False solo occidentales, None todos."""
    return [m for m, info in MOTORES.items() if cn is None or info['cn'] == cn]


def traducir(motor: str, campos: dict) -> str:
    """Traduce una consulta unificada al dialecto de `motor` (paso 117).

    campos: {campo: valor} con campos de CAMPOS. Se ignoran los que el motor no
    soporta y los vacíos. Devuelve '' si no queda nada que consultar.
    """
    if motor not in MOTORES:
        raise KeyError(f'motor desconocido: {motor}')
    info = MOTORES[motor]
    partes = []
    for campo in CAMPOS:
        val = campos.get(campo)
        if val in (None, '') or campo not in info['campos']:
            continue
        partes.append(info['campos'][campo].format(v=val))
    return info['join'].join(partes)


def traducir_todos(campos: dict, cn=None) -> dict:
    """La misma consulta traducida a CADA motor. {motor: query} (solo no vacíos)."""
    out = {}
    for motor in motores_disponibles(cn):
        q = traducir(motor, campos)
        if q:
            out[motor] = q
    return out
