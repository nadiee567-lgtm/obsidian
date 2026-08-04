"""Tests de utilidades de imagen (F9 paso 118).

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_imagen.py -q
"""
from urllib.parse import quote

import obsidian_web as ob
from core.modelo import Almacen
from core.transforms import ejecutar_por_nombre
from core.imagen import enlaces_reverse, enlaces_facial


def test_enlaces_reverse_todos_los_motores():
    d = enlaces_reverse('https://x.com/a.jpg')
    assert set(d) == {'yandex', 'google', 'tineye', 'bing'}
    assert all(u.startswith('https://') for u in d.values())


def test_enlaces_reverse_urlencode():
    src = 'https://x.com/a b.jpg?p=1&q=2'
    d = enlaces_reverse(src)
    assert ' ' not in d['yandex']                       # sin espacios crudos
    assert quote(src, safe='') in d['yandex']           # url completa urlencodeada


def test_reverse_image_transform():
    alm = Almacen()
    e = alm.crear('url', 'https://x.com/a.jpg')
    prod = ejecutar_por_nombre('reverse_image', e, alm)
    assert {p.propiedades.get('motor') for p in prod} == {'yandex', 'google', 'tineye', 'bing'}
    assert all(p.tipo == 'url' for p in prod)


def test_enlaces_facial():
    d = enlaces_facial('https://x.com/cara.jpg')
    assert set(d) == {'yandex', 'facecheck', 'pimeyes'}
    assert d['yandex']['modo'] == 'url' and 'yandex.com' in d['yandex']['url']
    assert d['facecheck']['modo'] == 'upload'          # honesto: es por subida manual
    assert d['pimeyes']['modo'] == 'upload'


def test_busqueda_facial_transform():
    alm = Almacen()
    e = alm.crear('url', 'https://x.com/cara.jpg')
    prod = ejecutar_por_nombre('busqueda_facial', e, alm)
    motores = {p.propiedades.get('motor'): p.propiedades.get('modo') for p in prod}
    assert motores == {'yandex': 'url', 'facecheck': 'upload', 'pimeyes': 'upload'}


class _FakeStream:
    def iter_content(self, n):
        yield b'\xff\xd8fakeimage'


def test_metadata_exif_como_entidades(monkeypatch):
    """El EXIF se vuelve entidades pivotables: dispositivo, software, autor, GPS."""
    monkeypatch.setattr(ob, '_which', lambda x: True)
    monkeypatch.setattr(ob, '_fetch_seguro', lambda *a, **k: _FakeStream())
    salida = ("Make                     : Apple\n"
              "Camera Model Name        : iPhone 12\n"
              "Software                 : 14.2\n"
              "Artist                   : Jane Doe\n"
              "GPS Position             : 40 deg 26' N, 79 deg 58' W\n")
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: salida)
    alm = Almacen()
    e = alm.crear('url', 'https://x.com/foto.jpg')
    prod = ejecutar_por_nombre('metadata', e, alm)
    techs = {p.valor for p in prod if p.tipo == 'tech'}
    personas = {p.valor for p in prod if p.tipo == 'persona'}
    urls = [p for p in prod if p.tipo == 'url']
    assert 'Apple iPhone 12' in techs and '14.2' in techs
    assert 'Jane Doe' in personas
    assert urls and 'maps' in urls[0].valor          # GPS -> link de mapa pivotable
    assert 'tiene-gps' in e.tags
