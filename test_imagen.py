"""Tests de utilidades de imagen (F9 paso 118).

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_imagen.py -q
"""
from urllib.parse import quote

import obsidian_web as ob
from core.modelo import Almacen
from core.transforms import ejecutar_por_nombre
from core.imagen import enlaces_reverse


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
