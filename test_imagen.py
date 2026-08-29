"""Tests de utilidades de imagen (F9 step 118).

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_imagen.py -q
"""
from urllib.parse import quote

import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name
from core.imagen import reverse_links, facial_links


def test_reverse_links_all_engines():
    d = reverse_links('https://x.com/a.jpg')
    assert set(d) == {'yandex', 'google', 'tineye', 'bing'}
    assert all(u.startswith('https://') for u in d.values())


def test_reverse_links_urlencode():
    src = 'https://x.com/a b.jpg?p=1&q=2'
    d = reverse_links(src)
    assert ' ' not in d['yandex']
    assert quote(src, safe='') in d['yandex']


def test_reverse_image_transform():
    store = Store()
    e = store.create('url', 'https://x.com/a.jpg')
    prod = run_by_name('reverse_image', e, store)
    assert {p.properties.get('engine') for p in prod} == {'yandex', 'google', 'tineye', 'bing'}
    assert all(p.type == 'url' for p in prod)


def test_facial_links():
    d = facial_links('https://x.com/cara.jpg')
    assert set(d) == {'yandex', 'facecheck', 'pimeyes'}
    assert d['yandex']['modo'] == 'url' and 'yandex.com' in d['yandex']['url']
    assert d['facecheck']['modo'] == 'upload'
    assert d['pimeyes']['modo'] == 'upload'


def test_search_facial_transform():
    store = Store()
    e = store.create('url', 'https://x.com/cara.jpg')
    prod = run_by_name('facial_search', e, store)
    motores = {p.properties.get('engine'): p.properties.get('mode') for p in prod}
    assert motores == {'yandex': 'url', 'facecheck': 'upload', 'pimeyes': 'upload'}


class _FakeStream:
    def iter_content(self, n):
        yield b'\xff\xd8fakeimage'


def test_metadata_exif_como_entities(monkeypatch):
    """El EXIF se vuelve entities pivotables: dispositivo, software, autor, GPS."""
    monkeypatch.setattr(ob, '_which', lambda x: True)
    monkeypatch.setattr(ob, '_fetch_seguro', lambda *a, **k: _FakeStream())
    salida = ("Make                     : Apple\n"
              "Camera Model Name        : iPhone 12\n"
              "Software                 : 14.2\n"
              "Artist                   : Jane Doe\n"
              "GPS Position             : 40 deg 26' N, 79 deg 58' W\n")
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: salida)
    store = Store()
    e = store.create('url', 'https://x.com/foto.jpg')
    prod = run_by_name('metadata', e, store)
    techs = {p.value for p in prod if p.type == 'tech'}
    personas = {p.value for p in prod if p.type == 'person'}
    urls = [p for p in prod if p.type == 'url']
    assert 'Apple iPhone 12' in techs and '14.2' in techs
    assert 'Jane Doe' in personas
    assert urls and 'maps' in urls[0].value
    assert 'has-gps' in e.tags


def test_parse_gps():
    from core.imagen import parse_gps
    r = parse_gps("40 deg 26' 46.0\" N, 79 deg 58' 56.0\" W")
    assert r and abs(r[0] - 40.446) < 0.01 and abs(r[1] + 79.982) < 0.01
    assert parse_gps('nada') is None


def test_cronolocalizacion(monkeypatch):
    from core.transforms import run_by_name
    store = Store()
    u = store.create('url', 'https://x.com/f.jpg', properties={'gps': "40 deg 26' N, 79 deg 58' W"})
    prod = run_by_name('chronolocation', u, store)
    assert {p.properties.get('tool') for p in prod} == {'suncalc', 'shadowmap'}
    assert any('40' in p.value for p in prod)


def test_satellite_requires_gps():
    from core.transforms import run_by_name
    store = Store()
    u = store.create('url', 'https://x.com/f.jpg')
    assert run_by_name('satellite', u, store) == []


def test_landmarks():
    from core.transforms import run_by_name
    store = Store()
    u = store.create('url', 'https://x.com/f.jpg')
    prod = run_by_name('landmarks', u, store)
    assert {p.properties.get('tool') for p in prod} == {'google_lens', 'mapillary', 'wikimapia'}


def test_ocr_without_tesseract(monkeypatch):
    from core.transforms import run_by_name
    monkeypatch.setattr(ob, '_which', lambda x: False)
    store = Store()
    u = store.create('url', 'https://x.com/f.jpg')
    assert run_by_name('ocr', u, store) == []


def test_geoloc_is_mode_ai():
    assert 'geoloc' in ob._AI_PROMPTS


def _img_grad():
    import tempfile
    from PIL import Image
    p = tempfile.mktemp(suffix='.png')
    img = Image.new('L', (16, 16))
    img.putdata([(i * 7 + j * 3) % 256 for i in range(16) for j in range(16)])
    img.save(p)
    return p


def test_phash_estable():
    from core.imagen import phash
    import os as _os
    a, b = _img_grad(), _img_grad()
    ha, hb = phash(a), phash(b)
    assert ha and len(ha) == 16 and ha == hb
    _os.unlink(a); _os.unlink(b)


def test_ela_genera_imagen():
    from core.imagen import ela
    import os as _os
    import tempfile
    src, out = _img_grad(), tempfile.mktemp(suffix='.png')
    md = ela(src, out)
    assert md is not None and _os.path.exists(out)
    _os.unlink(src); _os.unlink(out)


def test_phash_transform(monkeypatch):
    from core.transforms import run_by_name
    monkeypatch.setattr(ob, '_download_image', lambda url: _img_grad())
    store = Store()
    u = store.create('url', 'https://x.com/a.jpg')
    prod = run_by_name('phash', u, store)
    hs = [e for e in prod if e.type == 'hash']
    assert hs and hs[0].properties.get('hash_type') == 'phash'
    assert u.properties.get('phash')


def test_ela_transform(monkeypatch):
    from core.transforms import run_by_name
    monkeypatch.setattr(ob, '_download_image', lambda url: _img_grad())
    store = Store()
    u = store.create('url', 'https://x.com/a.jpg')
    run_by_name('ela', u, store)
    assert 'ela-generated' in u.tags and u.properties.get('ela_img')
