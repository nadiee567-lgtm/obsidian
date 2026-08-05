"""Tests de F10 — dark web / Tor.

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_darkweb.py -q
"""
import obsidian_web as ob
from core.modelo import Almacen
from core.transforms import ejecutar_por_nombre


def _correr(nombre, tipo, valor):
    alm = Almacen()
    e = alm.crear(tipo, valor)
    return ejecutar_por_nombre(nombre, e, alm), e


# ── 128: ruteo .onion por Tor ────────────────────────────────────────────────
def test_onion_fetch_solo_onion():
    prod, _ = _correr('onion_fetch', 'url', 'https://clearnet.com')
    assert prod == []                                # ignora lo que no es .onion (anti-SSRF)


def test_onion_fetch(monkeypatch):
    class R:
        text = ('<title>Mercado Oscuro</title> contacto@vendor.com '
                'http://abcdefghij234567.onion/foro')
    monkeypatch.setattr(ob, '_tor_disponible', lambda: True)
    monkeypatch.setattr(ob, '_fetch_tor', lambda url, **k: R())
    prod, e = _correr('onion_fetch', 'url', 'http://xxxxabcdefgh2345.onion/')
    assert 'contacto@vendor.com' in {x.valor for x in prod if x.tipo == 'email'}
    assert any('.onion' in x.valor for x in prod if x.tipo == 'url')
    assert e.propiedades.get('onion_titulo') == 'Mercado Oscuro'
    assert 'onion-vivo' in e.tags


def test_onion_fetch_tor_caido(monkeypatch):
    monkeypatch.setattr(ob, '_tor_disponible', lambda: False)
    prod, e = _correr('onion_fetch', 'url', 'http://xxxxabcdefgh2345.onion/')
    assert prod == [] and 'Tor no disponible' in e.propiedades.get('tor', '')


# ── 129: Ahmia + Haystak ─────────────────────────────────────────────────────
def test_haystak(monkeypatch):
    class R:
        text = 'resultados: abcdefghij234567.onion y zzzz2233abcdefgh.onion'
    monkeypatch.setattr(ob, '_tor_disponible', lambda: True)
    monkeypatch.setattr(ob, '_fetch_tor', lambda url, **k: R())
    prod, _ = _correr('haystak', 'persona', 'objetivo')
    onions = {x.valor for x in prod if x.tipo == 'url'}
    assert any('.onion' in o for o in onions) and len(onions) == 2


def test_haystak_sin_tor(monkeypatch):
    monkeypatch.setattr(ob, '_tor_disponible', lambda: False)
    prod, e = _correr('haystak', 'persona', 'objetivo')
    assert prod == [] and 'requiere Tor' in e.propiedades.get('haystak', '')


# ── 130: Telegram (Telethon) — caminos de degradado (el activo necesita cuenta) ─
def test_telegram_sin_credenciales(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('TELEGRAM_API', '')
    prod, e = _correr('telegram', 'usuario', 'durov')
    assert prod == [] and 'api_id:api_hash' in e.propiedades.get('telegram', '')


def test_telegram_sin_sesion(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: '123:abchash')
    monkeypatch.setattr(ob.os.path, 'exists', lambda p: not str(p).endswith('telegram.session'))
    prod, e = _correr('telegram', 'usuario', 'durov')
    assert prod == [] and 'login' in e.propiedades.get('telegram', '')


# ── 131: monitoreo de canales (lógica testeable; fetch degrada sin cuenta) ────
def test_coincidencias_leak():
    hits = ob.coincidencias_leak(['hola mundo', 'nueva DATABASE a la venta', 'ransomware group', 'nada'])
    assert len(hits) == 2 and {h['keyword'] for h in hits} == {'database', 'ransomware'}


def test_canal_leaks(monkeypatch):
    textos = ['combolist fresca de acme.com', 'admin@acme.com filtrado en breach', 'gatitos']
    monkeypatch.setattr(ob, '_tg_mensajes', lambda u, limite=100: (True, (123, textos)))
    prod, e = _correr('canal_leaks', 'usuario', 'canal_ru')
    assert 'canal-leaks' in e.tags and e.propiedades.get('leaks_menciones') == 2
    assert 'acme.com' in {x.valor for x in prod if x.tipo == 'dominio'}
    assert 'admin@acme.com' in {x.valor for x in prod if x.tipo == 'email'}


def test_canal_leaks_sin_creds(monkeypatch):
    monkeypatch.setattr(ob, '_tg_mensajes', lambda u, limite=100: (False, 'falta api_id:api_hash ...'))
    prod, e = _correr('canal_leaks', 'usuario', 'x')
    assert prod == [] and 'api_id' in e.propiedades.get('canal_leaks', '')
