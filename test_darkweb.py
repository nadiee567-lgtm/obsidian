"""Tests for F10 -- dark web / Tor.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_darkweb.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import ejecutar_por_nombre


def _correr(nombre, tipo, valor):
    alm = Store()
    e = alm.crear(tipo, valor)
    return ejecutar_por_nombre(nombre, e, alm), e


# ── 128: .onion routing over Tor ────────────────────────────────────────────
def test_onion_fetch_solo_onion():
    prod, _ = _correr('onion_fetch', 'url', 'https://clearnet.com')
    assert prod == []                                # ignores non-.onion (anti-SSRF)


def test_onion_fetch(monkeypatch):
    class R:
        text = ('<title>Dark Market</title> contacto@vendor.com '
                'http://abcdefghij234567.onion/foro')
    monkeypatch.setattr(ob, '_tor_disponible', lambda: True)
    monkeypatch.setattr(ob, '_fetch_tor', lambda url, **k: R())
    prod, e = _correr('onion_fetch', 'url', 'http://xxxxabcdefgh2345.onion/')
    assert 'contacto@vendor.com' in {x.valor for x in prod if x.tipo == 'email'}
    assert any('.onion' in x.valor for x in prod if x.tipo == 'url')
    assert e.propiedades.get('onion_titulo') == 'Dark Market'
    assert 'onion-vivo' in e.tags


def test_onion_fetch_tor_caido(monkeypatch):
    monkeypatch.setattr(ob, '_tor_disponible', lambda: False)
    prod, e = _correr('onion_fetch', 'url', 'http://xxxxabcdefgh2345.onion/')
    assert prod == [] and 'Tor unavailable' in e.propiedades.get('tor', '')


# ── 129: Ahmia + Haystak ────────────────────────────────────────────────────
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
    assert prod == [] and 'requires Tor' in e.propiedades.get('haystak', '')


# ── 130: Telegram (Telethon) -- degradation paths (the active one needs an account) ─
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


# ── 131: channel monitoring (testable logic; fetch degrades without an account) ─
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


# ── 132: domain-level stealer logs (keyless, Hudson Rock) ────────────────────
class _RjD:
    def __init__(self, data):
        self._d = data
    def json(self):
        return self._d


def test_stealer_dominio(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _RjD({'data': {'employees': 12, 'users': 340}}))
    _, e = _correr('stealer_dominio', 'dominio', 'acme.com')
    assert 'stealer-expuesto' in e.tags
    assert e.propiedades.get('stealer_empleados') == 12 and e.propiedades.get('stealer_usuarios') == 340


def test_stealer_dominio_limpio(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _RjD({'data': {'employees': 0, 'users': 0}}))
    _, e = _correr('stealer_dominio', 'dominio', 'acme.com')
    assert 'stealer-expuesto' not in e.tags


# ── 133: paste monitoring (psbdmp + keyless dorks) ──────────────────────────
def test_pastes(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _RjD({'data': [{'id': 'abc123'}, {'id': 'def456'}]}))
    prod, _ = _correr('pastes', 'email', 'a@b.com')
    urls = {x.valor for x in prod if x.tipo == 'url'}
    assert 'https://pastebin.com/abc123' in urls          # from psbdmp
    assert any('site%3Apastebin.com' in u for u in urls)  # dork (url-encoded, correct)
    assert len(urls) >= 6                                  # 2 pastes + 4 dorks


def test_pastes_psbdmp_muerto(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('psbdmp down')
    monkeypatch.setattr(ob.SESSION, 'get', boom)
    prod, _ = _correr('pastes', 'email', 'a@b.com')
    urls = {x.valor for x in prod if x.tipo == 'url'}
    assert len(urls) == 4                                  # the 4 dorks still come out


# ── 134: historical leaks (Intelligence X, keyed) ───────────────────────────
def test_intelx(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'fakekey')
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: _RjD({'id': 'search-123'}))
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _RjD({'records': [{'systemid': 'sys-a', 'name': 'leak1',
                                                           'bucket': 'leaks'}]}))
    prod, _ = _correr('intelx', 'email', 'a@b.com')
    assert 'https://intelx.io/?did=sys-a' in {x.valor for x in prod if x.tipo == 'url'}


def test_intelx_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('INTELX_KEY', '')
    prod, _ = _correr('intelx', 'email', 'a@b.com')
    assert prod == []


# ── 135: breach aggregator (keyless-first, unifies sources) ─────────────────
def test_breaches_agrega_y_dedup(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)   # no HIBP
    monkeypatch.setenv('HIBP_API_KEY', '')
    def fake_get(url, *a, **k):
        if 'xposedornot' in url:
            return _RjD({'breaches': [['Adobe', 'LinkedIn']]})
        if 'leakcheck' in url:
            return _RjD({'success': True, 'sources': [{'name': 'Canva'}, {'name': 'Adobe'}]})
        return _RjD({})
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    prod, e = _correr('breaches', 'email', 'a@b.com')
    orgs = {x.valor for x in prod if x.tipo == 'org'}
    assert orgs == {'Adobe', 'LinkedIn', 'Canva'}    # unified and deduped (Adobe once)
    assert 'filtrado' in e.tags


def test_breaches_limpio(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _RjD({}))
    prod, e = _correr('breaches', 'email', 'nadie@limpio.com')
    assert prod == [] and 'filtrado' not in e.tags
