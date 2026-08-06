"""Tests for F10 -- dark web / Tor.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_darkweb.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


def _run_one(name, type, value):
    alm = Store()
    e = alm.create(type, value)
    return run_by_name(name, e, alm), e


# ── 128: .onion routing over Tor ────────────────────────────────────────────
def test_onion_fetch_solo_onion():
    prod, _ = _run_one('onion_fetch', 'url', 'https://clearnet.com')
    assert prod == []                                # ignores non-.onion (anti-SSRF)


def test_onion_fetch(monkeypatch):
    class R:
        text = ('<title>Dark Market</title> contacto@vendor.com '
                'http://abcdefghij234567.onion/foro')
    monkeypatch.setattr(ob, '_tor_disponible', lambda: True)
    monkeypatch.setattr(ob, '_fetch_tor', lambda url, **k: R())
    prod, e = _run_one('onion_fetch', 'url', 'http://xxxxabcdefgh2345.onion/')
    assert 'contacto@vendor.com' in {x.value for x in prod if x.type == 'email'}
    assert any('.onion' in x.value for x in prod if x.type == 'url')
    assert e.properties.get('onion_title') == 'Dark Market'
    assert 'onion-live' in e.tags


def test_onion_fetch_tor_caido(monkeypatch):
    monkeypatch.setattr(ob, '_tor_disponible', lambda: False)
    prod, e = _run_one('onion_fetch', 'url', 'http://xxxxabcdefgh2345.onion/')
    assert prod == [] and 'Tor unavailable' in e.properties.get('tor', '')


# ── 129: Ahmia + Haystak ────────────────────────────────────────────────────
def test_haystak(monkeypatch):
    class R:
        text = 'results: abcdefghij234567.onion y zzzz2233abcdefgh.onion'
    monkeypatch.setattr(ob, '_tor_disponible', lambda: True)
    monkeypatch.setattr(ob, '_fetch_tor', lambda url, **k: R())
    prod, _ = _run_one('haystak', 'person', 'target')
    onions = {x.value for x in prod if x.type == 'url'}
    assert any('.onion' in o for o in onions) and len(onions) == 2


def test_haystak_sin_tor(monkeypatch):
    monkeypatch.setattr(ob, '_tor_disponible', lambda: False)
    prod, e = _run_one('haystak', 'person', 'target')
    assert prod == [] and 'requires Tor' in e.properties.get('haystak', '')


# ── 130: Telegram (Telethon) -- degradation paths (the active one needs an account) ─
def test_telegram_sin_credenciales(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('TELEGRAM_API', '')
    prod, e = _run_one('telegram', 'user', 'durov')
    assert prod == [] and 'api_id:api_hash' in e.properties.get('telegram', '')


def test_telegram_sin_sesion(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: '123:abchash')
    monkeypatch.setattr(ob.os.path, 'exists', lambda p: not str(p).endswith('telegram.session'))
    prod, e = _run_one('telegram', 'user', 'durov')
    assert prod == [] and 'login' in e.properties.get('telegram', '')


# ── 131: channel monitoring (testable logic; fetch degrades without an account) ─
def test_coincidencias_leak():
    hits = ob.leak_matches(['hola mundo', 'nueva DATABASE a la venta', 'ransomware group', 'nada'])
    assert len(hits) == 2 and {h['keyword'] for h in hits} == {'database', 'ransomware'}


def test_canal_leaks(monkeypatch):
    textos = ['combolist fresca de acme.com', 'admin@acme.com filtrado en breach', 'gatitos']
    monkeypatch.setattr(ob, '_tg_mensajes', lambda u, limite=100: (True, (123, textos)))
    prod, e = _run_one('canal_leaks', 'user', 'canal_ru')
    assert 'leaks-channel' in e.tags and e.properties.get('leaks_mentions') == 2
    assert 'acme.com' in {x.value for x in prod if x.type == 'domain'}
    assert 'admin@acme.com' in {x.value for x in prod if x.type == 'email'}


def test_canal_leaks_sin_creds(monkeypatch):
    monkeypatch.setattr(ob, '_tg_mensajes', lambda u, limite=100: (False, 'falta api_id:api_hash ...'))
    prod, e = _run_one('canal_leaks', 'user', 'x')
    assert prod == [] and 'api_id' in e.properties.get('canal_leaks', '')


# ── 132: domain-level stealer logs (keyless, Hudson Rock) ────────────────────
class _RjD:
    def __init__(self, data):
        self._d = data
    def json(self):
        return self._d


def test_stealer_domain(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _RjD({'data': {'employees': 12, 'users': 340}}))
    _, e = _run_one('stealer_domain', 'domain', 'acme.com')
    assert 'stealer-exposed' in e.tags
    assert e.properties.get('stealer_employees') == 12 and e.properties.get('stealer_users') == 340


def test_stealer_domain_clean(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _RjD({'data': {'employees': 0, 'users': 0}}))
    _, e = _run_one('stealer_domain', 'domain', 'acme.com')
    assert 'stealer-exposed' not in e.tags


# ── 133: paste monitoring (psbdmp + keyless dorks) ──────────────────────────
def test_pastes(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _RjD({'data': [{'id': 'abc123'}, {'id': 'def456'}]}))
    prod, _ = _run_one('pastes', 'email', 'a@b.com')
    urls = {x.value for x in prod if x.type == 'url'}
    assert 'https://pastebin.com/abc123' in urls          # from psbdmp
    assert any('site%3Apastebin.com' in u for u in urls)  # dork (url-encoded, correct)
    assert len(urls) >= 6                                  # 2 pastes + 4 dorks


def test_pastes_psbdmp_muerto(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('psbdmp down')
    monkeypatch.setattr(ob.SESSION, 'get', boom)
    prod, _ = _run_one('pastes', 'email', 'a@b.com')
    urls = {x.value for x in prod if x.type == 'url'}
    assert len(urls) == 4                                  # the 4 dorks still come out


# ── 134: historical leaks (Intelligence X, keyed) ───────────────────────────
def test_intelx(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: 'fakekey')
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: _RjD({'id': 'search-123'}))
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _RjD({'records': [{'systemid': 'sys-a', 'name': 'leak1',
                                                           'bucket': 'leaks'}]}))
    prod, _ = _run_one('intelx', 'email', 'a@b.com')
    assert 'https://intelx.io/?did=sys-a' in {x.value for x in prod if x.type == 'url'}


def test_intelx_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('INTELX_KEY', '')
    prod, _ = _run_one('intelx', 'email', 'a@b.com')
    assert prod == []


# ── 135: breach aggregator (keyless-first, unifies sources) ─────────────────
def test_breaches_agrega_y_dedup(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)   # no HIBP
    monkeypatch.setenv('HIBP_API_KEY', '')
    def fake_get(url, *a, **k):
        if 'xposedornot' in url:
            return _RjD({'breaches': [['Adobe', 'LinkedIn']]})
        if 'leakcheck' in url:
            return _RjD({'success': True, 'sources': [{'name': 'Canva'}, {'name': 'Adobe'}]})
        return _RjD({})
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    prod, e = _run_one('breaches', 'email', 'a@b.com')
    orgs = {x.value for x in prod if x.type == 'org'}
    assert orgs == {'Adobe', 'LinkedIn', 'Canva'}    # unified and deduped (Adobe once)
    assert 'leaked' in e.tags


def test_breaches_limpio(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _RjD({}))
    prod, e = _run_one('breaches', 'email', 'nadie@limpio.com')
    assert prod == [] and 'leaked' not in e.tags
