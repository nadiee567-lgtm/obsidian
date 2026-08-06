"""Tests for the multi-engine search transforms (F8 steps 108-113).

The APIs need a key, so here the response is MOCKED with each engine's documented
schema. It verifies parsing and entity emission, plus the keyless degradation.
Verification against the real API is pending a key.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_buscadores.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


class FakeResp:
    def __init__(self, data):
        self._data = data
    def json(self):
        return self._data


def _run_one(name, type, value):
    alm = Store()
    e = alm.create(type, value)
    return run_by_name(name, e, alm)


def _con_key(monkeypatch, resp, key='fakekey'):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: key)
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: FakeResp(resp))


# ── Censys (108) ─────────────────────────────────────────────────────────────
def test_censys(monkeypatch):
    resp = {'result': {
        'autonomous_system': {'name': 'ACME', 'asn': 64500},
        'services': [{'port': 443, 'service_name': 'HTTP'},
                     {'port': 22, 'service_name': 'SSH'}]}}
    _con_key(monkeypatch, resp, key='id:secret')
    prod = _run_one('censys', 'ip', '1.2.3.4')
    assert {e.value for e in prod if e.type == 'port'} == {'1.2.3.4:443', '1.2.3.4:22'}
    assert {e.value for e in prod if e.type == 'tech'} == {'HTTP', 'SSH'}
    assert any(e.type == 'asn' and e.value == 'AS64500' for e in prod)
    assert any(e.type == 'org' and e.value == 'ACME' for e in prod)


def test_censys_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('CENSYS_API', '')
    assert _run_one('censys', 'ip', '1.2.3.4') == []


# ── ZoomEye CN (109) ─────────────────────────────────────────────────────────
def test_zoomeye(monkeypatch):
    resp = {'matches': [{'portinfo': {'port': 80, 'service': 'http', 'app': 'nginx'}},
                        {'portinfo': {'port': 443, 'service': 'https', 'app': 'nginx'}}]}
    _con_key(monkeypatch, resp)
    prod = _run_one('zoomeye', 'ip', '1.2.3.4')
    assert {e.value for e in prod if e.type == 'port'} == {'1.2.3.4:80', '1.2.3.4:443'}
    assert 'nginx' in {e.value for e in prod if e.type == 'tech'}


def test_zoomeye_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('ZOOMEYE_KEY', '')
    assert _run_one('zoomeye', 'ip', '1.2.3.4') == []


# ── FOFA CN (110) ────────────────────────────────────────────────────────────
def test_fofa(monkeypatch):
    resp = {'error': False, 'results': [
        ['1.2.3.4', '443', 'site.com'],
        ['1.2.3.4', '80', 'other.com']]}
    _con_key(monkeypatch, resp, key='correo@x.com:apikey')
    prod = _run_one('fofa', 'ip', '1.2.3.4')
    assert {e.value for e in prod if e.type == 'port'} == {'1.2.3.4:443', '1.2.3.4:80'}
    assert {e.value for e in prod if e.type == 'domain'} == {'site.com', 'other.com'}


def test_fofa_error_api(monkeypatch):
    _con_key(monkeypatch, {'error': True, 'errmsg': 'quota'}, key='a@b.com:k')
    assert _run_one('fofa', 'ip', '1.2.3.4') == []


def test_fofa_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('FOFA_KEY', '')
    assert _run_one('fofa', 'ip', '1.2.3.4') == []


# ── Quake/360 CN (111) -- uses POST ─────────────────────────────────────────
def test_quake(monkeypatch):
    resp = {'data': [{'port': 443, 'service': {'name': 'http/ssl'}},
                     {'port': 22, 'service': {'name': 'ssh'}}]}
    monkeypatch.setattr(ob._boveda, 'get', lambda s: 'fakekey')
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: FakeResp(resp))
    prod = _run_one('quake', 'ip', '1.2.3.4')
    assert {e.value for e in prod if e.type == 'port'} == {'1.2.3.4:443', '1.2.3.4:22'}
    assert {e.value for e in prod if e.type == 'tech'} == {'http/ssl', 'ssh'}


def test_quake_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('QUAKE_KEY', '')
    assert _run_one('quake', 'ip', '1.2.3.4') == []


# ── Hunter.how + Netlas (112) ────────────────────────────────────────────────
def test_hunter(monkeypatch):
    resp = {'data': {'list': [{'port': 443, 'domain': 'a.com'}, {'port': 80, 'domain': 'b.com'}]}}
    _con_key(monkeypatch, resp)
    prod = _run_one('hunter', 'ip', '1.2.3.4')
    assert {e.value for e in prod if e.type == 'port'} == {'1.2.3.4:443', '1.2.3.4:80'}
    assert {e.value for e in prod if e.type == 'domain'} == {'a.com', 'b.com'}


def test_netlas(monkeypatch):
    resp = {'items': [{'data': {'port': 443}}, {'data': {'port': 22}}]}
    _con_key(monkeypatch, resp)
    prod = _run_one('netlas', 'ip', '1.2.3.4')
    assert {e.value for e in prod if e.type == 'port'} == {'1.2.3.4:443', '1.2.3.4:22'}


def test_hunter_netlas_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('HUNTER_KEY', '')
    monkeypatch.setenv('NETLAS_KEY', '')
    assert _run_one('hunter', 'ip', '1.2.3.4') == []
    assert _run_one('netlas', 'ip', '1.2.3.4') == []


# ── Criminal IP + BinaryEdge (113) ───────────────────────────────────────────
def test_criminalip(monkeypatch):
    resp = {'port': {'data': [{'open_port_no': 443, 'app_name': 'HTTPS'},
                              {'open_port_no': 8080, 'app_name': 'HTTP'}]}}
    _con_key(monkeypatch, resp)
    prod = _run_one('criminalip', 'ip', '1.2.3.4')
    assert {e.value for e in prod if e.type == 'port'} == {'1.2.3.4:443', '1.2.3.4:8080'}


def test_binaryedge(monkeypatch):
    resp = {'events': [{'port': 443}, {'port': 22}, {'port': 443}]}   # dedup by id
    _con_key(monkeypatch, resp)
    prod = _run_one('binaryedge', 'ip', '1.2.3.4')
    assert {e.value for e in prod if e.type == 'port'} == {'1.2.3.4:443', '1.2.3.4:22'}


def test_criminalip_binaryedge_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('CRIMINALIP_KEY', '')
    monkeypatch.setenv('BINARYEDGE_KEY', '')
    assert _run_one('criminalip', 'ip', '1.2.3.4') == []
    assert _run_one('binaryedge', 'ip', '1.2.3.4') == []


# ── Favicon pivot (114) ─────────────────────────────────────────────────────
def test_favicon_pivote(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get',
                        lambda s: {'fofa': 'a@b.com:k', 'shodan': 'sk'}.get(s))
    def fake_get(url, *a, **k):
        if 'fofa' in url:
            return FakeResp({'error': False, 'results': [['9.9.9.9'], ['8.8.8.8']]})
        return FakeResp({'matches': [{'ip_str': '7.7.7.7'}, {'ip_str': '9.9.9.9'}]})
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    alm = Store()
    h = alm.create('hash', '123456', properties={'tipo_hash': 'favicon'})
    prod = run_by_name('favicon_pivote', h, alm)
    ips = {e.value for e in prod if e.type == 'ip'}
    assert ips == {'9.9.9.9', '8.8.8.8', '7.7.7.7'}   # cross-engine dedup of 9.9.9.9


def test_favicon_pivote_ignora_hash_no_favicon(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: 'a@b.com:k')
    alm = Store()
    h = alm.create('hash', 'abc', properties={'tipo_hash': 'sha1'})
    assert run_by_name('favicon_pivote', h, alm) == []


# ── TLS certificate pivot (115) ─────────────────────────────────────────────
def test_cert_pivote(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get',
                        lambda s: {'fofa': 'a@b.com:k', 'shodan': 'sk'}.get(s))
    def fake_get(url, *a, **k):
        if 'fofa' in url:
            return FakeResp({'error': False, 'results': [['5.5.5.5']]})
        return FakeResp({'matches': [{'ip_str': '6.6.6.6'}]})
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    alm = Store()
    d = alm.create('domain', 'ejemplo.com', properties={'cert_cn': '*.ejemplo.com'})
    prod = run_by_name('cert_pivote', d, alm)
    assert {e.value for e in prod if e.type == 'ip'} == {'5.5.5.5', '6.6.6.6'}


# ── Cross-engine dedup (116) ────────────────────────────────────────────────
def test_dedup_cross_engine(monkeypatch):
    """Same host/port reported by 2 engines = 1 entity with 2 sources."""
    monkeypatch.setattr(ob._boveda, 'get', lambda s: 'id:secret')
    alm = Store()
    ip = alm.create('ip', '1.2.3.4')
    # Shodan sees port 443
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp({'data': [{'port': 443, 'product': 'nginx'}]}))
    run_by_name('shodan', ip, alm)
    # Censys sees the SAME port 443
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp({'result': {'services': [{'port': 443, 'service_name': 'HTTP'}]}}))
    run_by_name('censys', ip, alm)
    puertos = [e for e in alm.entities if e.type == 'port' and e.value == '1.2.3.4:443']
    assert len(puertos) == 1                              # ONE single entity (deterministic id)
    assert {'shodan', 'censys'} <= puertos[0].sources    # with BOTH sources


def test_todos_los_motores_registrados():
    """The 9 engines in core.motores each have a registered transform."""
    from core.transforms import REGISTRO
    from core.motores import MOTORES
    nombres = {t.name for t in REGISTRO.applicable('ip')}
    faltan = set(MOTORES) - nombres
    assert not faltan, f'engines without a transform: {faltan}'
