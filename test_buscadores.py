"""Tests de los transforms de buscadores multi-motor (F8 pasos 108-113).

Las APIs necesitan key, así que aquí se MOCKEA la respuesta con el esquema
documentado de cada motor. Verifica el parseo y la emisión de entidades, más el
degradado sin key. La verificación contra la API real queda pendiente de una key.

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_buscadores.py -q
"""
import obsidian_web as ob
from core.modelo import Almacen
from core.transforms import ejecutar_por_nombre


class FakeResp:
    def __init__(self, data):
        self._data = data
    def json(self):
        return self._data


def _correr(nombre, tipo, valor):
    alm = Almacen()
    e = alm.crear(tipo, valor)
    return ejecutar_por_nombre(nombre, e, alm)


def _con_key(monkeypatch, resp, key='fakekey'):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: key)
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: FakeResp(resp))


# ── Censys (108) ─────────────────────────────────────────────────────────────
def test_censys(monkeypatch):
    resp = {'result': {
        'autonomous_system': {'name': 'ACME', 'asn': 64500},
        'services': [{'port': 443, 'service_name': 'HTTP'},
                     {'port': 22, 'service_name': 'SSH'}]}}
    _con_key(monkeypatch, resp, key='id:secret')
    prod = _correr('censys', 'ip', '1.2.3.4')
    assert {e.valor for e in prod if e.tipo == 'puerto'} == {'1.2.3.4:443', '1.2.3.4:22'}
    assert {e.valor for e in prod if e.tipo == 'tech'} == {'HTTP', 'SSH'}
    assert any(e.tipo == 'asn' and e.valor == 'AS64500' for e in prod)
    assert any(e.tipo == 'org' and e.valor == 'ACME' for e in prod)


def test_censys_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('CENSYS_API', '')
    assert _correr('censys', 'ip', '1.2.3.4') == []


# ── ZoomEye CN (109) ─────────────────────────────────────────────────────────
def test_zoomeye(monkeypatch):
    resp = {'matches': [{'portinfo': {'port': 80, 'service': 'http', 'app': 'nginx'}},
                        {'portinfo': {'port': 443, 'service': 'https', 'app': 'nginx'}}]}
    _con_key(monkeypatch, resp)
    prod = _correr('zoomeye', 'ip', '1.2.3.4')
    assert {e.valor for e in prod if e.tipo == 'puerto'} == {'1.2.3.4:80', '1.2.3.4:443'}
    assert 'nginx' in {e.valor for e in prod if e.tipo == 'tech'}


def test_zoomeye_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('ZOOMEYE_KEY', '')
    assert _correr('zoomeye', 'ip', '1.2.3.4') == []


# ── FOFA CN (110) ────────────────────────────────────────────────────────────
def test_fofa(monkeypatch):
    resp = {'error': False, 'results': [
        ['1.2.3.4', '443', 'sitio.com'],
        ['1.2.3.4', '80', 'otro.com']]}
    _con_key(monkeypatch, resp, key='correo@x.com:apikey')
    prod = _correr('fofa', 'ip', '1.2.3.4')
    assert {e.valor for e in prod if e.tipo == 'puerto'} == {'1.2.3.4:443', '1.2.3.4:80'}
    assert {e.valor for e in prod if e.tipo == 'dominio'} == {'sitio.com', 'otro.com'}


def test_fofa_error_api(monkeypatch):
    _con_key(monkeypatch, {'error': True, 'errmsg': 'quota'}, key='a@b.com:k')
    assert _correr('fofa', 'ip', '1.2.3.4') == []


def test_fofa_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('FOFA_KEY', '')
    assert _correr('fofa', 'ip', '1.2.3.4') == []
