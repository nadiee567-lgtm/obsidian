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


# ── Quake/360 CN (111) — usa POST ────────────────────────────────────────────
def test_quake(monkeypatch):
    resp = {'data': [{'port': 443, 'service': {'name': 'http/ssl'}},
                     {'port': 22, 'service': {'name': 'ssh'}}]}
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'fakekey')
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: FakeResp(resp))
    prod = _correr('quake', 'ip', '1.2.3.4')
    assert {e.valor for e in prod if e.tipo == 'puerto'} == {'1.2.3.4:443', '1.2.3.4:22'}
    assert {e.valor for e in prod if e.tipo == 'tech'} == {'http/ssl', 'ssh'}


def test_quake_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('QUAKE_KEY', '')
    assert _correr('quake', 'ip', '1.2.3.4') == []


# ── Hunter.how + Netlas (112) ────────────────────────────────────────────────
def test_hunter(monkeypatch):
    resp = {'data': {'list': [{'port': 443, 'domain': 'a.com'}, {'port': 80, 'domain': 'b.com'}]}}
    _con_key(monkeypatch, resp)
    prod = _correr('hunter', 'ip', '1.2.3.4')
    assert {e.valor for e in prod if e.tipo == 'puerto'} == {'1.2.3.4:443', '1.2.3.4:80'}
    assert {e.valor for e in prod if e.tipo == 'dominio'} == {'a.com', 'b.com'}


def test_netlas(monkeypatch):
    resp = {'items': [{'data': {'port': 443}}, {'data': {'port': 22}}]}
    _con_key(monkeypatch, resp)
    prod = _correr('netlas', 'ip', '1.2.3.4')
    assert {e.valor for e in prod if e.tipo == 'puerto'} == {'1.2.3.4:443', '1.2.3.4:22'}


def test_hunter_netlas_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('HUNTER_KEY', '')
    monkeypatch.setenv('NETLAS_KEY', '')
    assert _correr('hunter', 'ip', '1.2.3.4') == []
    assert _correr('netlas', 'ip', '1.2.3.4') == []


# ── Criminal IP + BinaryEdge (113) ───────────────────────────────────────────
def test_criminalip(monkeypatch):
    resp = {'port': {'data': [{'open_port_no': 443, 'app_name': 'HTTPS'},
                              {'open_port_no': 8080, 'app_name': 'HTTP'}]}}
    _con_key(monkeypatch, resp)
    prod = _correr('criminalip', 'ip', '1.2.3.4')
    assert {e.valor for e in prod if e.tipo == 'puerto'} == {'1.2.3.4:443', '1.2.3.4:8080'}


def test_binaryedge(monkeypatch):
    resp = {'events': [{'port': 443}, {'port': 22}, {'port': 443}]}   # dedup por id
    _con_key(monkeypatch, resp)
    prod = _correr('binaryedge', 'ip', '1.2.3.4')
    assert {e.valor for e in prod if e.tipo == 'puerto'} == {'1.2.3.4:443', '1.2.3.4:22'}


def test_criminalip_binaryedge_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('CRIMINALIP_KEY', '')
    monkeypatch.setenv('BINARYEDGE_KEY', '')
    assert _correr('criminalip', 'ip', '1.2.3.4') == []
    assert _correr('binaryedge', 'ip', '1.2.3.4') == []


# ── Pivote por favicon (114) ─────────────────────────────────────────────────
def test_favicon_pivote(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener',
                        lambda s: {'fofa': 'a@b.com:k', 'shodan': 'sk'}.get(s))
    def fake_get(url, *a, **k):
        if 'fofa' in url:
            return FakeResp({'error': False, 'results': [['9.9.9.9'], ['8.8.8.8']]})
        return FakeResp({'matches': [{'ip_str': '7.7.7.7'}, {'ip_str': '9.9.9.9'}]})
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    alm = Almacen()
    h = alm.crear('hash', '123456', propiedades={'tipo_hash': 'favicon'})
    prod = ejecutar_por_nombre('favicon_pivote', h, alm)
    ips = {e.valor for e in prod if e.tipo == 'ip'}
    assert ips == {'9.9.9.9', '8.8.8.8', '7.7.7.7'}   # dedup cross-motor de 9.9.9.9


def test_favicon_pivote_ignora_hash_no_favicon(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'a@b.com:k')
    alm = Almacen()
    h = alm.crear('hash', 'abc', propiedades={'tipo_hash': 'sha1'})
    assert ejecutar_por_nombre('favicon_pivote', h, alm) == []


# ── Pivote por certificado TLS (115) ─────────────────────────────────────────
def test_cert_pivote(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener',
                        lambda s: {'fofa': 'a@b.com:k', 'shodan': 'sk'}.get(s))
    def fake_get(url, *a, **k):
        if 'fofa' in url:
            return FakeResp({'error': False, 'results': [['5.5.5.5']]})
        return FakeResp({'matches': [{'ip_str': '6.6.6.6'}]})
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    alm = Almacen()
    d = alm.crear('dominio', 'ejemplo.com', propiedades={'cert_cn': '*.ejemplo.com'})
    prod = ejecutar_por_nombre('cert_pivote', d, alm)
    assert {e.valor for e in prod if e.tipo == 'ip'} == {'5.5.5.5', '6.6.6.6'}


# ── Dedup cross-engine (116) ─────────────────────────────────────────────────
def test_dedup_cross_engine(monkeypatch):
    """Mismo host/puerto reportado por 2 motores = 1 entidad con 2 fuentes."""
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'id:secret')
    alm = Almacen()
    ip = alm.crear('ip', '1.2.3.4')
    # Shodan ve el puerto 443
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp({'data': [{'port': 443, 'product': 'nginx'}]}))
    ejecutar_por_nombre('shodan', ip, alm)
    # Censys ve el MISMO puerto 443
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp({'result': {'services': [{'port': 443, 'service_name': 'HTTP'}]}}))
    ejecutar_por_nombre('censys', ip, alm)
    puertos = [e for e in alm.entidades if e.tipo == 'puerto' and e.valor == '1.2.3.4:443']
    assert len(puertos) == 1                              # UNA sola entidad (id determinista)
    assert {'shodan', 'censys'} <= puertos[0].origenes    # con las DOS fuentes


def test_todos_los_motores_registrados():
    """Los 9 motores de core.motores tienen su transform registrado."""
    from core.transforms import REGISTRO
    from core.motores import MOTORES
    nombres = {t.nombre for t in REGISTRO.aplicables('ip')}
    faltan = set(MOTORES) - nombres
    assert not faltan, f'motores sin transform: {faltan}'
