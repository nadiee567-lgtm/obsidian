"""Integration tests for the main transforms, with the APIs MOCKED (F7 step 101).
They don't touch the network: they patch run_tool (dig/nmap) and SESSION.get.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_transforms_integracion.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import ejecutar_por_nombre


class FakeResp:
    def __init__(self, data):
        self._data = data
    def json(self):
        return self._data


def _correr(nombre, tipo, valor):
    alm = Store()
    e = alm.crear(tipo, valor)
    return ejecutar_por_nombre(nombre, e, alm)


def test_dns_a(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: '1.2.3.4\n5.6.7.8\n')
    prod = _correr('dns_a', 'dominio', 'ejemplo.com')
    assert {e.valor for e in prod} == {'1.2.3.4', '5.6.7.8'}
    assert all(e.tipo == 'ip' for e in prod)


def test_dns_a_sin_resultados(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: '')
    assert _correr('dns_a', 'dominio', 'ejemplo.com') == []


def test_dns_a_ignora_basura(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: ';; connection timed out\n1.2.3.4\n')
    prod = _correr('dns_a', 'dominio', 'ejemplo.com')
    assert {e.valor for e in prod} == {'1.2.3.4'}      # discards non-IP


def test_ptr(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: 'host.ejemplo.com.\n')
    prod = _correr('ptr', 'ip', '1.2.3.4')
    assert prod[0].tipo == 'dominio' and prod[0].valor == 'host.ejemplo.com'


def test_crtsh(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp([{'name_value': 'a.ejemplo.com\n*.b.ejemplo.com'}]))
    prod = _correr('crtsh', 'dominio', 'ejemplo.com')
    vals = {e.valor for e in prod}
    assert 'a.ejemplo.com' in vals and 'b.ejemplo.com' in vals
    assert all(e.tipo == 'subdominio' for e in prod)


def test_geo_ip(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp({'status': 'success', 'country': 'United States',
                                                  'org': 'ACME', 'as': 'AS123 ACME'}))
    prod = _correr('geo_ip', 'ip', '1.2.3.4')
    assert {e.tipo for e in prod} == {'pais', 'org', 'asn'}


def test_geo_ip_status_fail(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp({'status': 'fail'}))
    assert _correr('geo_ip', 'ip', '1.2.3.4') == []


def test_shodan(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'fakekey')
    host = {'org': 'ACME Corp', 'data': [
        {'port': 443, 'product': 'nginx'},
        {'port': 22, 'product': 'OpenSSH'},
        {'port': 8443, 'product': 'nginx'}]}       # nginx repeated → a single tech
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: FakeResp(host))
    prod = _correr('shodan', 'ip', '1.2.3.4')
    puertos = {e.valor for e in prod if e.tipo == 'puerto'}
    techs = {e.valor for e in prod if e.tipo == 'tech'}
    orgs = {e.valor for e in prod if e.tipo == 'org'}
    assert puertos == {'1.2.3.4:443', '1.2.3.4:22', '1.2.3.4:8443'}
    assert techs == {'nginx', 'OpenSSH'}
    assert orgs == {'ACME Corp'}


def test_shodan_sin_key_no_hace_nada(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('SHODAN_API_KEY', '')
    assert _correr('shodan', 'ip', '1.2.3.4') == []


def test_transform_con_api_caida_no_propaga(monkeypatch):
    """If the API blows up, the transform catches it and returns empty (isolation)."""
    def boom(*a, **k):
        raise RuntimeError('network down')
    monkeypatch.setattr(ob.SESSION, 'get', boom)
    assert _correr('crtsh', 'dominio', 'ejemplo.com') == []
