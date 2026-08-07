"""Integration tests for the main transforms, with the APIs MOCKED (F7 step 101).
They don't touch the network: they patch run_tool (dig/nmap) and SESSION.get.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_transforms_integracion.py -q
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
    store = Store()
    e = store.create(type, value)
    return run_by_name(name, e, store)


def test_dns_a(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: '1.2.3.4\n5.6.7.8\n')
    prod = _run_one('dns_a', 'domain', 'ejemplo.com')
    assert {e.value for e in prod} == {'1.2.3.4', '5.6.7.8'}
    assert all(e.type == 'ip' for e in prod)


def test_dns_a_sin_resultados(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: '')
    assert _run_one('dns_a', 'domain', 'ejemplo.com') == []


def test_dns_a_ignora_basura(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: ';; connection timed out\n1.2.3.4\n')
    prod = _run_one('dns_a', 'domain', 'ejemplo.com')
    assert {e.value for e in prod} == {'1.2.3.4'}      # discards non-IP


def test_ptr(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: 'host.ejemplo.com.\n')
    prod = _run_one('ptr', 'ip', '1.2.3.4')
    assert prod[0].type == 'domain' and prod[0].value == 'host.ejemplo.com'


def test_crtsh(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp([{'name_value': 'a.ejemplo.com\n*.b.ejemplo.com'}]))
    prod = _run_one('crtsh', 'domain', 'ejemplo.com')
    vals = {e.value for e in prod}
    assert 'a.ejemplo.com' in vals and 'b.ejemplo.com' in vals
    assert all(e.type == 'subdomain' for e in prod)


def test_geo_ip(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp({'status': 'success', 'country': 'United States',
                                                  'org': 'ACME', 'as': 'AS123 ACME'}))
    prod = _run_one('geo_ip', 'ip', '1.2.3.4')
    assert {e.type for e in prod} == {'country', 'org', 'asn'}


def test_geo_ip_status_fail(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: FakeResp({'status': 'fail'}))
    assert _run_one('geo_ip', 'ip', '1.2.3.4') == []


def test_shodan(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: 'fakekey')
    host = {'org': 'ACME Corp', 'data': [
        {'port': 443, 'product': 'nginx'},
        {'port': 22, 'product': 'OpenSSH'},
        {'port': 8443, 'product': 'nginx'}]}       # nginx repeated → a single tech
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: FakeResp(host))
    prod = _run_one('shodan', 'ip', '1.2.3.4')
    ports = {e.value for e in prod if e.type == 'port'}
    techs = {e.value for e in prod if e.type == 'tech'}
    orgs = {e.value for e in prod if e.type == 'org'}
    assert ports == {'1.2.3.4:443', '1.2.3.4:22', '1.2.3.4:8443'}
    assert techs == {'nginx', 'OpenSSH'}
    assert orgs == {'ACME Corp'}


def test_shodan_sin_key_no_hace_nada(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('SHODAN_API_KEY', '')
    assert _run_one('shodan', 'ip', '1.2.3.4') == []


def test_transform_con_api_caida_no_propaga(monkeypatch):
    """If the API blows up, the transform catches it and returns empty (isolation)."""
    def boom(*a, **k):
        raise RuntimeError('network down')
    monkeypatch.setattr(ob.SESSION, 'get', boom)
    assert _run_one('crtsh', 'domain', 'ejemplo.com') == []
