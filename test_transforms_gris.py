"""Tests for the new passive-recon transforms: rapiddns, wayback_urls, asn_netblocks.
APIs mocked -- no network."""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


class _Resp:
    def __init__(self, text='', data=None):
        self._text = text
        self._data = data
    @property
    def text(self):
        return self._text
    def json(self):
        return self._data


def test_rapiddns(monkeypatch):
    html = ('<table><tr><th>domain</th></tr>'
            '<tr><td>shop.ejemplo.com</td><td>1.2.3.4</td><td>A</td></tr>'
            '<tr><td>mail.ejemplo.com</td><td></td><td>CNAME</td></tr>'
            '<tr><td>otro.com</td><td>9.9.9.9</td><td>A</td></tr></table>')
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Resp(text=html))
    store = Store()
    e = store.create('domain', 'ejemplo.com')
    prod = run_by_name('rapiddns', e, store)
    subs = {p.value for p in prod if p.type == 'subdomain'}
    assert subs == {'shop.ejemplo.com', 'mail.ejemplo.com'}   # otro.com is not a subdomain
    assert '1.2.3.4' in {x.value for x in store.of_type('ip')}


def test_wayback_urls(monkeypatch):
    rows = [['original'], ['http://ejemplo.com/admin'],
            ['http://ejemplo.com/login?u=1'], ['http://ejemplo.com/admin']]  # dup collapses
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Resp(data=rows))
    store = Store()
    e = store.create('domain', 'ejemplo.com')
    prod = run_by_name('wayback_urls', e, store)
    vals = {p.value for p in prod}
    assert 'http://ejemplo.com/admin' in vals and 'http://ejemplo.com/login?u=1' in vals
    assert all(p.type == 'url' for p in prod)


def test_asn_netblocks(monkeypatch):
    data = {'data': {'prefixes': [{'prefix': '1.2.3.0/24'}, {'prefix': '5.6.0.0/16'}]}}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Resp(data=data))
    store = Store()
    e = store.create('asn', 'AS64500 ACME')   # value carries org text; number is parsed out
    prod = run_by_name('asn_netblocks', e, store)
    assert {p.value for p in prod} == {'1.2.3.0/24', '5.6.0.0/16'}
    assert all(p.type == 'netblock' for p in prod)


def test_asn_netblocks_ignores_non_asn():
    store = Store()
    e = store.create('asn', 'no-number-here')
    assert run_by_name('asn_netblocks', e, store) == []
