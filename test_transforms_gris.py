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


class _FR:
    """Fake _fetch_seguro response (status_code / text / headers)."""
    def __init__(self, status_code=200, text='', ctype='text/plain'):
        self.status_code = status_code
        self.text = text
        self.headers = {'Content-Type': ctype}


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


def test_reverse_ip(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _Resp(text='a.com\nb.com\nnot a host\n'))
    store = Store()
    e = store.create('ip', '1.2.3.4')
    prod = run_by_name('reverse_ip', e, store)
    assert {p.value for p in prod} == {'a.com', 'b.com'}     # 'not a host' rejected
    assert all(p.type == 'domain' for p in prod)


def test_reverse_ip_api_limit(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Resp(text='API count exceeded'))
    store = Store()
    e = store.create('ip', '1.2.3.4')
    assert run_by_name('reverse_ip', e, store) == []


def test_otx_passivedns(monkeypatch):
    data = {'passive_dns': [{'address': '1.2.3.4'}, {'address': '5.6.7.8'}, {'address': 'bad'}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Resp(data=data))
    store = Store()
    e = store.create('domain', 'ejemplo.com')
    prod = run_by_name('otx_passivedns', e, store)
    assert {p.value for p in prod} == {'1.2.3.4', '5.6.7.8'}
    assert all(p.type == 'ip' for p in prod)


def test_anubis_subdomains(monkeypatch):
    data = ['a.ejemplo.com', 'b.ejemplo.com', 'ejemplo.com', 'otro.com']
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Resp(data=data))
    store = Store()
    e = store.create('domain', 'ejemplo.com')
    prod = run_by_name('anubis_subdomains', e, store)
    assert {p.value for p in prod} == {'a.ejemplo.com', 'b.ejemplo.com'}  # apex + otro.com excluded
    assert all(p.type == 'subdomain' for p in prod)


def test_deep_scan(monkeypatch):
    out = ("PORT     STATE SERVICE VERSION\n"
           "22/tcp   open  ssh     OpenSSH 8.9\n"
           "443/tcp  open  https   nginx 1.24.0\n")
    monkeypatch.setattr(ob, '_which', lambda c: True)
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: out)
    store = Store()
    e = store.create('ip', '1.2.3.4')
    prod = run_by_name('deep_scan', e, store)
    assert {p.value for p in prod if p.type == 'port'} == {'1.2.3.4:22', '1.2.3.4:443'}
    assert {p.value for p in prod if p.type == 'tech'} == {'OpenSSH', 'nginx'}


def test_deep_scan_no_nmap(monkeypatch):
    monkeypatch.setattr(ob, '_which', lambda c: False)
    store = Store()
    e = store.create('ip', '1.2.3.4')
    assert run_by_name('deep_scan', e, store) == []


def test_cve_intel(monkeypatch):
    ob._KEV_CACHE['set'] = None
    ob._KEV_CACHE['ts'] = 0.0

    def fake_get(url, *a, **k):
        if 'first.org' in url:
            return _Resp(data={'data': [{'epss': '0.97', 'percentile': '0.99'}]})
        if 'cisa.gov' in url:
            return _Resp(data={'vulnerabilities': [{'cveID': 'CVE-2021-44228'}]})
        return _Resp(data={})
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    store = Store()
    e = store.create('cve', 'CVE-2021-44228')
    run_by_name('cve_intel', e, store)
    assert e.properties.get('epss') == '0.97'
    assert e.properties.get('cisa_kev') is True
    assert 'high-exploit-probability' in e.tags and 'actively-exploited' in e.tags
    ob._KEV_CACHE['set'] = None


def test_exposed_files(monkeypatch):
    def ff(url, **k):
        if url.endswith('/.env'):
            return _FR(200, 'SECRET=abc\nDB_PASS=1', 'text/plain')
        if url.endswith('/.git/HEAD'):
            return _FR(200, 'ref: refs/heads/main', 'text/plain')
        return _FR(404, 'nope', 'text/html')
    monkeypatch.setattr(ob, '_fetch_seguro', ff)
    store = Store()
    e = store.create('domain', 'ejemplo.com')
    prod = run_by_name('exposed_files', e, store)
    vals = {p.value for p in prod}
    assert 'https://ejemplo.com/.env' in vals
    assert 'https://ejemplo.com/.git/HEAD' in vals
    assert all('exposed-file' in p.tags for p in prod)


def test_exposed_files_soft_404(monkeypatch):
    # a generic path returning an HTML page must NOT be flagged
    monkeypatch.setattr(ob, '_fetch_seguro',
                        lambda url, **k: _FR(200, '<html>Not Found</html>', 'text/html'))
    store = Store()
    e = store.create('domain', 'ejemplo.com')
    assert run_by_name('exposed_files', e, store) == []


def test_secret_scan(monkeypatch):
    def ff(url, **k):
        if url.endswith('.js'):
            return _FR(200, 'var k="AIza' + 'B' * 35 + '";', 'application/javascript')
        return _FR(200, 'AKIA' + 'A' * 16 + ' <script src="/app.js"></script>', 'text/html')
    monkeypatch.setattr(ob, '_fetch_seguro', ff)
    store = Store()
    e = store.create('url', 'https://ejemplo.com/')
    prod = run_by_name('secret_scan', e, store)
    labels = {p.value.split(':')[0] for p in prod}
    assert 'AWS access key' in labels and 'Google API key' in labels
    assert all(p.type == 'credential' and 'exposed-secret' in p.tags for p in prod)


def test_geo_ip_stores_coords(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _Resp(data={'status': 'success', 'country': 'United States',
                                                     'city': 'Ashburn', 'lat': 39.04, 'lon': -77.48,
                                                     'org': 'ACME', 'as': 'AS123 ACME'}))
    store = Store()
    e = store.create('ip', '1.2.3.4')
    run_by_name('geo_ip', e, store)
    assert e.properties['lat'] == 39.04 and e.properties['lon'] == -77.48
    assert e.properties['city'] == 'Ashburn'
