"""Tests for the exposure scanners: internetdb (passive, keyless) and range_scan (active nmap)."""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


def _run(name, type, value):
    store = Store()
    e = store.create(type, value)
    return run_by_name(name, e, store), e, store


class _Rj:
    def __init__(self, d): self._d = d
    def json(self): return self._d


def test_internetdb_parses_exposure(monkeypatch):
    sample = {'ip': '1.2.3.4', 'ports': [22, 443, 3389], 'vulns': ['CVE-2021-1234'],
              'hostnames': ['mail.acme.example'], 'cpes': ['cpe:/a:nginx:nginx:1.24'],
              'tags': ['self-signed']}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Rj(sample))
    prod, e, _ = _run('internetdb', 'ip', '1.2.3.4')
    ports = {p.value for p in prod if p.type == 'port'}
    assert ports == {'1.2.3.4:22', '1.2.3.4:443', '1.2.3.4:3389'}
    assert any(p.type == 'cve' and p.value == 'CVE-2021-1234' for p in prod)
    assert any(p.type == 'tech' and 'nginx' in p.value for p in prod)
    assert any(p.type == 'subdomain' and p.value == 'mail.acme.example' for p in prod)
    assert 'self-signed' in e.tags


def test_internetdb_404_no_crash(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Rj({'detail': 'No information'}))
    prod, _, _ = _run('internetdb', 'ip', '8.8.8.8')
    assert prod == []


def test_range_scan_parses_hosts(monkeypatch):
    greppable = (
        "# Nmap scan\n"
        "Host: 203.0.113.10 ()\tPorts: 22/open/tcp//ssh///, 443/open/tcp//https///\n"
        "Host: 203.0.113.25 ()\tPorts: 3389/open/tcp//ms-wbt-server///\n"
        "# Nmap done\n"
    )
    monkeypatch.setattr(ob, '_which', lambda t: True)
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: greppable)
    prod, _, store = _run('range_scan', 'ip', '203.0.113.10')
    hosts = {p.value for p in prod if p.type == 'ip'}
    assert hosts == {'203.0.113.10', '203.0.113.25'}
    ports = {p.value for p in store.entities if p.type == 'port'}
    assert '203.0.113.10:22' in ports and '203.0.113.25:3389' in ports


def test_range_scan_no_nmap(monkeypatch):
    monkeypatch.setattr(ob, '_which', lambda t: False)
    prod, _, _ = _run('range_scan', 'ip', '10.0.0.1')
    assert prod == []


def test_both_applicable_to_ip():
    names = {t.name for t in ob.REGISTRO.applicable('ip')}
    assert {'internetdb', 'range_scan'} <= names


def test_holehe_parses_used_sites(monkeypatch):
    out = "Twitter : holehe\n[+] adobe.com\n[-] amazon.com\n[x] facebook.com\n[+] github.com\n"
    monkeypatch.setattr(ob, '_which', lambda t: True)
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: out)
    prod, e, _ = _run('holehe', 'email', 'a@b.com')
    plats = {p.value for p in prod if p.type == 'platform'}
    assert plats == {'adobe.com', 'github.com'}
    assert 'has-accounts' in e.tags


def test_maigret_parses_profiles(monkeypatch):
    out = ("on 3: [+] GitHub: https://github.com/nadiee\n"
           "[+] YouTube: https://www.youtube.com/@nadiee/about\n"
           "[+] Using sites database: /home/user/.maigret/data.json\n")
    monkeypatch.setattr(ob, '_which', lambda t: True)
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: out)
    prod, _, _ = _run('maigret', 'user', 'nadiee')
    urls = {p.value for p in prod if p.type == 'url'}
    assert 'https://github.com/nadiee' in urls
    assert 'https://www.youtube.com/@nadiee/about' in urls
    assert not any('data.json' in u for u in urls)


def test_theharvester_filters_to_domain(monkeypatch):
    out = ("[*] Emails found:\nadmin@acme.com\nfoo@other.com\n"
           "[*] Hosts found:\nmail.acme.com\napi.acme.com\nevil.com\n")
    monkeypatch.setattr(ob, '_which', lambda t: True)
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: out)
    prod, _, _ = _run('theharvester', 'domain', 'acme.com')
    emails = {p.value for p in prod if p.type == 'email'}
    subs = {p.value for p in prod if p.type == 'subdomain'}
    assert emails == {'admin@acme.com'}
    assert subs == {'mail.acme.com', 'api.acme.com'}


def test_cli_tools_no_binary(monkeypatch):
    monkeypatch.setattr(ob, '_which', lambda t: False)
    for name, typ, val in [('holehe', 'email', 'a@b.com'), ('maigret', 'user', 'x'),
                           ('theharvester', 'domain', 'a.com')]:
        prod, _, _ = _run(name, typ, val)
        assert prod == []


def _key(monkeypatch, val='fakekey'):
    monkeypatch.setattr(ob, '_rotating_key', lambda s: val)


def test_malwarebazaar(monkeypatch):
    _key(monkeypatch)
    resp = {'query_status': 'ok', 'data': [{'signature': 'Emotet', 'file_type': 'exe',
                                            'tags': ['banker', 'trojan']}]}
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: _Rj(resp))
    _, e, _ = _run('malwarebazaar', 'hash', 'a' * 64)
    assert e.properties['malware'] == 'Emotet'
    assert e.properties['file_type'] == 'exe'
    assert {'malware', 'banker', 'trojan'} <= e.tags


def test_threatfox(monkeypatch):
    _key(monkeypatch)
    resp = {'query_status': 'ok', 'data': [{'malware_printable': 'Cobalt Strike'}]}
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: _Rj(resp))
    _, e, _ = _run('threatfox', 'ip', '1.2.3.4')
    assert e.properties['threats'] == ['Cobalt Strike']
    assert 'malicious' in e.tags


def test_emailrep(monkeypatch):
    _key(monkeypatch)
    resp = {'reputation': 'low', 'suspicious': True,
            'details': {'credentials_leaked': True, 'malicious_activity': True}}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Rj(resp))
    _, e, _ = _run('emailrep', 'email', 'a@b.com')
    assert e.properties['reputation'] == 'low'
    assert {'suspicious', 'leaked', 'malicious'} <= e.tags


def test_urlscan_keyless(monkeypatch):
    resp = {'results': [{'page': {'ip': '9.9.9.9', 'url': 'https://acme.com/login'}},
                        {'page': {'ip': '9.9.9.9', 'url': 'https://acme.com/admin'}}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _Rj(resp))
    prod, _, _ = _run('urlscan', 'domain', 'acme.com')
    ips = {p.value for p in prod if p.type == 'ip'}
    urls = {p.value for p in prod if p.type == 'url'}
    assert ips == {'9.9.9.9'}
    assert urls == {'https://acme.com/login', 'https://acme.com/admin'}


def test_keyed_no_key(monkeypatch):
    monkeypatch.setattr(ob, '_rotating_key', lambda s: '')
    monkeypatch.setattr(ob, 'os', ob.os)
    for name, typ, val in [('malwarebazaar', 'hash', 'a' * 64),
                           ('threatfox', 'ip', '1.2.3.4'), ('emailrep', 'email', 'a@b.com')]:
        _, e, _ = _run(name, typ, val)
        assert not e.tags and not e.properties.get('malware') and not e.properties.get('threats')
