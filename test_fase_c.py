"""Phase C -- new keyless transforms (endoflife.date, ProxyNova COMB) + EOL rule.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_fase_c.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


class _R:
    def __init__(self, data=None, code=200):
        self._d, self.status_code = data, code
    def json(self):
        return self._d


def _run(name, type, value, **props):
    alm = Store()
    e = alm.create(type, value, properties=props)
    return run_by_name(name, e, alm), e, alm


# ── endoflife.date (tech -> EOL) ─────────────────────────────────────────────
def test_eol_flags_dead_version(monkeypatch):
    # nginx 1.18 whose cycle is EOL in the past
    cycles = [{'cycle': '1.25', 'eol': False}, {'cycle': '1.18', 'eol': '2020-01-01'}]
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=cycles))
    _, e, alm = _run('eol', 'tech', 'nginx', version='1.18.0')
    assert 'eol' in e.tags and e.properties.get('eol_since') == '2020-01-01'
    # correlation rule fires
    from core.correlacion import correlate
    h = correlate(alm)
    assert any(x.rule == 'software-eol' and x.severity == 'high' for x in h)


def test_eol_clean_when_supported(monkeypatch):
    cycles = [{'cycle': '1.25', 'eol': False}, {'cycle': '1.18', 'eol': '2099-01-01'}]
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=cycles))
    _, e, _ = _run('eol', 'tech', 'nginx', version='1.18.0')
    assert 'eol' not in e.tags


def test_eol_untracked_product_noop(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data={}, code=404))
    _, e, _ = _run('eol', 'tech', 'inventado-xyz')
    assert 'eol' not in e.tags and 'eol_tracked' not in e.properties


# ── ProxyNova COMB (email -> breach count) ───────────────────────────────────
def test_comb_flags_leaked(monkeypatch):
    resp = {'count': 42, 'lines': ['a@b.com:123456', 'a@b.com:hunter2', 'other@x.com:z']}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=resp))
    _, e, _ = _run('comb', 'email', 'a@b.com')
    assert 'leaked' in e.tags and e.properties.get('comb_count') == 42
    # security/ethics: plaintext passwords are NOT stored in the graph
    assert 'hunter2' not in str(e.properties)


def test_comb_clean_email(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data={'count': 0, 'lines': []}))
    _, e, _ = _run('comb', 'email', 'clean@nowhere.com')
    assert 'leaked' not in e.tags


# ── Gravatar (email -> person + accounts) ────────────────────────────────────
def test_gravatar_profile(monkeypatch):
    prof = {'entry': [{'displayName': 'Jane Dev',
                       'accounts': [{'url': 'https://github.com/jane', 'shortname': 'github'}],
                       'urls': [{'value': 'https://jane.dev'}]}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=prof))
    prod, e, _ = _run('gravatar', 'email', 'jane@dev.com')
    assert 'has-gravatar' in e.tags
    assert 'Jane Dev' in {x.value for x in prod if x.type == 'person'}
    assert 'https://github.com/jane' in {x.value for x in prod if x.type == 'url'}


def test_gravatar_no_profile(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data='User not found', code=404))
    prod, e, _ = _run('gravatar', 'email', 'nobody@nowhere.com')
    assert prod == [] and 'has-gravatar' not in e.tags


# ── IP-RDAP (ip -> net owner + abuse) ────────────────────────────────────────
def test_ip_rdap(monkeypatch):
    d = {'name': 'GOOGLE', 'startAddress': '8.8.8.0', 'endAddress': '8.8.8.255',
         'entities': [{'roles': ['registrant'],
                       'vcardArray': ['vcard', [['fn', {}, 'text', 'Google LLC']]]},
                      {'roles': ['abuse'],
                       'vcardArray': ['vcard', [['fn', {}, 'text', 'Google Abuse']]]}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=d))
    prod, e, _ = _run('ip_rdap', 'ip', '8.8.8.8')
    assert e.properties.get('net_name') == 'GOOGLE'
    assert e.properties.get('abuse_contact') == 'Google Abuse'
    assert 'Google LLC' in {x.value for x in prod if x.type == 'org'}


# ── RIPEstat (ip -> ASN + prefix) ────────────────────────────────────────────
def test_ripe_netinfo(monkeypatch):
    d = {'data': {'prefix': '8.8.8.0/24', 'asns': ['15169']}}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=d))
    prod, e, _ = _run('ripe_netinfo', 'ip', '8.8.8.8')
    assert e.properties.get('prefix') == '8.8.8.0/24'
    assert 'AS15169' in {x.value for x in prod if x.type == 'asn'}


# ── DNSTwister (domain -> registered typosquats) ─────────────────────────────
def test_dnstwister(monkeypatch):
    fuzz = {'fuzzy_domains': [{'domain': 'github.com'}, {'domain': 'gitbub.com'},
                              {'domain': 'guthub.com'}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=fuzz))
    # only gitbub.com "resolves"
    monkeypatch.setattr(ob, 'run_tool',
                        lambda argv, **k: '1.2.3.4\n' if 'gitbub.com' in argv else '')
    prod, _, _ = _run('dnstwister', 'domain', 'github.com')
    squats = {x.value for x in prod if x.type == 'domain'}
    assert 'gitbub.com' in squats and 'guthub.com' not in squats
    assert all('typosquat' in x.tags for x in prod if x.value == 'gitbub.com')
