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
