"""Tests for F12 -- continuous attack surface (EASM).

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_easm.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


class _R:
    def __init__(self, data=None):
        self._data = data
    def json(self):
        return self._data


def _cliente_with(store, monkeypatch):
    monkeypatch.setattr(ob, '_store', store)
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    return c


# ── 144: asset inventory ────────────────────────────────────────────────────
def test_inventory(monkeypatch):
    store = Store()
    store.create('domain', 'x.com')
    store.create('ip', '1.2.3.4')
    store.create('port', '1.2.3.4:443')
    store.create('email', 'a@x.com')                # NOT an internet-facing asset
    c = _cliente_with(store, monkeypatch)
    d = c.get('/api/v2/inventory').get_json()
    assert d['total_activos'] == 3               # domain+ip+port, not the email
    assert set(d['inventario']) == {'domain', 'ip', 'port'}


# ── 145 + 146: continuous discovery + change detection (via the monitor) ─────
def test_discovery_changes_via_monitor():
    from core.monitor import snapshot, diff
    store = Store()
    d = store.create('domain', 'x.com', properties={'cert_expires': '2027'})
    before = snapshot(store)
    store.create('subdomain', 'nuevo.x.com')       # new asset (145)
    store.create('port', '1.2.3.4:22')            # new port (146)
    d.properties['cert_expires'] = '2020'        # cert changed (146)
    changes = diff(before, snapshot(store))
    valores = {e['value'] for e in changes.new_entities}
    assert {'nuevo.x.com', '1.2.3.4:22'} <= valores
    assert any(c['field'] == 'cert_expires' for c in changes.prop_changes)


# ── 147: infrastructure clustering ──────────────────────────────────────────
def test_infra_shared():
    from core.correlacion import correlate
    store = Store()
    store.create('domain', 'a.com', properties={'favicon_hash': '123456'})
    store.create('domain', 'b.com', properties={'favicon_hash': '123456'})   # same favicon
    store.create('domain', 'c.com', properties={'favicon_hash': '999'})       # different
    r = [x for x in correlate(store) if x.rule == 'shared-infra']
    assert len(r) == 1 and len(r[0].entities) == 2                          # a.com and b.com


def test_infra_shared_without_group():
    from core.correlacion import correlate
    store = Store()
    store.create('domain', 'solo.com', properties={'favicon_hash': '111'})
    assert not [x for x in correlate(store) if x.rule == 'shared-infra']


# ── 148: tech -> CVE map (cve_lookup, with anti-noise CPE filter) ────────────
def test_cve_lookup_tech(monkeypatch):
    resp = {'vulnerabilities': [
        {'cve': {'id': 'CVE-2021-1234',
                 'configurations': [{'nodes': [{'cpeMatch': [{'criteria': 'cpe:2.3:a:nginx:nginx:1.0'}]}]}]}},
        {'cve': {'id': 'CVE-2021-9999',      # apache, must NOT show up for tech=nginx
                 'configurations': [{'nodes': [{'cpeMatch': [{'criteria': 'cpe:2.3:a:apache:httpd:2.4'}]}]}]}},
    ]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=resp))
    store = Store()
    prod = run_by_name('cve_lookup', store.create('tech', 'nginx'), store)
    cids = {x.value for x in prod if x.type == 'cve'}
    assert cids == {'CVE-2021-1234'}             # anti-noise CPE filter: only the nginx one


# ── 149: exposure scoring ───────────────────────────────────────────────────
def test_score_exposure():
    from core.correlacion import exposure_score
    assert exposure_score({}, 0) == 0
    # surface: 10 subdom + 3 ports(*2) = 16 ; risk 40//2 = 20 -> 36
    assert exposure_score({'subdomain': 10, 'port': 3}, 40) == 36
    assert exposure_score({'subdomain': 999}, 100) == 100          # caps at 100


def test_exposure_endpoint(monkeypatch):
    store = Store()
    for i in range(5):
        store.create('subdomain', f's{i}.x.com')
    c = _cliente_with(store, monkeypatch)
    d = c.get('/api/v2/exposure').get_json()
    assert d['surface']['subdomain'] == 5 and 0 <= d['exposicion'] <= 100


# ── 150: Shadow IT / forgotten assets ───────────────────────────────────────
def test_shadow_it():
    from core.correlacion import correlate
    store = Store()
    store.create('bucket', 'acme-backups').tag('public')           # open storage
    store.create('subdomain', 'viejo.acme.com', properties={'http_status': 503})  # broken
    store.create('subdomain', 'vivo.acme.com', properties={'http_status': 200})   # healthy
    r = [x for x in correlate(store) if x.rule == 'shadow-it']
    sev = {x.severity for x in r}
    assert len(r) == 2 and sev == {'high', 'medium'}                    # bucket + broken subdom


# ── 151: historical surface diff ────────────────────────────────────────────
def test_diff_history(tmp_path):
    from core.workspaces import Manager
    g = Manager(str(tmp_path))
    g.create('caso')
    store = Store()
    store.create('subdomain', 'a.x.com')
    g.save('caso', store)
    sid = g.snapshot('caso')                     # historical snapshot: 1 asset
    store.create('subdomain', 'b.x.com')           # a new asset appeared
    g.save('caso', store)
    viejo = g.load_snapshot('caso', sid)
    assert len(viejo) == 1
    nuevos = {e.id for e in g.load('caso').entities} - {e.id for e in viejo.entities}
    assert len(nuevos) == 1                       # b.x.com appeared since the snapshot
