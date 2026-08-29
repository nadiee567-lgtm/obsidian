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


def test_inventory(monkeypatch):
    store = Store()
    store.create('domain', 'x.com')
    store.create('ip', '1.2.3.4')
    store.create('port', '1.2.3.4:443')
    store.create('email', 'a@x.com')
    c = _cliente_with(store, monkeypatch)
    d = c.get('/api/v2/inventory').get_json()
    assert d['total_activos'] == 3
    assert set(d['inventario']) == {'domain', 'ip', 'port'}


def test_discovery_changes_via_monitor():
    from core.monitor import snapshot, diff
    store = Store()
    d = store.create('domain', 'x.com', properties={'cert_expires': '2027'})
    before = snapshot(store)
    store.create('subdomain', 'nuevo.x.com')
    store.create('port', '1.2.3.4:22')
    d.properties['cert_expires'] = '2020'
    changes = diff(before, snapshot(store))
    valores = {e['value'] for e in changes.new_entities}
    assert {'nuevo.x.com', '1.2.3.4:22'} <= valores
    assert any(c['field'] == 'cert_expires' for c in changes.prop_changes)


def test_infra_shared():
    from core.correlacion import correlate
    store = Store()
    store.create('domain', 'a.com', properties={'favicon_hash': '123456'})
    store.create('domain', 'b.com', properties={'favicon_hash': '123456'})
    store.create('domain', 'c.com', properties={'favicon_hash': '999'})
    r = [x for x in correlate(store) if x.rule == 'shared-infra']
    assert len(r) == 1 and len(r[0].entities) == 2


def test_infra_shared_without_group():
    from core.correlacion import correlate
    store = Store()
    store.create('domain', 'solo.com', properties={'favicon_hash': '111'})
    assert not [x for x in correlate(store) if x.rule == 'shared-infra']


def test_cve_lookup_tech(monkeypatch):
    resp = {'vulnerabilities': [
        {'cve': {'id': 'CVE-2021-1234',
                 'configurations': [{'nodes': [{'cpeMatch': [{'criteria': 'cpe:2.3:a:nginx:nginx:1.0'}]}]}]}},
        {'cve': {'id': 'CVE-2021-9999',
                 'configurations': [{'nodes': [{'cpeMatch': [{'criteria': 'cpe:2.3:a:apache:httpd:2.4'}]}]}]}},
    ]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=resp))
    store = Store()
    prod = run_by_name('cve_lookup', store.create('tech', 'nginx'), store)
    cids = {x.value for x in prod if x.type == 'cve'}
    assert cids == {'CVE-2021-1234'}


def test_score_exposure():
    from core.correlacion import exposure_score
    assert exposure_score({}, 0) == 0
    assert exposure_score({'subdomain': 10, 'port': 3}, 40) == 36
    assert exposure_score({'subdomain': 999}, 100) == 100


def test_exposure_endpoint(monkeypatch):
    store = Store()
    for i in range(5):
        store.create('subdomain', f's{i}.x.com')
    c = _cliente_with(store, monkeypatch)
    d = c.get('/api/v2/exposure').get_json()
    assert d['surface']['subdomain'] == 5 and 0 <= d['exposicion'] <= 100


def test_shadow_it():
    from core.correlacion import correlate
    store = Store()
    store.create('bucket', 'acme-backups').tag('public')
    store.create('subdomain', 'viejo.acme.com', properties={'http_status': 503})
    store.create('subdomain', 'vivo.acme.com', properties={'http_status': 200})
    r = [x for x in correlate(store) if x.rule == 'shadow-it']
    sev = {x.severity for x in r}
    assert len(r) == 2 and sev == {'high', 'medium'}


def test_diff_history(tmp_path):
    from core.workspaces import Manager
    g = Manager(str(tmp_path))
    g.create('caso')
    store = Store()
    store.create('subdomain', 'a.x.com')
    g.save('caso', store)
    sid = g.snapshot('caso')
    store.create('subdomain', 'b.x.com')
    g.save('caso', store)
    viejo = g.load_snapshot('caso', sid)
    assert len(viejo) == 1
    nuevos = {e.id for e in g.load('caso').entities} - {e.id for e in viejo.entities}
    assert len(nuevos) == 1
