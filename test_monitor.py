"""Tests for continuous monitoring (F7 step 95).

Run:  ../.venv/bin/python -m pytest test_monitor.py -q
"""
from core.modelo import Store
from core.monitor import snapshot, diff, Monitor


def test_diff_detects_entidad_nueva():
    store = Store()
    store.create('domain', 'target.com')
    before = snapshot(store)
    store.create('subdomain', 'nuevo.target.com')      # a subdomain appeared
    changes = diff(before, snapshot(store))
    assert changes.has_changes()
    assert len(changes.new_entities) == 1
    assert changes.new_entities[0]['value'] == 'nuevo.target.com'


def test_diff_detects_new_relation():
    store = Store()
    d = store.create('domain', 'target.com')
    ip = store.create('ip', '1.2.3.4')
    before = snapshot(store)
    store.relate(d.id, ip.id, 'resuelve')
    changes = diff(before, snapshot(store))
    assert len(changes.new_relations) == 1


def test_diff_detects_change_propiedad():
    store = Store()
    d = store.create('domain', 'target.com', properties={'cert_expires': '2027'})
    before = snapshot(store)
    d.properties['cert_expires'] = '2020'              # the cert changed (expired)
    changes = diff(before, snapshot(store))
    assert len(changes.prop_changes) == 1
    c = changes.prop_changes[0]
    assert c['field'] == 'cert_expires' and c['before'] == '2027' and c['now'] == '2020'


def test_diff_detects_tag_nuevo():
    store = Store()
    s = store.create('subdomain', 's.target.com')
    before = snapshot(store)
    s.tag('takeover')                            # became vulnerable
    changes = diff(before, snapshot(store))
    assert any(c['field'] == 'tag' and c['now'] == 'takeover' for c in changes.prop_changes)


def test_diff_without_changes():
    store = Store()
    store.create('domain', 'target.com')
    snap = snapshot(store)
    assert not diff(snap, snapshot(store)).has_changes()


def test_monitor_cycle_alert_change():
    store = Store()
    store.create('domain', 'target.com')
    disparos = []
    def refrescar():                                   # simulates a re-scan with news
        store.create('subdomain', 'nuevo.target.com')
    m = Monitor(lambda: snapshot(store), refrescar,
                on_alerta=lambda c: disparos.append(c), interval=999)
    changes = m.cycle()
    assert changes.has_changes()
    assert len(m.alerts) == 1
    assert len(disparos) == 1                          # the callback (future ntfy) was called
    assert 'nuevo.target.com' in m.alerts[0]['summary']


def test_monitor_cycle_without_changes_no_alert():
    store = Store()
    store.create('domain', 'target.com')
    m = Monitor(lambda: snapshot(store), lambda: None, interval=999)
    m.cycle()
    assert m.alerts == []


def test_monitor_refresh_fails_no_kill_cycle():
    store = Store()
    store.create('domain', 'target.com')
    def refrescar():
        raise RuntimeError('network down')
    m = Monitor(lambda: snapshot(store), refrescar, interval=999)
    m.cycle()                                          # must not raise
    assert m.alerts == []                             # no real changes
