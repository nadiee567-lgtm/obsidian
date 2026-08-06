"""Tests for continuous monitoring (F7 step 95).

Run:  ../.venv/bin/python -m pytest test_monitor.py -q
"""
from core.modelo import Store
from core.monitor import snapshot, diff, Monitor


def test_diff_detecta_entidad_nueva():
    alm = Store()
    alm.create('domain', 'target.com')
    antes = snapshot(alm)
    alm.create('subdomain', 'nuevo.target.com')      # a subdomain appeared
    cambios = diff(antes, snapshot(alm))
    assert cambios.hay()
    assert len(cambios.nuevas_entidades) == 1
    assert cambios.nuevas_entidades[0]['value'] == 'nuevo.target.com'


def test_diff_detects_new_relation():
    alm = Store()
    d = alm.create('domain', 'target.com')
    ip = alm.create('ip', '1.2.3.4')
    antes = snapshot(alm)
    alm.relate(d.id, ip.id, 'resuelve')
    cambios = diff(antes, snapshot(alm))
    assert len(cambios.nuevas_relaciones) == 1


def test_diff_detecta_cambio_de_propiedad():
    alm = Store()
    d = alm.create('domain', 'target.com', properties={'cert_expires': '2027'})
    antes = snapshot(alm)
    d.properties['cert_expires'] = '2020'              # the cert changed (expired)
    cambios = diff(antes, snapshot(alm))
    assert len(cambios.cambios_prop) == 1
    c = cambios.cambios_prop[0]
    assert c['campo'] == 'cert_expires' and c['antes'] == '2027' and c['ahora'] == '2020'


def test_diff_detecta_tag_nuevo():
    alm = Store()
    s = alm.create('subdomain', 's.target.com')
    antes = snapshot(alm)
    s.tag('takeover')                            # became vulnerable
    cambios = diff(antes, snapshot(alm))
    assert any(c['campo'] == 'tag' and c['ahora'] == 'takeover' for c in cambios.cambios_prop)


def test_diff_sin_cambios():
    alm = Store()
    alm.create('domain', 'target.com')
    snap = snapshot(alm)
    assert not diff(snap, snapshot(alm)).hay()


def test_monitor_ciclo_alerta_en_cambio():
    alm = Store()
    alm.create('domain', 'target.com')
    disparos = []
    def refrescar():                                   # simulates a re-scan with news
        alm.create('subdomain', 'nuevo.target.com')
    m = Monitor(lambda: snapshot(alm), refrescar,
                on_alerta=lambda c: disparos.append(c), interval=999)
    cambios = m.cycle()
    assert cambios.hay()
    assert len(m.alerts) == 1
    assert len(disparos) == 1                          # the callback (future ntfy) was called
    assert 'nuevo.target.com' in m.alerts[0]['summary']


def test_monitor_ciclo_sin_cambios_no_alerta():
    alm = Store()
    alm.create('domain', 'target.com')
    m = Monitor(lambda: snapshot(alm), lambda: None, interval=999)
    m.cycle()
    assert m.alerts == []


def test_monitor_refrescar_que_falla_no_tumba_el_ciclo():
    alm = Store()
    alm.create('domain', 'target.com')
    def refrescar():
        raise RuntimeError('network down')
    m = Monitor(lambda: snapshot(alm), refrescar, interval=999)
    m.cycle()                                          # must not raise
    assert m.alerts == []                             # no real changes
