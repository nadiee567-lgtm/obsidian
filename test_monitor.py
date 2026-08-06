"""Tests for continuous monitoring (F7 step 95).

Run:  ../.venv/bin/python -m pytest test_monitor.py -q
"""
from core.modelo import Store
from core.monitor import snapshot, diff, Monitor


def test_diff_detecta_entidad_nueva():
    alm = Store()
    alm.create('domain', 'objetivo.com')
    antes = snapshot(alm)
    alm.create('subdomain', 'nuevo.objetivo.com')      # a subdomain appeared
    cambios = diff(antes, snapshot(alm))
    assert cambios.hay()
    assert len(cambios.nuevas_entidades) == 1
    assert cambios.nuevas_entidades[0]['value'] == 'nuevo.objetivo.com'


def test_diff_detecta_relacion_nueva():
    alm = Store()
    d = alm.create('domain', 'objetivo.com')
    ip = alm.create('ip', '1.2.3.4')
    antes = snapshot(alm)
    alm.relate(d.id, ip.id, 'resuelve')
    cambios = diff(antes, snapshot(alm))
    assert len(cambios.nuevas_relaciones) == 1


def test_diff_detecta_cambio_de_propiedad():
    alm = Store()
    d = alm.create('domain', 'objetivo.com', properties={'cert_expira': '2027'})
    antes = snapshot(alm)
    d.properties['cert_expira'] = '2020'              # the cert changed (expired)
    cambios = diff(antes, snapshot(alm))
    assert len(cambios.cambios_prop) == 1
    c = cambios.cambios_prop[0]
    assert c['campo'] == 'cert_expira' and c['antes'] == '2027' and c['ahora'] == '2020'


def test_diff_detecta_tag_nuevo():
    alm = Store()
    s = alm.create('subdomain', 's.objetivo.com')
    antes = snapshot(alm)
    s.tag('takeover')                            # became vulnerable
    cambios = diff(antes, snapshot(alm))
    assert any(c['campo'] == 'tag' and c['ahora'] == 'takeover' for c in cambios.cambios_prop)


def test_diff_sin_cambios():
    alm = Store()
    alm.create('domain', 'objetivo.com')
    snap = snapshot(alm)
    assert not diff(snap, snapshot(alm)).hay()


def test_monitor_ciclo_alerta_en_cambio():
    alm = Store()
    alm.create('domain', 'objetivo.com')
    disparos = []
    def refrescar():                                   # simulates a re-scan with news
        alm.create('subdomain', 'nuevo.objetivo.com')
    m = Monitor(lambda: snapshot(alm), refrescar,
                on_alerta=lambda c: disparos.append(c), intervalo=999)
    cambios = m.ciclo()
    assert cambios.hay()
    assert len(m.alertas) == 1
    assert len(disparos) == 1                          # the callback (future ntfy) was called
    assert 'nuevo.objetivo.com' in m.alertas[0]['resumen']


def test_monitor_ciclo_sin_cambios_no_alerta():
    alm = Store()
    alm.create('domain', 'objetivo.com')
    m = Monitor(lambda: snapshot(alm), lambda: None, intervalo=999)
    m.ciclo()
    assert m.alertas == []


def test_monitor_refrescar_que_falla_no_tumba_el_ciclo():
    alm = Store()
    alm.create('domain', 'objetivo.com')
    def refrescar():
        raise RuntimeError('network down')
    m = Monitor(lambda: snapshot(alm), refrescar, intervalo=999)
    m.ciclo()                                          # must not raise
    assert m.alertas == []                             # no real changes
