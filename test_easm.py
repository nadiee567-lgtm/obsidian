"""Tests de F12 — superficie de ataque continua (EASM).

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_easm.py -q
"""
import obsidian_web as ob
from core.modelo import Almacen


def _cliente_con(alm, monkeypatch):
    monkeypatch.setattr(ob, '_almacen', alm)
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    return c


# ── 144: inventario de activos ───────────────────────────────────────────────
def test_inventario(monkeypatch):
    alm = Almacen()
    alm.crear('dominio', 'x.com')
    alm.crear('ip', '1.2.3.4')
    alm.crear('puerto', '1.2.3.4:443')
    alm.crear('email', 'a@x.com')                # NO es activo internet-facing
    c = _cliente_con(alm, monkeypatch)
    d = c.get('/api/v2/inventario').get_json()
    assert d['total_activos'] == 3               # dominio+ip+puerto, no el email
    assert set(d['inventario']) == {'dominio', 'ip', 'puerto'}


# ── 145 + 146: descubrimiento continuo + detección de cambios (vía el monitor) ─
def test_descubrimiento_y_cambios_via_monitor():
    from core.monitor import snapshot, diff
    alm = Almacen()
    d = alm.crear('dominio', 'x.com', propiedades={'cert_expira': '2027'})
    antes = snapshot(alm)
    alm.crear('subdominio', 'nuevo.x.com')       # activo nuevo (145)
    alm.crear('puerto', '1.2.3.4:22')            # puerto nuevo (146)
    d.propiedades['cert_expira'] = '2020'        # cert cambió (146)
    cambios = diff(antes, snapshot(alm))
    valores = {e['valor'] for e in cambios.nuevas_entidades}
    assert {'nuevo.x.com', '1.2.3.4:22'} <= valores
    assert any(c['campo'] == 'cert_expira' for c in cambios.cambios_prop)
