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
