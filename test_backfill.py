"""Tests del backfill de F2/F4 (módulos viejos migrados a transforms + reglas).

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_backfill.py -q
"""
import obsidian_web as ob
from core.modelo import Almacen
from core.transforms import ejecutar_por_nombre


def _correr(nombre, tipo, valor):
    alm = Almacen()
    e = alm.crear(tipo, valor)
    return ejecutar_por_nombre(nombre, e, alm), e, alm


# ── 33: teléfono ─────────────────────────────────────────────────────────────
def test_telefono_dorks_keyless():
    prod, _, _ = _correr('telefono_dorks', 'telefono', '+14155552671')
    dorks = {p.propiedades.get('dork') for p in prod if p.tipo == 'url'}
    assert dorks == {'truecaller', 'whitepages', 'mensajeria', 'general'}
    assert all(p.tipo == 'url' for p in prod)      # sin key: solo dorks, sin país
