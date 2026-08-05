"""Tests de F13 — OPSEC de la herramienta.

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_opsec.py -q
"""


# ── 152: bóveda de sock puppets ──────────────────────────────────────────────
def test_gestor_personas(tmp_path):
    from core.personas import GestorPersonas
    g = GestorPersonas(str(tmp_path / 'p.json'))
    g.crear('juan_investigador', {'email': 'juan@proton.me', 'usuario': 'juanx'})
    assert 'juan_investigador' in g.listar()
    p = g.obtener('juan_investigador')
    assert p['email'] == 'juan@proton.me' and 'creada' in p
    assert g.borrar('juan_investigador') is True and g.listar() == []
    assert g.borrar('no_existe') is False
