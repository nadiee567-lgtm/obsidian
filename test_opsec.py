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


# ── 153: ruteo por Tor/SOCKS5 (modo anónimo) ─────────────────────────────────
def test_modo_anonimo_toggle():
    import obsidian_web as ob
    try:
        ob._set_anonimo(True)
        assert ob.SESSION.proxies.get('https', '').startswith('socks5h') and ob._OPSEC['anonimo']
        ob._set_anonimo(False)
        assert ob.SESSION.proxies == {} and not ob._OPSEC['anonimo']
    finally:
        ob._set_anonimo(False)                       # no dejar el proxy puesto


# ── 154: rotación de proxies ─────────────────────────────────────────────────
def test_rotacion_proxies():
    import obsidian_web as ob
    try:
        ob._PROXIES['pool'] = ['http://p1:8080', 'http://p2:8080']
        ob._PROXIES['i'] = 0
        p1, p2, p3 = ob._rotar_proxy(), ob._rotar_proxy(), ob._rotar_proxy()
        assert (p1, p2, p3) == ('http://p1:8080', 'http://p2:8080', 'http://p1:8080')  # round-robin
        assert ob.SESSION.proxies['https'] == 'http://p1:8080'
    finally:
        ob._PROXIES['pool'] = []
        ob.SESSION.proxies = {}
