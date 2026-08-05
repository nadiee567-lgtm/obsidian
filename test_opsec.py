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


# ── 155: higiene de request (UA aleatorio) ───────────────────────────────────
def test_higiene_request():
    import obsidian_web as ob
    prev = ob.SESSION.headers.get('User-Agent')
    try:
        ob._OPSEC_HIGIENE['on'] = True
        ob._higiene_request()
        assert ob.SESSION.headers['User-Agent'] in ob._USER_AGENTS
    finally:
        ob._OPSEC_HIGIENE['on'] = False
        if prev:
            ob.SESSION.headers['User-Agent'] = prev


# ── 156: jitter / throttling ─────────────────────────────────────────────────
def test_jitter():
    import obsidian_web as ob
    assert ob._jitter() == 0.0                       # sin config, no espera
    try:
        ob._OPSEC_JITTER['min'] = 0.01
        ob._OPSEC_JITTER['max'] = 0.03
        d = ob._jitter()
        assert 0.01 <= d <= 0.03
    finally:
        ob._OPSEC_JITTER['min'] = 0.0
        ob._OPSEC_JITTER['max'] = 0.0


# ── 157: modo no-atribución (perfil OPSEC por workspace) ─────────────────────
def test_perfil_opsec_por_workspace(tmp_path, monkeypatch):
    import json
    import obsidian_web as ob
    pf = tmp_path / 'op.json'
    pf.write_text(json.dumps({'caso1': {'higiene': True, 'jitter_min': 0.01,
                                        'jitter_max': 0.02, 'proxies': ['http://p:8080']}}))
    monkeypatch.setattr(ob, '_OPSEC_PROFILES', str(pf))
    try:
        ob._aplicar_perfil_opsec('caso1')
        assert ob._OPSEC_HIGIENE['on'] is True
        assert ob._OPSEC_JITTER['max'] == 0.02
        assert ob._PROXIES['pool'] == ['http://p:8080']
    finally:
        ob._OPSEC_HIGIENE['on'] = False
        ob._OPSEC_JITTER['min'] = ob._OPSEC_JITTER['max'] = 0.0
        ob._PROXIES['pool'] = []
        ob.SESSION.proxies = {}


# ── 158: detección de fugas ──────────────────────────────────────────────────
def test_evaluar_fuga():
    import obsidian_web as ob
    assert ob._evaluar_fuga(True, '1.2.3.4', '1.2.3.4') is True     # anónimo pero misma IP = FUGA
    assert ob._evaluar_fuga(True, '9.9.9.9', '1.2.3.4') is False    # IP distinta = ok
    assert ob._evaluar_fuga(False, '1.2.3.4', '1.2.3.4') is False   # no anónimo = no aplica


# ── 159: rotación de API keys ────────────────────────────────────────────────
def test_key_rotativa(monkeypatch):
    import obsidian_web as ob
    ob._KEY_ROT.clear()
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'k1|k2|k3')
    assert [ob._key_rotativa('shodan') for _ in range(4)] == ['k1', 'k2', 'k3', 'k1']  # round-robin
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'solo')
    assert ob._key_rotativa('x') == 'solo'                # una sola: tal cual
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    assert ob._key_rotativa('x') is None


# ── 160: registro de tu propia huella ────────────────────────────────────────
def test_registrar_huella():
    import obsidian_web as ob
    ob._HUELLA.clear()
    ob._OPSEC['anonimo'] = False
    ob._PROXIES['pool'] = []
    ob._registrar_huella('crtsh', 'dominio', 'x.com')
    assert ob._HUELLA[0]['transform'] == 'crtsh' and ob._HUELLA[0]['anonimo'] is False
    assert ob._HUELLA[0]['objetivo'] == 'dominio:x.com'
