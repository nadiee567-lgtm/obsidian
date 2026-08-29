"""Tests for F13 -- the tool's OPSEC.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_opsec.py -q
"""


def test_persona_manager(tmp_path):
    from core.personas import PersonaManager
    g = PersonaManager(str(tmp_path / 'p.json'))
    g.create('juan_investigador', {'email': 'juan@proton.me', 'user': 'juanx'})
    assert 'juan_investigador' in g.list_ws()
    p = g.get('juan_investigador')
    assert p['email'] == 'juan@proton.me' and 'created' in p
    assert g.delete('juan_investigador') is True and g.list_ws() == []
    assert g.delete('no_existe') is False


def test_mode_anonymous_toggle():
    import obsidian_web as ob
    try:
        ob._set_anonimo(True)
        assert ob.SESSION.proxies.get('https', '').startswith('socks5h') and ob._OPSEC['anonimo']
        ob._set_anonimo(False)
        assert ob.SESSION.proxies == {} and not ob._OPSEC['anonimo']
    finally:
        ob._set_anonimo(False)


def test_rotation_proxies():
    import obsidian_web as ob
    try:
        ob._PROXIES['pool'] = ['http://p1:8080', 'http://p2:8080']
        ob._PROXIES['i'] = 0
        p1, p2, p3 = ob._rotate_proxy(), ob._rotate_proxy(), ob._rotate_proxy()
        assert (p1, p2, p3) == ('http://p1:8080', 'http://p2:8080', 'http://p1:8080')
        assert ob.SESSION.proxies['https'] == 'http://p1:8080'
    finally:
        ob._PROXIES['pool'] = []
        ob.SESSION.proxies = {}


def test_hygiene_request():
    import obsidian_web as ob
    prev = ob.SESSION.headers.get('User-Agent')
    try:
        ob._OPSEC_HIGIENE['on'] = True
        ob._request_hygiene()
        assert ob.SESSION.headers['User-Agent'] in ob._USER_AGENTS
    finally:
        ob._OPSEC_HIGIENE['on'] = False
        if prev:
            ob.SESSION.headers['User-Agent'] = prev


def test_jitter():
    import obsidian_web as ob
    assert ob._jitter() == 0.0
    try:
        ob._OPSEC_JITTER['min'] = 0.01
        ob._OPSEC_JITTER['max'] = 0.03
        d = ob._jitter()
        assert 0.01 <= d <= 0.03
    finally:
        ob._OPSEC_JITTER['min'] = 0.0
        ob._OPSEC_JITTER['max'] = 0.0


def test_profile_opsec_per_workspace(tmp_path, monkeypatch):
    import json
    import obsidian_web as ob
    pf = tmp_path / 'op.json'
    pf.write_text(json.dumps({'caso1': {'higiene': True, 'jitter_min': 0.01,
                                        'jitter_max': 0.02, 'proxies': ['http://p:8080']}}))
    monkeypatch.setattr(ob, '_OPSEC_PROFILES', str(pf))
    try:
        ob._apply_opsec_profile('caso1')
        assert ob._OPSEC_HIGIENE['on'] is True
        assert ob._OPSEC_JITTER['max'] == 0.02
        assert ob._PROXIES['pool'] == ['http://p:8080']
    finally:
        ob._OPSEC_HIGIENE['on'] = False
        ob._OPSEC_JITTER['min'] = ob._OPSEC_JITTER['max'] = 0.0
        ob._PROXIES['pool'] = []
        ob.SESSION.proxies = {}


def test_evaluar_fuga():
    import obsidian_web as ob
    assert ob._evaluate_leak(True, '1.2.3.4', '1.2.3.4') is True
    assert ob._evaluate_leak(True, '9.9.9.9', '1.2.3.4') is False
    assert ob._evaluate_leak(False, '1.2.3.4', '1.2.3.4') is False


def test_key_rotativa(monkeypatch):
    import obsidian_web as ob
    ob._KEY_ROT.clear()
    monkeypatch.setattr(ob._boveda, 'get', lambda s: 'k1|k2|k3')
    assert [ob._rotating_key('shodan') for _ in range(4)] == ['k1', 'k2', 'k3', 'k1']
    monkeypatch.setattr(ob._boveda, 'get', lambda s: 'solo')
    assert ob._rotating_key('x') == 'solo'
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    assert ob._rotating_key('x') is None


def test_record_footprint():
    import obsidian_web as ob
    ob._FOOTPRINT.clear()
    ob._OPSEC['anonimo'] = False
    ob._PROXIES['pool'] = []
    ob._record_footprint('crtsh', 'domain', 'x.com')
    assert ob._FOOTPRINT[0]['transform'] == 'crtsh' and ob._FOOTPRINT[0]['anonimo'] is False
    assert ob._FOOTPRINT[0]['target'] == 'domain:x.com'
