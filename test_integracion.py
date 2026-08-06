"""Integration tests: the model/engine INSIDE the real app (F2).

They verify the integration broke nothing and that the /api/v2/* endpoints work.
They don't depend on the network (they don't really run dns_a/crtsh).

Run:  ../.venv/bin/python -m pytest test_integracion.py -q
"""
import obsidian_web as ob
from core.transforms import REGISTRO


def _client():
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    return c


def test_transforms_reales_registrados():
    nombres = {t.nombre for t in REGISTRO.all_transforms()}
    assert {'dns_a', 'ptr', 'crtsh', 'geo_ip', 'github_usuario', 'puertos', 'dns_mx',
            'dns_ns', 'email_breaches', 'email_spoofable', 'rdap', 'greynoise',
            'dns_txt', 'ssl', 'subdominios_ht', 'http_probe', 'http_probe_sub',
            'screenshot', 'nuclei', 'breaches_xon', 'stealer_hudsonrock',
            'reputacion_ip', 'abuseipdb', 'wallet_balance', 'ip_blocklist', 'ct_certspotter', 'tech', 'cve_lookup', 'dorks', 'pastes_github', 'sherlock', 'metadata', 'wayback', 'reverse_whois', 'favicon_hash'} <= nombres


def test_transforms_aplicables_por_tipo():
    ip = {t.nombre for t in REGISTRO.applicable('ip')}
    assert {'ptr', 'geo_ip', 'puertos'} <= ip
    dominio = {t.nombre for t in REGISTRO.applicable('domain')}
    assert {'dns_a', 'crtsh', 'dns_mx', 'dns_ns'} <= dominio
    usuario = {t.nombre for t in REGISTRO.applicable('user')}
    assert 'github_usuario' in usuario


def test_endpoints_viejos_intactos():
    c = _client()
    assert c.get('/').status_code == 200
    assert c.get('/api/status').status_code == 200


def test_v2_transforms_aplicables():
    c = _client()
    r = c.get('/api/v2/transforms/domain')
    assert r.status_code == 200
    nombres = [t['nombre'] for t in r.get_json()['transforms']]
    assert 'dns_a' in nombres and 'crtsh' in nombres
    # ptr applies to ip, not to domain
    assert 'ptr' not in nombres


def test_v2_run_rechaza_arg_injection():
    c = _client()
    r = c.post('/api/v2/run', json={'type': 'ip', 'value': '-oG/tmp/x', 'transform': 'ptr'})
    assert r.status_code == 400


def test_v2_run_tipo_invalido():
    c = _client()
    r = c.post('/api/v2/run', json={'type': 'inventado', 'value': 'x', 'transform': 'ptr'})
    assert r.status_code == 400


def test_v2_run_transform_inexistente():
    c = _client()
    r = c.post('/api/v2/run', json={'type': 'domain', 'value': 'example.com', 'transform': 'noexiste'})
    assert r.status_code == 400


def test_v2_grafo_migrar_vacio():
    c = _client()
    r = c.get('/api/v2/grafo?migrar=1')
    assert r.status_code == 200
    assert r.get_json() == {'entities': [], 'relations': []}


def test_auth_protege_v2():
    # without a session, /api/v2 must require auth (no leaking)
    c = ob.app.test_client()
    r = c.get('/api/v2/transforms/domain')
    assert r.status_code == 401


def test_workspaces_flujo(tmp_path):
    """Workspace CRUD + persistence via endpoints (F3), isolated in tmp."""
    from core.workspaces import Manager
    prev_g, prev_ws, prev_a = ob._gestor, ob._ws_activo, ob._almacen
    ob._gestor = Manager(str(tmp_path))
    ob._ws_activo = None
    ob._almacen = ob.Store()
    try:
        c = _client()
        # create -> becomes active
        r = c.post('/api/v2/workspaces', json={'nombre': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['activo'] == 'caso demo'
        # list
        j = c.get('/api/v2/workspaces').get_json()
        assert 'caso demo' in j['workspaces'] and j['activo'] == 'caso demo'
        # simulate saved data and open fresh
        ob._almacen.create('ip', '8.8.8.8')
        ob._gestor.guardar('caso demo', ob._almacen)
        ob._almacen = ob.Store()
        r = c.post('/api/v2/workspaces/abrir', json={'nombre': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['total_entities'] == 1
        # delete -> no active
        r = c.delete('/api/v2/workspaces', json={'nombre': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['activo'] is None
        assert c.get('/api/v2/workspaces').get_json()['workspaces'] == []
    finally:
        ob._gestor, ob._ws_activo, ob._almacen = prev_g, prev_ws, prev_a


def test_guard_recuerda_destino():
    # without a session, going to /v2 redirects to /login AND saves the destination
    # in the session, to return there after login (fixes the bounce to the old page)
    c = ob.app.test_client()
    r = c.get('/v2')
    assert r.status_code == 302 and '/login' in r.headers.get('Location', '')
    with c.session_transaction() as s:
        assert s.get('next') == '/v2'
