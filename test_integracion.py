"""Tests de integración: el modelo/motor DENTRO de la app real (F2).

Verifican que la integración no rompió nada y que los endpoints /api/v2/*
funcionan. No dependen de la red (no ejecutan dns_a/crtsh de verdad).

Correr:  ../.venv/bin/python -m pytest test_integracion.py -q
"""
import obsidian_web as ob
from core.transforms import REGISTRO


def _client():
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    return c


def test_transforms_reales_registrados():
    nombres = {t.nombre for t in REGISTRO.todos()}
    assert {'dns_a', 'ptr', 'crtsh', 'geo_ip', 'github_usuario', 'puertos', 'dns_mx',
            'dns_ns', 'email_breaches', 'email_spoofable', 'rdap', 'greynoise',
            'dns_txt', 'ssl', 'subdominios_ht', 'http_probe', 'http_probe_sub',
            'screenshot', 'nuclei', 'breaches_xon', 'stealer_hudsonrock',
            'reputacion_ip', 'abuseipdb', 'wallet_balance', 'ip_blocklist', 'ct_certspotter', 'tech', 'cve_lookup', 'dorks'} <= nombres


def test_transforms_aplicables_por_tipo():
    ip = {t.nombre for t in REGISTRO.aplicables('ip')}
    assert {'ptr', 'geo_ip', 'puertos'} <= ip
    dominio = {t.nombre for t in REGISTRO.aplicables('dominio')}
    assert {'dns_a', 'crtsh', 'dns_mx', 'dns_ns'} <= dominio
    usuario = {t.nombre for t in REGISTRO.aplicables('usuario')}
    assert 'github_usuario' in usuario


def test_endpoints_viejos_intactos():
    c = _client()
    assert c.get('/').status_code == 200
    assert c.get('/api/status').status_code == 200


def test_v2_transforms_aplicables():
    c = _client()
    r = c.get('/api/v2/transforms/dominio')
    assert r.status_code == 200
    nombres = [t['nombre'] for t in r.get_json()['transforms']]
    assert 'dns_a' in nombres and 'crtsh' in nombres
    # ptr aplica a ip, no a dominio
    assert 'ptr' not in nombres


def test_v2_run_rechaza_arg_injection():
    c = _client()
    r = c.post('/api/v2/run', json={'tipo': 'ip', 'valor': '-oG/tmp/x', 'transform': 'ptr'})
    assert r.status_code == 400


def test_v2_run_tipo_invalido():
    c = _client()
    r = c.post('/api/v2/run', json={'tipo': 'inventado', 'valor': 'x', 'transform': 'ptr'})
    assert r.status_code == 400


def test_v2_run_transform_inexistente():
    c = _client()
    r = c.post('/api/v2/run', json={'tipo': 'dominio', 'valor': 'example.com', 'transform': 'noexiste'})
    assert r.status_code == 400


def test_v2_grafo_migrar_vacio():
    c = _client()
    r = c.get('/api/v2/grafo?migrar=1')
    assert r.status_code == 200
    assert r.get_json() == {'entidades': [], 'relaciones': []}


def test_auth_protege_v2():
    # sin sesión, /api/v2 debe pedir auth (no filtrar)
    c = ob.app.test_client()
    r = c.get('/api/v2/transforms/dominio')
    assert r.status_code == 401


def test_workspaces_flujo(tmp_path):
    """CRUD + persistencia de workspaces vía endpoints (F3), aislado en tmp."""
    from core.workspaces import Gestor
    prev_g, prev_ws, prev_a = ob._gestor, ob._ws_activo, ob._almacen
    ob._gestor = Gestor(str(tmp_path))
    ob._ws_activo = None
    ob._almacen = ob.Almacen()
    try:
        c = _client()
        # crear -> queda activo
        r = c.post('/api/v2/workspaces', json={'nombre': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['activo'] == 'caso demo'
        # listar
        j = c.get('/api/v2/workspaces').get_json()
        assert 'caso demo' in j['workspaces'] and j['activo'] == 'caso demo'
        # simular datos guardados y abrir en limpio
        ob._almacen.crear('ip', '8.8.8.8')
        ob._gestor.guardar('caso demo', ob._almacen)
        ob._almacen = ob.Almacen()
        r = c.post('/api/v2/workspaces/abrir', json={'nombre': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['total_entidades'] == 1
        # borrar -> sin activo
        r = c.delete('/api/v2/workspaces', json={'nombre': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['activo'] is None
        assert c.get('/api/v2/workspaces').get_json()['workspaces'] == []
    finally:
        ob._gestor, ob._ws_activo, ob._almacen = prev_g, prev_ws, prev_a


def test_guard_recuerda_destino():
    # sin sesión, ir a /v2 redirige a /login Y guarda el destino en la sesión,
    # para volver ahí tras loguear (arregla el rebote a la página vieja)
    c = ob.app.test_client()
    r = c.get('/v2')
    assert r.status_code == 302 and '/login' in r.headers.get('Location', '')
    with c.session_transaction() as s:
        assert s.get('next') == '/v2'
