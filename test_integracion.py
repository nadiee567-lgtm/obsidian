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
    assert {'dns_a', 'ptr', 'crtsh', 'geo_ip', 'github_usuario'} <= nombres


def test_transforms_aplicables_por_tipo():
    ip = {t.nombre for t in REGISTRO.aplicables('ip')}
    assert {'ptr', 'geo_ip'} <= ip
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
