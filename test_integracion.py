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
    nombres = {t.name for t in REGISTRO.all_transforms()}
    assert {'dns_a', 'ptr', 'crtsh', 'geo_ip', 'github_user', 'ports', 'dns_mx',
            'dns_ns', 'email_breaches', 'email_spoofable', 'rdap', 'greynoise',
            'dns_txt', 'ssl', 'subdomains_ht', 'http_probe', 'http_probe_sub',
            'screenshot', 'nuclei', 'breaches_xon', 'stealer_hudsonrock',
            'ip_reputation', 'abuseipdb', 'wallet_balance', 'ip_blocklist', 'ct_certspotter', 'tech', 'cve_lookup', 'dorks', 'pastes_github', 'sherlock', 'metadata', 'wayback', 'reverse_whois', 'favicon_hash'} <= nombres


def test_transforms_applicable_per_type():
    ip = {t.name for t in REGISTRO.applicable('ip')}
    assert {'ptr', 'geo_ip', 'ports'} <= ip
    domain = {t.name for t in REGISTRO.applicable('domain')}
    assert {'dns_a', 'crtsh', 'dns_mx', 'dns_ns'} <= domain
    username = {t.name for t in REGISTRO.applicable('user')}
    assert 'github_user' in username


def test_endpoints_old_intact():
    c = _client()
    # / now redirects to the interactive graph (v2); the classic UI moved to /classic
    r = c.get('/')
    assert r.status_code == 302 and r.headers['Location'].endswith('/v2')
    assert c.get('/classic').status_code == 200
    assert c.get('/api/status').status_code == 200


def test_v2_export_obsidian_zip():
    import io, zipfile
    from core.modelo import Store
    prev = ob._store
    try:
        ob._store = Store()
        d = ob._store.create('domain', 'example.com')
        ip = ob._store.create('ip', '203.0.113.10')
        ob._store.relate(d, ip, 'resolves')
        r = _client().get('/api/v2/export/obsidian')
        assert r.status_code == 200 and r.mimetype == 'application/zip'
        z = zipfile.ZipFile(io.BytesIO(r.data))
        names = z.namelist()
        assert any(n.endswith('index.md') for n in names)
        dom = z.read(next(n for n in names if n.endswith('example.com.md'))).decode()
        assert '[[203.0.113.10]]' in dom
    finally:
        ob._store = prev


def test_v2_terminal_runs_command():
    r = _client().post('/api/v2/terminal', json={'cmd': 'echo terminaltest'})
    assert r.status_code == 200
    assert 'terminaltest' in r.get_json()['output']


def test_v2_terminal_cd_persists():
    import tempfile, os
    tmp = tempfile.gettempdir()
    d = _client().post('/api/v2/terminal', json={'cmd': f'cd {tmp}'}).get_json()
    assert os.path.realpath(d['cwd']) == os.path.realpath(tmp)


def test_v2_terminal_enabled_on_localhost():
    assert _client().get('/api/v2/terminal').get_json().get('enabled') is True


def test_v2_playbooks_list():
    names = {p['name'] for p in _client().get('/api/v2/playbooks').get_json()['playbooks']}
    assert {'external_recon', 'ip_recon', 'attack_surface'} <= names


def test_v2_playbook_unknown():
    assert _client().post('/api/v2/playbook', json={'playbook': 'nope', 'value': 'x'}).status_code == 404


def test_v2_playbook_malformed_value():
    r = _client().post('/api/v2/playbook', json={'playbook': 'external_recon', 'value': 'not a domain'})
    assert r.status_code == 400


def test_v2_playbook_runs(monkeypatch):
    from core.transforms import REGISTRO
    from core.modelo import Store
    monkeypatch.setattr(REGISTRO, 'by_name', lambda n: None)   # skip every step -> no network
    ob._store = Store()
    d = _client().post('/api/v2/playbook', json={'playbook': 'ip_recon', 'value': '1.2.3.4'}).get_json()
    assert d['playbook'] == 'ip_recon' and isinstance(d['produced'], int)
    assert d['total_entities'] >= 1   # the seed was added


def test_v2_import_bulk():
    from core.modelo import Store
    ob._store = Store()
    d = _client().post('/api/v2/import',
                       json={'text': '1.2.3.4\nexample.com\nfoo@bar.com'}).get_json()
    assert d['added'] == 3
    assert {'ip', 'domain', 'email'} <= {e.type for e in ob._store.entities}


def test_v2_repeater_bad_method():
    r = _client().post('/api/v2/repeater', json={'method': 'FOO', 'url': 'https://x.com'})
    assert r.status_code == 400


def test_v2_repeater_blocks_internal(monkeypatch):
    monkeypatch.setattr(ob, '_public_url', lambda u: False)
    r = _client().post('/api/v2/repeater', json={'method': 'GET', 'url': 'http://127.0.0.1/'})
    assert r.status_code == 400


def test_v2_repeater_sends(monkeypatch):
    monkeypatch.setattr(ob, '_public_url', lambda u: True)

    class _R:
        status_code = 200
        reason = 'OK'
        headers = {'Content-Type': 'text/plain'}
        content = b'hello'
        text = 'hello'
    monkeypatch.setattr(ob.SESSION, 'request', lambda *a, **k: _R())
    d = _client().post('/api/v2/repeater',
                       json={'method': 'GET', 'url': 'https://example.com',
                             'headers': 'X-Test: 1'}).get_json()
    assert d['status'] == 200 and d['body'] == 'hello' and d['size'] == 5


def test_v2_transforms_applicable():
    c = _client()
    r = c.get('/api/v2/transforms/domain')
    assert r.status_code == 200
    nombres = [t['name'] for t in r.get_json()['transforms']]
    assert 'dns_a' in nombres and 'crtsh' in nombres
    assert 'ptr' not in nombres


def test_v2_run_rechaza_arg_injection():
    c = _client()
    r = c.post('/api/v2/run', json={'type': 'ip', 'value': '-oG/tmp/x', 'transform': 'ptr'})
    assert r.status_code == 400


def test_v2_run_type_invalid():
    c = _client()
    r = c.post('/api/v2/run', json={'type': 'inventado', 'value': 'x', 'transform': 'ptr'})
    assert r.status_code == 400


def test_v2_run_transform_inexistente():
    c = _client()
    r = c.post('/api/v2/run', json={'type': 'domain', 'value': 'example.com', 'transform': 'noexiste'})
    assert r.status_code == 400


def test_v2_graph_migrate_empty():
    c = _client()
    r = c.get('/api/v2/grafo?migrar=1')
    assert r.status_code == 200
    assert r.get_json() == {'entities': [], 'relations': []}


def test_auth_protege_v2():
    c = ob.app.test_client()
    r = c.get('/api/v2/transforms/domain')
    assert r.status_code == 401


def test_workspaces_flujo(tmp_path):
    """Workspace CRUD + persistence via endpoints (F3), isolated in tmp."""
    from core.workspaces import Manager
    prev_g, prev_ws, prev_a = ob._gestor, ob._ws_activo, ob._store
    ob._gestor = Manager(str(tmp_path))
    ob._ws_activo = None
    ob._store = ob.Store()
    try:
        c = _client()
        r = c.post('/api/v2/workspaces', json={'name': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['active'] == 'caso demo'
        j = c.get('/api/v2/workspaces').get_json()
        assert 'caso demo' in j['workspaces'] and j['active'] == 'caso demo'
        ob._store.create('ip', '8.8.8.8')
        ob._gestor.save('caso demo', ob._store)
        ob._store = ob.Store()
        r = c.post('/api/v2/workspaces/open', json={'name': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['total_entities'] == 1
        r = c.delete('/api/v2/workspaces', json={'name': 'caso demo'})
        assert r.status_code == 200 and r.get_json()['active'] is None
        assert c.get('/api/v2/workspaces').get_json()['workspaces'] == []
    finally:
        ob._gestor, ob._ws_activo, ob._store = prev_g, prev_ws, prev_a


def test_guard_remembers_target():
    c = ob.app.test_client()
    r = c.get('/v2')
    assert r.status_code == 302 and '/login' in r.headers.get('Location', '')
    with c.session_transaction() as s:
        assert s.get('next') == '/v2'
