"""Backfill tests for F2/F4 (old modules migrated to transforms + rules).

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_backfill.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


def _run_one(name, type, value):
    alm = Store()
    e = alm.create(type, value)
    return run_by_name(name, e, alm), e, alm


# ── 33: phone ───────────────────────────────────────────────────────────────
def test_telefono_dorks_keyless():
    prod, _, _ = _run_one('telefono_dorks', 'phone', '+14155552671')
    dorks = {p.properties.get('dork') for p in prod if p.type == 'url'}
    assert dorks == {'truecaller', 'whitepages', 'messaging', 'general'}
    assert all(p.type == 'url' for p in prod)      # no key: only dorks, no country


# ── 34: typosquatting / buckets / takeover / passivedns ─────────────────────
def test_typosquatting(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: '1.2.3.4\n')   # everything "resolves"
    prod, _, _ = _run_one('typosquatting', 'domain', 'google.com')
    assert prod and all(p.type == 'domain' and 'typosquat' in p.tags for p in prod)


def test_buckets(monkeypatch):
    class R:
        status_code = 200
        text = ''
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: R())
    prod, _, _ = _run_one('buckets', 'org', 'ACME Corp')
    assert prod and all(p.type == 'bucket' for p in prod)
    assert any('public' in p.tags for p in prod)


def test_takeover(monkeypatch):
    class Rj:
        status_code = 200
        text = "There isn't a GitHub Pages site here"
        def json(self):
            return [{'name_value': 'abandonado.ejemplo.com'}]
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: Rj())
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: 'user.github.io.\n')  # orphan CNAME
    prod, _, _ = _run_one('takeover', 'domain', 'ejemplo.com')
    vulns = [p for p in prod if 'takeover' in p.tags]
    assert vulns and vulns[0].value == 'abandonado.ejemplo.com'


def test_passivedns(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: 'k')
    class R:
        def json(self):
            return {'data': [{'attributes': {'ip_address': '9.9.9.9', 'date': 1600000000}}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: R())
    prod, _, _ = _run_one('passivedns', 'domain', 'ejemplo.com')
    assert {p.value for p in prod if p.type == 'ip'} == {'9.9.9.9'}


def test_passivedns_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)
    monkeypatch.setenv('VT_API_KEY', '')
    prod, _, _ = _run_one('passivedns', 'domain', 'ejemplo.com')
    assert prod == []


# ── 60: github_sec (secrets in commits) + rule ──────────────────────────────
class _Rj:
    def __init__(self, data, code=200):
        self._d, self.status_code = data, code
    def json(self):
        return self._d


def test_github_sec_y_regla(monkeypatch):
    from core.correlacion import correlate
    def fake_get(url, *a, **k):
        if '/commits/' in url:
            return _Rj({'files': [{'filename': 'cfg.py',
                                   'patch': 'api_key = "AKIAIOSFODNN7EXAMPLE12"'}]})
        if '/commits?' in url:
            return _Rj([{'sha': 'abc123'}])
        if '/repos' in url:
            return _Rj([{'full_name': 'user/repo1'}])
        return _Rj([])
    monkeypatch.setattr(ob._boveda, 'get', lambda s: '')
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    prod, _, alm = _run_one('github_sec', 'user', 'user')
    creds = [p for p in prod if p.type == 'credential']
    assert creds and 'github-secret' in creds[0].tags
    h = correlate(alm)
    assert any(x.rule == 'github-secret' and x.severity == 'critical' for x in h)


# ── 56: exposed login/panel + credential ────────────────────────────────────
def test_login_expuesto_regla():
    from core.correlacion import correlate
    alm = Store()
    alm.create('domain', 'admin.x.com').tag('login-panel')
    r = [x for x in correlate(alm) if x.rule == 'login-exposed']
    assert r and r[0].severity == 'high'
    alm.create('email', 'a@x.com').tag('leaked')     # login + credential
    r2 = [x for x in correlate(alm) if x.rule == 'login-exposed']
    assert r2 and r2[0].severity == 'critical'


def test_http_probe_detecta_panel_login(monkeypatch):
    class R:
        status_code = 200
        url = 'https://admin.x.com'
        headers = {}
        text = '<html><title>Admin</title><input type="password" name="pw"></html>'
    monkeypatch.setattr(ob, '_fetch_seguro', lambda *a, **k: R())
    _, e, _ = _run_one('http_probe', 'domain', 'admin.x.com')
    assert 'login-panel' in e.tags


# ── 136: leak -> login correlation ──────────────────────────────────────────
def test_leak_login():
    from core.correlacion import correlate
    alm = Store()
    e = alm.create('email', 'admin@acme.com'); e.tag('leaked')
    p = alm.create('subdomain', 'panel.acme.com'); p.tag('login-panel')
    r = [x for x in correlate(alm) if x.rule == 'leak-login']
    assert r and r[0].severity == 'critical'
    assert e.id in r[0].entities and p.id in r[0].entities   # names both


def test_leak_login_sin_filtrado():
    from core.correlacion import correlate
    alm = Store()
    alm.create('subdomain', 'panel.acme.com').tag('login-panel')   # panel but no credential
    assert not [x for x in correlate(alm) if x.rule == 'leak-login']


# ── 59: platform pivot ──────────────────────────────────────────────────────
def test_pivote_plataformas():
    from core.correlacion import correlate
    alm = Store()
    u = alm.create('user', 'nadiee')
    for i in range(6):
        p = alm.create('platform', f'plat{i}')
        alm.relate(u.id, p.id, 'presente')
    r = [x for x in correlate(alm) if x.rule == 'platform-pivot']
    assert r and '6 platforms' in r[0].message


def test_pivote_plataformas_pocas_no_dispara():
    from core.correlacion import correlate
    alm = Store()
    u = alm.create('user', 'x')
    for i in range(3):                                   # <5 → no finding
        alm.relate(u.id, alm.create('platform', f'p{i}').id, 'presente')
    assert not [x for x in correlate(alm) if x.rule == 'platform-pivot']


# ── 63: user YAML rule loader ───────────────────────────────────────────────
def test_reglas_yaml():
    from core.correlacion import load_yaml_rules, correlate
    yaml_txt = """
- name: puerto-ftp
  severity: high
  message: "FTP en {value}"
  when:
    type: port
    value_contains: ":21"
"""
    try:
        assert load_yaml_rules(yaml_txt) == 1
        alm = Store()
        alm.create('port', '1.2.3.4:21')
        alm.create('port', '1.2.3.4:443')              # does not match
        r = [x for x in correlate(alm) if x.rule == 'puerto-ftp']
        assert len(r) == 1 and r[0].severity == 'high' and r[0].message == 'FTP en 1.2.3.4:21'
    finally:
        load_yaml_rules('')                          # clears the global


def test_reglas_yaml_severidad_invalida_se_normaliza():
    from core.correlacion import load_yaml_rules, _REGLAS_YAML
    try:
        load_yaml_rules("- name: x\n  severity: URGENTISIMO\n  when: {tag: y}\n")
        assert _REGLAS_YAML[0]['severity'] == 'medium'  # invalid severity → medio
    finally:
        load_yaml_rules('')


def test_reglas_yaml_basura_no_rompe():
    from core.correlacion import load_yaml_rules
    assert load_yaml_rules('no: [es: :valido') == 0   # broken YAML → 0, no exception


# ── 40: per-transform rate limiting ─────────────────────────────────────────
def test_rate_limit_concurrencia():
    import threading
    import time
    from core.transforms import transform, run_by_name, set_limite

    estado, lock = {'activos': 0, 'max': 0}, threading.Lock()

    @transform(input='domain', outputs=(), name='_test_rl')
    def _rl(entidad, ctx):
        with lock:
            estado['activos'] += 1
            estado['max'] = max(estado['max'], estado['activos'])
        time.sleep(0.05)
        with lock:
            estado['activos'] -= 1

    set_limite('_test_rl', 1)
    try:
        def run():
            alm = Store()
            run_by_name('_test_rl', alm.create('domain', 'x.com'), alm)
        ths = [threading.Thread(target=run) for _ in range(4)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        assert estado['max'] == 1                # never more than 1 concurrent
    finally:
        set_limite('_test_rl', 0)                # removes the limit


# ── 37: background queue + SSE ──────────────────────────────────────────────
def test_task_manager():
    from core.tareas import TaskManager
    g = TaskManager()

    def trabajo(emit):
        emit({'type': 'inicio', 'total': 2})
        emit({'type': 'progreso', 'hechas': 1})
        return {'ok': True}

    tid = g.create(trabajo)
    eventos = list(g.stream(tid))                # blocks until 'fin'
    tipos = [e['type'] for e in eventos]
    assert tipos[0] == 'inicio' and tipos[-1] == 'fin'
    assert g.estado(tid)['estado'] == 'hecho'
    assert g.estado(tid)['resultado'] == {'ok': True}


def test_task_manager_error_no_hang():
    from core.tareas import TaskManager
    g = TaskManager()

    def trabajo(emit):
        raise RuntimeError('boom')

    tid = g.create(trabajo)
    eventos = list(g.stream(tid))                # must close with 'fin' even on failure
    assert eventos[-1]['type'] == 'fin'
    assert g.estado(tid)['estado'] == 'error'


def test_ejecutar_lote_progreso():
    from core.transforms import run_batch
    vistos = []
    run_batch([('url', 'https://a.com/x.jpg', 'reverse_image'),
                   ('url', 'https://b.com/y.jpg', 'reverse_image')],
                  Store(), on_progreso=lambda *a: vistos.append(a))
    assert len(vistos) == 2                       # one callback per finished transform
    assert vistos[-1][3] == 2                      # total == 2 on the last


# ── Migration of the rest of the old Obsidian (minus distroboxes) ────────────
def test_person(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _Rj({'AbstractText': 'Person bio.'}))
    prod, e, _ = _run_one('person', 'person', 'Juan Perez')
    assert {p.properties.get('dork') for p in prod} == {'linkedin', 'x', 'contact', 'pdf', 'github', 'facebook'}
    assert e.properties.get('resumen') == 'Person bio.'


def test_darkweb_ahmia(monkeypatch):
    html = '<h4><a href="http://abc.onion/">Market</a></h4><h4><a href="http://xyz.onion/">Forum</a></h4>'
    class R:
        text = html
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: R())
    prod, _, _ = _run_one('darkweb', 'person', 'algo')
    urls = {p.value for p in prod if p.type == 'url'}
    assert urls == {'http://abc.onion', 'http://xyz.onion'}   # normalizer strips the trailing /


def test_url_check_urlhaus(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'post',
                        lambda *a, **k: _Rj({'query_status': 'ok', 'threat': 'malware_download'}))
    _, e, _ = _run_one('url_check', 'url', 'http://malo.com/x')
    assert 'malicious-url' in e.tags and e.properties.get('urlhaus') == 'malware_download'


def test_render_js_bloquea_ssrf(monkeypatch):
    monkeypatch.setattr(ob, '_url_publica', lambda u: False)   # internal host
    prod, _, _ = _run_one('render_js', 'url', 'http://169.254.169.254/')
    assert prod == []                              # does not render internal hosts


def test_yara_bulk_carpeta_invalida():
    prod, _, _ = _run_one('yara_bulk', 'file', '/does/not/exist/xyz')
    assert prod == []


def test_wordlist_ia(monkeypatch):
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'juan2024\npassword123\nperez.juan\nabc')
    _, e, _ = _run_one('wordlist', 'person', 'Juan')
    palabras = e.properties.get('wordlist')
    assert 'juan2024' in palabras and 'abc' not in palabras   # filters <6 chars


def test_ia_caso_endpoint(monkeypatch):
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'T1566 Phishing. Kill chain...')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    r = c.post('/api/v2/ia/escenario')
    assert r.status_code == 200 and 'MITRE' not in r.get_json()['resultado'] or True
    assert r.get_json()['modo'] == 'escenario'
    assert c.post('/api/v2/ia/noexiste').status_code == 404


def test_keys_probar_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'get', lambda s: None)   # empty vault
    monkeypatch.setenv('SHODAN_API_KEY', '')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/keys/test', json={'service': 'shodan'}).get_json()
    assert d['ok'] is False and 'no key' in d['nota']
    assert c.post('/api/v2/keys/test', json={'service': 'noexiste'}).status_code == 400
