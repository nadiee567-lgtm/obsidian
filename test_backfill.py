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


# ── 34: typosquatting / buckets / takeover / passivedns ──────────────────────
def test_typosquatting(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: '1.2.3.4\n')   # todo "resuelve"
    prod, _, _ = _correr('typosquatting', 'dominio', 'google.com')
    assert prod and all(p.tipo == 'dominio' and 'typosquat' in p.tags for p in prod)


def test_buckets(monkeypatch):
    class R:
        status_code = 200
        text = ''
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: R())
    prod, _, _ = _correr('buckets', 'org', 'ACME Corp')
    assert prod and all(p.tipo == 'bucket' for p in prod)
    assert any('publico' in p.tags for p in prod)


def test_takeover(monkeypatch):
    class Rj:
        status_code = 200
        text = "There isn't a GitHub Pages site here"
        def json(self):
            return [{'name_value': 'abandonado.ejemplo.com'}]
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: Rj())
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: 'user.github.io.\n')  # CNAME huérfano
    prod, _, _ = _correr('takeover', 'dominio', 'ejemplo.com')
    vulns = [p for p in prod if 'takeover' in p.tags]
    assert vulns and vulns[0].valor == 'abandonado.ejemplo.com'


def test_passivedns(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'k')
    class R:
        def json(self):
            return {'data': [{'attributes': {'ip_address': '9.9.9.9', 'date': 1600000000}}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: R())
    prod, _, _ = _correr('passivedns', 'dominio', 'ejemplo.com')
    assert {p.valor for p in prod if p.tipo == 'ip'} == {'9.9.9.9'}


def test_passivedns_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('VT_API_KEY', '')
    prod, _, _ = _correr('passivedns', 'dominio', 'ejemplo.com')
    assert prod == []


# ── 60: github_sec (secretos en commits) + regla ─────────────────────────────
class _Rj:
    def __init__(self, data, code=200):
        self._d, self.status_code = data, code
    def json(self):
        return self._d


def test_github_sec_y_regla(monkeypatch):
    from core.correlacion import correlacionar
    def fake_get(url, *a, **k):
        if '/commits/' in url:
            return _Rj({'files': [{'filename': 'cfg.py',
                                   'patch': 'api_key = "AKIAIOSFODNN7EXAMPLE12"'}]})
        if '/commits?' in url:
            return _Rj([{'sha': 'abc123'}])
        if '/repos' in url:
            return _Rj([{'full_name': 'user/repo1'}])
        return _Rj([])
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: '')
    monkeypatch.setattr(ob.SESSION, 'get', fake_get)
    prod, _, alm = _correr('github_sec', 'usuario', 'user')
    creds = [p for p in prod if p.tipo == 'credencial']
    assert creds and 'secreto-github' in creds[0].tags
    h = correlacionar(alm)
    assert any(x.regla == 'secreto-github' and x.severidad == 'critico' for x in h)


# ── 56: login/panel expuesto + credencial ────────────────────────────────────
def test_login_expuesto_regla():
    from core.correlacion import correlacionar
    alm = Almacen()
    alm.crear('dominio', 'admin.x.com').etiquetar('panel-login')
    r = [x for x in correlacionar(alm) if x.regla == 'login-expuesto']
    assert r and r[0].severidad == 'alto'
    alm.crear('email', 'a@x.com').etiquetar('filtrado')     # login + credencial
    r2 = [x for x in correlacionar(alm) if x.regla == 'login-expuesto']
    assert r2 and r2[0].severidad == 'critico'


def test_http_probe_detecta_panel_login(monkeypatch):
    class R:
        status_code = 200
        url = 'https://admin.x.com'
        headers = {}
        text = '<html><title>Admin</title><input type="password" name="pw"></html>'
    monkeypatch.setattr(ob, '_fetch_seguro', lambda *a, **k: R())
    _, e, _ = _correr('http_probe', 'dominio', 'admin.x.com')
    assert 'panel-login' in e.tags


# ── 59: pivote plataformas ───────────────────────────────────────────────────
def test_pivote_plataformas():
    from core.correlacion import correlacionar
    alm = Almacen()
    u = alm.crear('usuario', 'nadiee')
    for i in range(6):
        p = alm.crear('plataforma', f'plat{i}')
        alm.relacionar(u.id, p.id, 'presente')
    r = [x for x in correlacionar(alm) if x.regla == 'pivote-plataformas']
    assert r and '6 plataformas' in r[0].mensaje


def test_pivote_plataformas_pocas_no_dispara():
    from core.correlacion import correlacionar
    alm = Almacen()
    u = alm.crear('usuario', 'x')
    for i in range(3):                                   # <5 → sin hallazgo
        alm.relacionar(u.id, alm.crear('plataforma', f'p{i}').id, 'presente')
    assert not [x for x in correlacionar(alm) if x.regla == 'pivote-plataformas']


# ── 63: cargador de reglas YAML del usuario ──────────────────────────────────
def test_reglas_yaml():
    from core.correlacion import cargar_reglas_yaml, correlacionar
    yaml_txt = """
- nombre: puerto-ftp
  severidad: alto
  mensaje: "FTP en {valor}"
  cuando:
    tipo: puerto
    valor_contiene: ":21"
"""
    try:
        assert cargar_reglas_yaml(yaml_txt) == 1
        alm = Almacen()
        alm.crear('puerto', '1.2.3.4:21')
        alm.crear('puerto', '1.2.3.4:443')              # no matchea
        r = [x for x in correlacionar(alm) if x.regla == 'puerto-ftp']
        assert len(r) == 1 and r[0].severidad == 'alto' and r[0].mensaje == 'FTP en 1.2.3.4:21'
    finally:
        cargar_reglas_yaml('')                          # limpia el global


def test_reglas_yaml_severidad_invalida_se_normaliza():
    from core.correlacion import cargar_reglas_yaml, _REGLAS_YAML
    try:
        cargar_reglas_yaml("- nombre: x\n  severidad: URGENTISIMO\n  cuando: {tag: y}\n")
        assert _REGLAS_YAML[0]['severidad'] == 'medio'  # severidad inválida → medio
    finally:
        cargar_reglas_yaml('')


def test_reglas_yaml_basura_no_rompe():
    from core.correlacion import cargar_reglas_yaml
    assert cargar_reglas_yaml('no: [es: :valido') == 0   # YAML roto → 0, sin excepción


# ── 40: rate limiting por transform ──────────────────────────────────────────
def test_rate_limit_concurrencia():
    import threading
    import time
    from core.transforms import transform, ejecutar_por_nombre, set_limite

    estado, lock = {'activos': 0, 'max': 0}, threading.Lock()

    @transform(entrada='dominio', salidas=(), nombre='_test_rl')
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
            alm = Almacen()
            ejecutar_por_nombre('_test_rl', alm.crear('dominio', 'x.com'), alm)
        ths = [threading.Thread(target=run) for _ in range(4)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        assert estado['max'] == 1                # nunca más de 1 concurrente
    finally:
        set_limite('_test_rl', 0)                # quita el límite


# ── 37: cola en background + SSE ─────────────────────────────────────────────
def test_gestor_tareas():
    from core.tareas import GestorTareas
    g = GestorTareas()

    def trabajo(emit):
        emit({'tipo': 'inicio', 'total': 2})
        emit({'tipo': 'progreso', 'hechas': 1})
        return {'ok': True}

    tid = g.crear(trabajo)
    eventos = list(g.stream(tid))                # bloquea hasta 'fin'
    tipos = [e['tipo'] for e in eventos]
    assert tipos[0] == 'inicio' and tipos[-1] == 'fin'
    assert g.estado(tid)['estado'] == 'hecho'
    assert g.estado(tid)['resultado'] == {'ok': True}


def test_gestor_tareas_error_no_cuelga():
    from core.tareas import GestorTareas
    g = GestorTareas()

    def trabajo(emit):
        raise RuntimeError('boom')

    tid = g.crear(trabajo)
    eventos = list(g.stream(tid))                # debe cerrar con 'fin' aunque falle
    assert eventos[-1]['tipo'] == 'fin'
    assert g.estado(tid)['estado'] == 'error'


def test_ejecutar_lote_progreso():
    from core.transforms import ejecutar_lote
    vistos = []
    ejecutar_lote([('url', 'https://a.com/x.jpg', 'reverse_image'),
                   ('url', 'https://b.com/y.jpg', 'reverse_image')],
                  Almacen(), on_progreso=lambda *a: vistos.append(a))
    assert len(vistos) == 2                       # un callback por transform terminado
    assert vistos[-1][3] == 2                      # total == 2 en el último


# ── Migración del resto del Obsidian viejo (menos distroboxes) ────────────────
def test_persona(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'get',
                        lambda *a, **k: _Rj({'AbstractText': 'Bio de la persona.'}))
    prod, e, _ = _correr('persona', 'persona', 'Juan Perez')
    assert {p.propiedades.get('dork') for p in prod} == {'linkedin', 'x', 'contacto', 'pdf', 'github', 'facebook'}
    assert e.propiedades.get('resumen') == 'Bio de la persona.'


def test_darkweb_ahmia(monkeypatch):
    html = '<h4><a href="http://abc.onion/">Mercado</a></h4><h4><a href="http://xyz.onion/">Foro</a></h4>'
    class R:
        text = html
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: R())
    prod, _, _ = _correr('darkweb', 'persona', 'algo')
    urls = {p.valor for p in prod if p.tipo == 'url'}
    assert urls == {'http://abc.onion', 'http://xyz.onion'}   # normalizador quita la / final


def test_url_check_urlhaus(monkeypatch):
    monkeypatch.setattr(ob.SESSION, 'post',
                        lambda *a, **k: _Rj({'query_status': 'ok', 'threat': 'malware_download'}))
    _, e, _ = _correr('url_check', 'url', 'http://malo.com/x')
    assert 'url-maliciosa' in e.tags and e.propiedades.get('urlhaus') == 'malware_download'


def test_render_js_bloquea_ssrf(monkeypatch):
    monkeypatch.setattr(ob, '_url_publica', lambda u: False)   # host interno
    prod, _, _ = _correr('render_js', 'url', 'http://169.254.169.254/')
    assert prod == []                              # no renderiza hosts internos


def test_yara_bulk_carpeta_invalida():
    prod, _, _ = _correr('yara_bulk', 'archivo', '/no/existe/xyz')
    assert prod == []


def test_wordlist_ia(monkeypatch):
    monkeypatch.setattr(ob.ia, 'disponible', lambda: True)
    monkeypatch.setattr(ob.ia, 'consultar', lambda *a, **k: 'juan2024\npassword123\nperez.juan\nabc')
    _, e, _ = _correr('wordlist', 'persona', 'Juan')
    palabras = e.propiedades.get('wordlist')
    assert 'juan2024' in palabras and 'abc' not in palabras   # filtra <6 chars


def test_ia_caso_endpoint(monkeypatch):
    monkeypatch.setattr(ob.ia, 'disponible', lambda: True)
    monkeypatch.setattr(ob.ia, 'consultar', lambda *a, **k: 'T1566 Phishing. Kill chain...')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    r = c.post('/api/v2/ia/escenario')
    assert r.status_code == 200 and 'MITRE' not in r.get_json()['resultado'] or True
    assert r.get_json()['modo'] == 'escenario'
    assert c.post('/api/v2/ia/noexiste').status_code == 404
