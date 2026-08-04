#!/usr/bin/env python3
"""OBSIDIAN Web — Local OSINT & Security Framework"""
import subprocess, requests, json, os, re, sys, threading, time, datetime, html, socket, hashlib, secrets, ssl
import shutil, tempfile, glob, base64, sqlite3, ipaddress
from urllib.parse import urlparse, urljoin
from flask import Flask, request, jsonify, Response, stream_with_context, send_from_directory, session, redirect
from werkzeug.exceptions import HTTPException

from core.config import HOME, HOME_INIT, CASES_DIR, STATIC_DIR, CASES_DB, PORT, WORKSPACES_DIR, VIS_FILE as _VIS
from core.validacion import (_SHELL_PELIGROSOS, _MODULO_TIPO, _es_ip, _validar,
                             _objetivo_seguro, _slug_caso, _ruta_caso_segura, _url_publica)
from core.registro import get_logger
from core.modelo import Almacen, Entidad, tipo_valido
from core.transforms import transform, REGISTRO, ejecutar_por_nombre
from core.migracion import migrar_caso
from core.workspaces import Gestor
from core.boveda import Boveda
from core.correlacion import correlacionar, score_riesgo

log = get_logger()

app   = Flask(__name__,
              static_folder=os.path.join(HOME_INIT, 'obsidian-static'),
              static_url_path='/static')
os.makedirs(CASES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# ── Manejo uniforme de errores (paso 11) ─────────────────────────────────────
def _error(mensaje, codigo=400):
    """Respuesta de error consistente en JSON: {'error': msg, 'code': n}."""
    return jsonify({'error': mensaje, 'code': codigo}), codigo

@app.errorhandler(Exception)
def _manejar_error(e):
    """Cualquier error termina en JSON uniforme para rutas /api. Las excepciones
    no controladas se loguean completas del lado servidor, pero al cliente solo
    le llega un mensaje genérico — no filtrar el stack trace."""
    if isinstance(e, HTTPException):
        if request.path.startswith('/api/'):
            return _error(e.description or e.name, e.code)
        return e   # páginas normales: 404/405 HTML por defecto
    log.exception("error no controlado en %s %s", request.method, request.path)
    if request.path.startswith('/api/'):
        return _error('Error interno del servidor', 500)
    return 'Error interno del servidor', 500

def _db_init():
    con = sqlite3.connect(CASES_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS casos (
        nombre TEXT PRIMARY KEY, objetivo TEXT, iniciado TEXT,
        actualizado TEXT, datos_json TEXT
    )""")
    con.commit()
    con.close()

_db_init()

def _db_guardar_caso(caso_dict):
    """Espejo del caso en SQLite — no reemplaza el JSON, solo lo hace buscable."""
    try:
        con = sqlite3.connect(CASES_DB)
        con.execute(
            "INSERT INTO casos (nombre, objetivo, iniciado, actualizado, datos_json) VALUES (?,?,?,?,?) "
            "ON CONFLICT(nombre) DO UPDATE SET objetivo=excluded.objetivo, actualizado=excluded.actualizado, datos_json=excluded.datos_json",
            (caso_dict.get('nombre'), caso_dict.get('objetivo'), caso_dict.get('iniciado'),
             datetime.datetime.now().isoformat(), json.dumps(caso_dict.get('datos', {}), default=str))
        )
        con.commit()
        con.close()
    except Exception as e:
        log.error("error guardando espejo SQLite: %s", e)

def _db_buscar(termino):
    """Busca un término (email, dominio, usuario...) en todos los casos guardados."""
    con = sqlite3.connect(CASES_DB)
    con.row_factory = sqlite3.Row
    filas = con.execute(
        "SELECT nombre, objetivo, actualizado, datos_json FROM casos WHERE datos_json LIKE ? OR objetivo LIKE ?",
        (f'%{termino}%', f'%{termino}%')
    ).fetchall()
    con.close()
    resultados = []
    for fila in filas:
        try:
            datos = json.loads(fila['datos_json'])
        except Exception:
            datos = {}
        modulos_con_match = [clave for clave, valor in datos.items()
                              if termino.lower() in json.dumps(valor, default=str).lower()]
        resultados.append({
            'caso': fila['nombre'], 'objetivo': fila['objetivo'],
            'actualizado': fila['actualizado'], 'modulos_con_match': modulos_con_match
        })
    return resultados
# Si falta vis.js (grafo) en el static del usuario, copiar el que viene con el programa
_HERE = os.path.dirname(os.path.abspath(__file__))
_WEB_DIR = os.path.join(_HERE, 'web')
def _cargar_web(nombre):
    """Carga un archivo de UI (HTML/JS/CSS) desde web/. El front vive en
    archivos, no incrustado en el .py. Se lee como texto: los .replace()/
    .format() de siempre siguen aplicando (nada de Jinja, que chocaría con
    las llaves del CSS y los ${} de JS)."""
    with open(os.path.join(_WEB_DIR, nombre), encoding='utf-8') as _f:
        return _f.read()

if not os.path.exists(os.path.join(STATIC_DIR, _VIS)) and os.path.exists(os.path.join(_HERE, _VIS)):
    shutil.copy(os.path.join(_HERE, _VIS), os.path.join(STATIC_DIR, _VIS))
OLLAMA    = 'http://localhost:11434'
MODEL     = 'qwen2.5:3b'

# ── Auth: obligatoria si el server se expone fuera de 127.0.0.1 ───────────────
CONFIG_DIR     = os.path.join(HOME, '.obsidian')
SECRET_KEY_FILE = os.path.join(CONFIG_DIR, 'secret_key')
AUTH_FILE       = os.path.join(CONFIG_DIR, 'auth.json')
os.makedirs(CONFIG_DIR, exist_ok=True)

def _load_secret_key():
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE) as f: return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f: f.write(key)
    os.chmod(SECRET_KEY_FILE, 0o600)
    return key

def _hash_password(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200_000).hex()

def _load_or_create_auth():
    env_pw = os.environ.get('OBSIDIAN_PASSWORD')
    if env_pw:
        salt = secrets.token_bytes(16)
        return {'salt': salt.hex(), 'hash': _hash_password(env_pw, salt)}
    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE) as f: return json.load(f)
    salt = secrets.token_bytes(16)
    pw = secrets.token_urlsafe(9)
    auth = {'salt': salt.hex(), 'hash': _hash_password(pw, salt)}
    with open(AUTH_FILE, 'w') as f: json.dump(auth, f)
    os.chmod(AUTH_FILE, 0o600)
    print(f"\n[OBSIDIAN] Contraseña generada: {pw}")
    print(f"[OBSIDIAN] Guárdala — no se vuelve a mostrar. Para cambiarla: borra {AUTH_FILE} o usa OBSIDIAN_PASSWORD=tu_clave\n")
    return auth

app.secret_key = _load_secret_key()
app.permanent_session_lifetime = datetime.timedelta(days=7)
_AUTH = _load_or_create_auth()
_login_attempts = {}   # ip -> [intentos, bloqueado_hasta_ts]
_LOCK_THRESHOLD = 5
_LOCK_SECONDS   = 300
_PUBLIC_PATHS   = {'/login', '/manifest.json', '/sw.js', '/cert.pem'}
_PUBLIC_PREFIXES = ('/static/', '/icon-')

_LOGIN_HTML = _cargar_web('login.html')

@app.before_request
def _require_auth():
    if request.path in _PUBLIC_PATHS or request.path.startswith(_PUBLIC_PREFIXES):
        return
    if session.get('auth'):
        return
    if request.path.startswith('/api/'):
        return jsonify({'error': 'No autenticado'}), 401
    session['next'] = request.path   # recordar a dónde iba, para volver tras el login
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    now = time.time()
    intentos, bloqueado_hasta = _login_attempts.get(ip, [0, 0])
    if now < bloqueado_hasta:
        err = f'<div class="err">Demasiados intentos. Esperá {int(bloqueado_hasta - now)}s.</div>'
        return _LOGIN_HTML.format(error_html=err), 429
    if request.method == 'POST':
        pw = request.form.get('password', '')
        salt = bytes.fromhex(_AUTH['salt'])
        if secrets.compare_digest(_hash_password(pw, salt), _AUTH['hash']):
            dest = session.get('next', '/')
            session.clear()
            session['auth'] = True
            session.permanent = True
            _login_attempts.pop(ip, None)
            # solo rutas internas (anti open-redirect)
            if not dest.startswith('/') or dest.startswith('//'):
                dest = '/'
            return redirect(dest)
        intentos += 1
        bloqueado_hasta = now + _LOCK_SECONDS if intentos >= _LOCK_THRESHOLD else 0
        _login_attempts[ip] = [intentos, bloqueado_hasta]
        return _LOGIN_HTML.format(error_html='<div class="err">Contraseña incorrecta</div>'), 401
    return _LOGIN_HTML.format(error_html='')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ── OBSIDIAN es libre y gratuito — sin licencias, tiers ni candados ───────────

SESSION = requests.Session()
SESSION.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0'})

# Estado global de investigación
case = {'nombre': None, 'objetivo': None, 'datos': {}, 'historial': [], 'iniciado': None}
case_lock = threading.Lock()

# Modelo tipado de la sesión (F2, integración del motor de transforms).
# Convive con `case` mientras migramos; los endpoints /api/v2/* usan esto.
_almacen = Almacen()

# F3: gestor de workspaces (casos aislados en SQLite). _ws_activo = None -> modo
# efímero (no se guarda); si hay uno activo, cada transform hace autosave.
_gestor = Gestor(WORKSPACES_DIR)
_ws_activo = None

# F3 paso 51: bóveda de API keys cifrada (Fernet).
_boveda = Boveda(os.path.join(HOME, '.obsidian'))

SYSTEM = """You are OBSIDIAN AI, an OSINT intelligence analysis engine.
ROLE: Expert analyst. Correlate data, find patterns, generate actionable conclusions.
RULES: NEVER fabricate data. Be direct and technical. Use [!] critical, [+] positive, [-] negative.
Always respond in English."""

# ── Utilidades ────────────────────────────────────────────────────────────────

def _cmd(cmd, timeout=25):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout, cwd=HOME, env={**os.environ,'HOME':HOME})
        return (r.stdout + r.stderr).strip() or '(sin salida)'
    except subprocess.TimeoutExpired:
        return f'[Timeout {timeout}s]'
    except Exception as e:
        return f'[Error: {e}]'

def run_tool(argv, timeout=25, stdin=None):
    """Ejecuta una herramienta SIN shell: argv es una lista, no un string.
    Cierra la inyección por metacaracteres (;, |, `, $()...) porque nunca
    pasa por un intérprete de shell. Para cerrar TAMBIÉN la argument
    injection (un valor que empieza con '-' se interpreta como flag),
    validar el objetivo por tipo con _validar() ANTES de llamar aquí.
    Preferir esta función sobre _cmd para todo lo que interpole datos del
    usuario. _cmd queda solo para pipelines internos con valores ya validados."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           cwd=HOME, env={**os.environ, 'HOME': HOME}, input=stdin)
        return (r.stdout + r.stderr).strip() or '(sin salida)'
    except subprocess.TimeoutExpired:
        return f'[Timeout {timeout}s]'
    except FileNotFoundError:
        return f'[Error: {argv[0] if argv else "?"} no encontrado]'
    except Exception as e:
        return f'[Error: {e}]'

# ── Seguridad: fetch anti-SSRF (usa _url_publica de core.validacion + SESSION) ─
def _fetch_seguro(url, timeout=10, stream=False, max_redirs=3):
    """GET que cierra SSRF: valida que CADA hop apunte a IP pública. Sigue los
    redirects a mano y revalida cada uno (un sitio público puede redirigir a
    169.254.169.254). Lanza ValueError si algún destino es interno.
    Nota: no cubre DNS rebinding (TOCTOU); vector avanzado, pendiente futuro."""
    if '://' not in url:
        url = 'https://' + url
    for _ in range(max_redirs + 1):
        if not _url_publica(url):
            raise ValueError('URL bloqueada (SSRF): red interna/privada o esquema no permitido')
        r = SESSION.get(url, timeout=timeout, stream=stream, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get('Location'):
            url = urljoin(url, r.headers['Location'])
            continue
        return r
    raise ValueError('Demasiados redirects')

def _which(cmd):
    return subprocess.run(['which',cmd], capture_output=True).returncode == 0

def _guardar_dato(clave, valor):
    with case_lock:
        case['datos'][clave] = valor
        case['historial'].append({'ts': time.time(), 'clave': clave, 'resumen': str(valor)[:100]})

def _ai_stream(prompt):
    try:
        r = SESSION.post(f'{OLLAMA}/api/chat', json={
            'model': MODEL,
            'messages': [{'role':'system','content':SYSTEM},{'role':'user','content':prompt}],
            'stream': True,
            'options': {'num_ctx':2048,'num_predict':600,'temperature':0.4,'num_thread':4}
        }, timeout=(10,120), stream=True)
        for line in r.iter_lines():
            if line:
                try:
                    chunk = json.loads(line)
                    tok = chunk.get('message',{}).get('content','')
                    if tok: yield tok
                    if chunk.get('done'): break
                except Exception: continue
    except Exception as e:
        yield f'[Error IA: {e}]'

def _ai(prompt):
    return ''.join(_ai_stream(prompt))

def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception: return '127.0.0.1'

# ── Módulos OSINT ─────────────────────────────────────────────────────────────

def _osint_persona(nombre):
    datos = {'tipo':'persona','objetivo':nombre,'resultados':{}}
    # DuckDuckGo
    try:
        r = SESSION.get(f"https://api.duckduckgo.com/?q={requests.utils.quote(nombre)}&format=json&no_html=1", timeout=8)
        d = r.json()
        if d.get('AbstractText'):
            datos['resultados']['resumen'] = d['AbstractText'][:400]
        topics = [t['Text'][:200] for t in d.get('RelatedTopics',[])[:5] if isinstance(t,dict) and t.get('Text')]
        if topics: datos['resultados']['temas'] = topics
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # Dorks
    datos['resultados']['dorks'] = [
        f'"{nombre}" site:linkedin.com',
        f'"{nombre}" site:twitter.com OR site:x.com',
        f'"{nombre}" email OR phone OR address',
        f'"{nombre}" filetype:pdf',
        f'"{nombre}" site:github.com',
        f'"{nombre}" "fecha de nacimiento" OR "birthday"',
        f'"{nombre}" site:facebook.com',
    ]
    # HIBP check
    try:
        r = SESSION.get(f"https://haveibeenpwned.com/unifiedsearch/{requests.utils.quote(nombre)}",
                       timeout=6, headers={'User-Agent':'OSINT-Research'})
        datos['resultados']['hibp'] = 'Posible presencia en HIBP' if r.status_code==200 else 'No encontrado en HIBP'
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    _guardar_dato(f'persona_{nombre}', datos)
    return datos

def _osint_usuario(username):
    datos = {'tipo':'usuario','objetivo':username,'resultados':{}}
    plataformas = {
        'GitHub':    f'https://github.com/{username}',
        'Twitter/X': f'https://x.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Reddit':    f'https://reddit.com/user/{username}',
        'TikTok':    f'https://tiktok.com/@{username}',
        'Telegram':  f'https://t.me/{username}',
        'GitLab':    f'https://gitlab.com/{username}',
        'HackerNews':f'https://news.ycombinator.com/user?id={username}',
        'Medium':    f'https://medium.com/@{username}',
        'Dev.to':    f'https://dev.to/{username}',
    }
    encontrados = []
    def _check(plat, url):
        try:
            r = SESSION.get(url, timeout=5, allow_redirects=True)
            if r.status_code == 200 and 'not found' not in r.text.lower()[:300]:
                encontrados.append({'plataforma':plat,'url':url})
        except Exception as _e: log.debug("fuente no disponible: %s", _e)
    ths = [threading.Thread(target=_check, args=(p,u)) for p,u in plataformas.items()]
    for t in ths: t.start()
    for t in ths: t.join(timeout=8)
    datos['resultados']['plataformas'] = encontrados
    # GitHub API
    try:
        gh = SESSION.get(f'https://api.github.com/users/{username}', timeout=8).json()
        if gh.get('login'):
            datos['resultados']['github'] = {
                'nombre': gh.get('name','?'), 'bio': gh.get('bio','?'),
                'repos': gh.get('public_repos',0), 'seguidores': gh.get('followers',0),
                'ubicacion': gh.get('location','?'), 'email': gh.get('email','oculto'),
                'web': gh.get('blog','?'), 'creado': gh.get('created_at','?')
            }
            # Repos públicos
            repos_r = SESSION.get(f'https://api.github.com/users/{username}/repos?per_page=10&sort=updated', timeout=8)
            if repos_r.status_code == 200:
                repos = [{'nombre':r['name'],'url':r['html_url'],'stars':r['stargazers_count'],
                          'lenguaje':r.get('language','?')} for r in repos_r.json()]
                datos['resultados']['github_repos'] = repos
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # Sherlock
    if _which('sherlock'):
        out = _cmd(f'sherlock {username} --timeout 5 --print-found 2>/dev/null', timeout=60)
        encontrados_sh = [l.strip() for l in out.splitlines() if '[+]' in l]
        datos['resultados']['sherlock'] = encontrados_sh
    # Maigret — más cobertura de plataformas que Sherlock
    if _which('maigret'):
        with tempfile.TemporaryDirectory() as tmpdir:
            _cmd(f'maigret {username} --timeout 8 -J ndjson -fo {tmpdir} 2>/dev/null', timeout=90)
            encontrados_mg = []
            for fpath in glob.glob(os.path.join(tmpdir, '*.ndjson')):
                try:
                    with open(fpath, encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if not line: continue
                            try: rec = json.loads(line)
                            except Exception: continue
                            estado = str(rec.get('status', '')).lower()
                            if 'claim' not in estado: continue
                            sitio = rec.get('sitename') or rec.get('site_name') or rec.get('name') or '?'
                            url   = rec.get('url_user') or rec.get('url') or ''
                            encontrados_mg.append({'plataforma': sitio, 'url': url})
                except Exception as _e: log.debug("maigret parse: %s", _e)
            if encontrados_mg:
                datos['resultados']['maigret'] = encontrados_mg
    _guardar_dato(f'usuario_{username}', datos)
    return datos

def _osint_dominio(dominio):
    dominio = dominio.replace('https://','').replace('http://','').split('/')[0]
    datos = {'tipo':'dominio','objetivo':dominio,'resultados':{}}
    # WHOIS
    whois_raw = _cmd(f'whois {dominio} 2>/dev/null')
    whois_lines = [l.strip() for l in whois_raw.splitlines()
                   if any(k in l.lower() for k in ['registr','creat','expir','name server','email','org','status'])]
    datos['resultados']['whois'] = whois_lines[:20]
    # DNS
    dns = {}
    for rtype in ['A','AAAA','MX','NS','TXT','CNAME']:
        out = _cmd(f'dig {dominio} {rtype} +short 2>/dev/null')
        if out.strip() and 'error' not in out.lower():
            dns[rtype] = out.strip()
    datos['resultados']['dns'] = dns
    # Subdominios crt.sh
    try:
        r = SESSION.get(f'https://crt.sh/?q=%.{dominio}&output=json', timeout=12)
        subs = set()
        for cert in r.json():
            for s in cert.get('name_value','').split('\n'):
                s = s.strip().lstrip('*.')
                if s.endswith(dominio) and s != dominio: subs.add(s)
        datos['resultados']['subdominios'] = sorted(list(subs))[:30]
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # Headers / Tecnologías
    try:
        import urllib3; urllib3.disable_warnings()
        r = SESSION.get(f'https://{dominio}', timeout=8, verify=False)
        h = r.headers
        tech = {k:h[k] for k in ['Server','X-Powered-By','X-Generator','X-Framework'] if k in h}
        missing_sec = [k for k in ['Strict-Transport-Security','Content-Security-Policy',
                                    'X-Frame-Options','X-Content-Type-Options'] if k not in h]
        datos['resultados']['tecnologias'] = tech
        datos['resultados']['headers_faltantes'] = missing_sec
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # theHarvester
    if _which('theHarvester'):
        out = _cmd(f'theHarvester -d {dominio} -b duckduckgo -l 50 2>/dev/null', timeout=45)
        emails = list(set(re.findall(r'[\w\.-]+@[\w\.-]+', out)))
        hosts  = list(set(re.findall(r'[\w\.-]+\.'+re.escape(dominio), out)))
        datos['resultados']['emails']  = emails[:15]
        datos['resultados']['hosts']   = hosts[:15]
    # Wayback
    try:
        r = SESSION.get(f'http://archive.org/wayback/available?url={dominio}', timeout=8)
        snap = r.json().get('archived_snapshots',{}).get('closest',{})
        if snap.get('url'): datos['resultados']['wayback'] = snap
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    _guardar_dato(f'dominio_{dominio}', datos)
    return datos

def _osint_ip(ip):
    datos = {'tipo':'ip','objetivo':ip,'resultados':{}}
    # Geo
    try:
        r = SESSION.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,mobile,proxy,hosting', timeout=8)
        d = r.json()
        if d.get('status') == 'success': datos['resultados']['geo'] = d
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # Puertos
    if _which('nmap'):
        out = run_tool(['nmap','-T4','--top-ports','20','-sV','--open',ip], timeout=60)
        puertos = [l.strip() for l in out.splitlines() if '/tcp' in l or '/udp' in l]
        datos['resultados']['puertos'] = puertos
    # PTR
    ptr = _cmd(f'dig -x {ip} +short 2>/dev/null').strip()
    if ptr: datos['resultados']['ptr'] = ptr
    # ASN
    try:
        r = SESSION.get(f'https://api.hackertarget.com/aslookup/?q={ip}', timeout=8)
        datos['resultados']['asn'] = r.text.strip()
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    _guardar_dato(f'ip_{ip}', datos)
    return datos

def _osint_email(email):
    datos = {'tipo':'email','objetivo':email,'resultados':{}}
    dominio = email.split('@')[1] if '@' in email else ''
    # Breach check
    try:
        r = SESSION.get(f'https://breachdirectory.p.rapidapi.com/?func=auto&term={email}',
                       timeout=8, headers={'X-RapidAPI-Key':'demo','X-RapidAPI-Host':'breachdirectory.p.rapidapi.com'})
        if r.status_code == 200:
            datos['resultados']['breach'] = r.json()
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # HIBP
    try:
        r = SESSION.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}',
                       timeout=8, headers={'hibp-api-key':'free','User-Agent':'OBSIDIAN-OSINT'})
        if r.status_code == 200:
            breaches = [b.get('Name','?') for b in r.json()]
            datos['resultados']['hibp_breaches'] = breaches
        elif r.status_code == 404:
            datos['resultados']['hibp_breaches'] = []
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # SPF/DKIM/DMARC del dominio
    if dominio:
        spf   = _cmd(f'dig {dominio} TXT +short 2>/dev/null')
        dmarc = _cmd(f'dig _dmarc.{dominio} TXT +short 2>/dev/null')
        dkim  = _cmd(f'dig default._domainkey.{dominio} TXT +short 2>/dev/null')
        spoofable = not any('v=spf1' in spf.lower() for _ in [1])
        datos['resultados']['email_sec'] = {
            'spf': spf.strip()[:200] or 'NO CONFIGURADO',
            'dmarc': dmarc.strip()[:200] or 'NO CONFIGURADO',
            'dkim': dkim.strip()[:200] or 'NO CONFIGURADO',
            'spoofable': spoofable
        }
    _guardar_dato(f'email_{email}', datos)
    return datos

def _osint_phone(numero):
    datos = {'tipo':'telefono','objetivo':numero,'resultados':{}}
    numero_limpio = re.sub(r'[^\d+]','',numero)
    # API pública básica
    try:
        r = SESSION.get(f'https://api.hackertarget.com/ipgeo/?q={numero_limpio}', timeout=8)
        datos['resultados']['raw'] = r.text.strip()
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # NumVerify (sin key — básico)
    try:
        r = SESSION.get(f'http://apilayer.net/api/validate?number={numero_limpio}', timeout=8)
        if r.status_code == 200:
            d = r.json()
            datos['resultados']['info'] = {
                'válido': d.get('valid', False),
                'pais': d.get('country_name','?'),
                'carrier': d.get('carrier','?'),
                'tipo': d.get('line_type','?')
            }
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # Buscar en redes
    datos['resultados']['busquedas'] = [
        f'"{numero}" site:truecaller.com',
        f'"{numero}" site:whitepages.com',
        f'"{numero_limpio}"',
        f'"{numero}" whatsapp OR telegram',
    ]
    _guardar_dato(f'telefono_{numero}', datos)
    return datos

def _recon_github_secrets(username_or_org):
    datos = {'tipo':'github_secrets','objetivo':username_or_org,'resultados':{}}
    patrones = [
        ('API Key',      r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})'),
        ('Secret',       r'secret\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})'),
        ('Password',     r'password\s*[=:]\s*["\']?([^\s"\']{8,})'),
        ('Token',        r'token\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})'),
        ('AWS Key',      r'AKIA[0-9A-Z]{16}'),
        ('Private Key',  r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'),
    ]
    try:
        repos_r = SESSION.get(f'https://api.github.com/users/{username_or_org}/repos?per_page=20', timeout=8)
        if repos_r.status_code != 200:
            repos_r = SESSION.get(f'https://api.github.com/orgs/{username_or_org}/repos?per_page=20', timeout=8)
        repos = repos_r.json()
        hallazgos = []
        for repo in repos[:10]:
            repo_name = repo.get('full_name','')
            # Buscar en commits recientes
            commits_r = SESSION.get(f'https://api.github.com/repos/{repo_name}/commits?per_page=5', timeout=8)
            if commits_r.status_code != 200: continue
            for commit in commits_r.json()[:3]:
                sha = commit.get('sha','')
                diff_r = SESSION.get(f'https://api.github.com/repos/{repo_name}/commits/{sha}', timeout=8)
                if diff_r.status_code != 200: continue
                files = diff_r.json().get('files',[])
                for f in files[:5]:
                    patch = f.get('patch','')
                    for nombre_pat, patron in patrones:
                        matches = re.findall(patron, patch, re.IGNORECASE)
                        for m in matches:
                            hallazgos.append({
                                'repo': repo_name, 'tipo': nombre_pat,
                                'valor': m[:50]+'...' if len(m)>50 else m,
                                'commit': sha[:8], 'archivo': f.get('filename','?')
                            })
        datos['resultados']['hallazgos'] = hallazgos
        datos['resultados']['repos_analizados'] = len(repos[:10])
    except Exception as e:
        datos['resultados']['error'] = str(e)
    _guardar_dato(f'github_secrets_{username_or_org}', datos)
    return datos

def _recon_ssl(dominio):
    datos = {'tipo':'ssl','objetivo':dominio,'resultados':{}}
    dominio = dominio.replace('https://','').replace('http://','').split('/')[0]
    # Info básica
    cert_info = _cmd(f'echo | openssl s_client -connect {dominio}:443 -servername {dominio} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint 2>/dev/null')
    datos['resultados']['certificado'] = cert_info
    # Cipher suites vulnerables
    for cipher, vuln in [('RC4','OBSOLETE'),('DES','VULNERABLE'),('NULL','CRITICAL'),('EXPORT','CRITICAL')]:
        out = _cmd(f'openssl s_client -connect {dominio}:443 -cipher {cipher} 2>/dev/null | head -3')
        if 'Cipher' in out and 'NONE' not in out:
            datos['resultados'][f'cipher_{cipher}'] = f'VULNERABLE — {vuln}'
    # HSTS
    try:
        import urllib3; urllib3.disable_warnings()
        r = SESSION.get(f'https://{dominio}', timeout=8, verify=False)
        datos['resultados']['hsts'] = r.headers.get('Strict-Transport-Security','NO CONFIGURADO')
        datos['resultados']['ocsp'] = 'Verificar manualmente'
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    _guardar_dato(f'ssl_{dominio}', datos)
    return datos

def _recon_favicon(dominio):
    """Hash mmh3 del favicon (algoritmo Shodan) — pivotea a infraestructura relacionada."""
    datos = {'tipo':'favicon','objetivo':dominio,'resultados':{}}
    dominio = dominio.replace('https://','').replace('http://','').split('/')[0]
    try:
        import mmh3
    except ImportError:
        datos['resultados']['error'] = "Falta la librería mmh3 — instalar con: pip install mmh3"
        _guardar_dato(f'favicon_{dominio}', datos)
        return datos
    favicon_bytes = None
    for esquema in ('https', 'http'):
        try:
            r = SESSION.get(f'{esquema}://{dominio}/favicon.ico', timeout=8, verify=False)
            if r.status_code == 200 and r.content:
                favicon_bytes = r.content
                break
        except Exception as _e: log.debug("fuente no disponible: %s", _e)
    if not favicon_bytes:
        datos['resultados']['error'] = 'No se encontró favicon.ico en el objetivo (probar con otra ruta manualmente)'
        _guardar_dato(f'favicon_{dominio}', datos)
        return datos
    favicon_b64 = base64.encodebytes(favicon_bytes)
    hash_mmh3 = mmh3.hash(favicon_b64)
    datos['resultados']['hash'] = hash_mmh3
    datos['resultados']['tamano_bytes'] = len(favicon_bytes)
    if SHODAN_KEY:
        try:
            r = SESSION.get(f'https://api.shodan.io/shodan/host/search?key={SHODAN_KEY}&query=http.favicon.hash:{hash_mmh3}', timeout=10)
            d = r.json()
            datos['resultados']['total_relacionados'] = d.get('total', 0)
            datos['resultados']['relacionados'] = [{
                'ip': m.get('ip_str'), 'puerto': m.get('port'),
                'org': m.get('org'), 'pais': m.get('location',{}).get('country_name'),
                'hostnames': m.get('hostnames', [])
            } for m in d.get('matches', [])[:15]]
        except Exception as e:
            datos['resultados']['error_shodan'] = str(e)
    else:
        datos['resultados']['nota'] = f'Hash calculado: {hash_mmh3}. Agregar API key de Shodan (gratis en shodan.io) para buscar infraestructura relacionada, o pegar el hash manualmente en shodan.io/search?query=http.favicon.hash:{hash_mmh3}'
    _guardar_dato(f'favicon_{dominio}', datos)
    return datos

def _recon_typosquatting(dominio):
    datos = {'tipo':'typosquatting','objetivo':dominio,'resultados':{}}
    nombre, ext = dominio.rsplit('.',1) if '.' in dominio else (dominio,'com')
    variantes = set()
    # Sustituciones comunes
    subs = {'a':'4','e':'3','i':'1','o':'0','s':'5','l':'1'}
    for i, c in enumerate(nombre):
        if c in subs:
            v = nombre[:i]+subs[c]+nombre[i+1:]
            variantes.add(f'{v}.{ext}')
    # Typos de teclado
    teclado = {'q':'w','w':'e','e':'r','r':'t','t':'y','a':'s','s':'d','d':'f',
               'f':'g','g':'h','z':'x','x':'c','c':'v','v':'b'}
    for i, c in enumerate(nombre.lower()):
        if c in teclado:
            v = nombre[:i]+teclado[c]+nombre[i+1:]
            variantes.add(f'{v}.{ext}')
    # Omisión/duplicación de letras
    for i in range(len(nombre)):
        variantes.add(f'{nombre[:i]+nombre[i+1:]}.{ext}')
        variantes.add(f'{nombre[:i]+nombre[i]*2+nombre[i:]}.{ext}')
    # Verificar cuáles existen
    registrados = []
    def _check_domain(v):
        out = _cmd(f'dig {v} A +short 2>/dev/null', timeout=3)
        if out.strip() and not 'error' in out.lower():
            registrados.append({'dominio':v,'ip':out.strip()})
    ths = [threading.Thread(target=_check_domain, args=(v,)) for v in list(variantes)[:25]]
    for t in ths: t.start()
    for t in ths: t.join(timeout=10)
    datos['resultados']['variantes_totales'] = len(variantes)
    datos['resultados']['registrados'] = registrados
    _guardar_dato(f'typosquatting_{dominio}', datos)
    return datos

def _recon_buckets(empresa):
    datos = {'tipo':'buckets','objetivo':empresa,'resultados':{}}
    nombre = empresa.lower().replace(' ','-').replace('_','-')
    variantes = [nombre, f'{nombre}-backup', f'{nombre}-dev', f'{nombre}-prod',
                 f'{nombre}-staging', f'{nombre}-assets', f'{nombre}-media',
                 f'backup-{nombre}', f'dev-{nombre}', f'assets-{nombre}']
    encontrados = []
    def _check(bucket):
        urls = [
            f'https://{bucket}.s3.amazonaws.com',
            f'https://storage.googleapis.com/{bucket}',
            f'https://{bucket}.blob.core.windows.net',
        ]
        for url in urls:
            try:
                r = SESSION.get(url, timeout=5)
                if r.status_code in [200, 403]:
                    encontrados.append({
                        'bucket': bucket, 'url': url,
                        'status': r.status_code,
                        'publico': r.status_code == 200
                    })
            except Exception as _e: log.debug("fuente no disponible: %s", _e)
    ths = [threading.Thread(target=_check, args=(b,)) for b in variantes]
    for t in ths: t.start()
    for t in ths: t.join(timeout=15)
    datos['resultados']['buckets'] = encontrados
    datos['resultados']['variantes_probadas'] = variantes
    _guardar_dato(f'buckets_{empresa}', datos)
    return datos

def _recon_subdomain_takeover(dominio):
    datos = {'tipo':'subdomain_takeover','objetivo':dominio,'resultados':{}}
    try:
        r = SESSION.get(f'https://crt.sh/?q=%.{dominio}&output=json', timeout=12)
        subs = set()
        for cert in r.json():
            for s in cert.get('name_value','').split('\n'):
                s = s.strip().lstrip('*.')
                if s.endswith(dominio) and s != dominio: subs.add(s)
    except Exception:
        subs = set()
    # Servicios vulnerables a takeover
    FINGERPRINTS = {
        'github.io':          'There isn\'t a GitHub Pages site here',
        'herokuapp.com':      'No such app',
        'amazonaws.com':      'NoSuchBucket',
        'azurewebsites.net':  '404 Web Site not found',
        'netlify.app':        'Not Found',
        'surge.sh':           'project not found',
        'readme.io':          'Project doesnt exist',
        'zendesk.com':        'Help Center Closed',
        'shopify.com':        "Sorry, this shop is currently unavailable",
    }
    vulnerables = []
    def _check_sub(sub):
        cname = _cmd(f'dig {sub} CNAME +short 2>/dev/null').strip()
        if not cname: return
        for servicio, fp in FINGERPRINTS.items():
            if servicio in cname:
                try:
                    r = SESSION.get(f'http://{sub}', timeout=5)
                    if fp.lower() in r.text.lower():
                        vulnerables.append({'subdominio':sub,'cname':cname,'servicio':servicio,'status':'VULNERABLE'})
                except Exception:
                    vulnerables.append({'subdominio':sub,'cname':cname,'servicio':servicio,'status':'POSIBLE'})
    ths = [threading.Thread(target=_check_sub, args=(s,)) for s in list(subs)[:20]]
    for t in ths: t.start()
    for t in ths: t.join(timeout=20)
    datos['resultados']['subdominios_analizados'] = len(list(subs)[:20])
    datos['resultados']['vulnerables'] = vulnerables
    _guardar_dato(f'takeover_{dominio}', datos)
    return datos

def _recon_passivedns(dominio):
    """Historial de IPs por las que pasó el dominio, vía VirusTotal (ya tenés la key de Analyze)."""
    datos = {'tipo':'passivedns','objetivo':dominio,'resultados':{}}
    dominio = dominio.replace('https://','').replace('http://','').split('/')[0]
    vt_key = os.environ.get('VT_API_KEY','')
    if not vt_key:
        datos['resultados']['nota'] = 'Agregar API key de VirusTotal (gratis, tab Analyze) para ver el historial de IPs'
        _guardar_dato(f'passivedns_{dominio}', datos)
        return datos
    try:
        r = SESSION.get(f'https://www.virustotal.com/api/v3/domains/{dominio}/resolutions',
                       headers={'x-apikey': vt_key}, params={'limit': 20}, timeout=12)
        d = r.json()
        historial = []
        for item in d.get('data', []):
            attr = item.get('attributes', {})
            fecha = attr.get('date')
            historial.append({
                'ip': attr.get('ip_address', '?'),
                'fecha': datetime.datetime.utcfromtimestamp(fecha).strftime('%Y-%m-%d') if fecha else '?'
            })
        datos['resultados']['historial'] = historial
        datos['resultados']['total'] = len(historial)
    except Exception as e:
        datos['resultados']['error'] = str(e)
    _guardar_dato(f'passivedns_{dominio}', datos)
    return datos

def _recon_metadata(url):
    if '://' not in url:
        url = 'https://' + url
    datos = {'tipo':'metadata','objetivo':url,'resultados':{}}
    try:
        r = _fetch_seguro(url, timeout=10, stream=True)
        content_type = r.headers.get('Content-Type','')
        # Si es imagen, extraer EXIF
        if 'image' in content_type:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
                    if f.tell() > 5_000_000: break
                fname = f.name
            if _which('exiftool'):
                exif = _cmd(f'exiftool {fname} 2>/dev/null')
                datos['resultados']['exif'] = exif[:2000]
                # Buscar GPS
                gps = re.findall(r'GPS.*?:\s*(.+)', exif)
                if gps: datos['resultados']['gps'] = gps
            os.unlink(fname)
        else:
            # HTML — extraer meta tags
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text[:50000], 'html.parser')
            metas = {}
            for tag in soup.find_all('meta'):
                name = tag.get('name') or tag.get('property','')
                content = tag.get('content','')
                if name and content: metas[name] = content[:200]
            datos['resultados']['meta_tags'] = metas
            datos['resultados']['titulo'] = soup.title.string if soup.title else '?'
    except Exception as e:
        datos['resultados']['error'] = str(e)
    _guardar_dato(f'metadata_{url[:50]}', datos)
    return datos

def _recon_render_js(url):
    """Renderiza la página con navegador headless — ve lo que carga con JS, screenshot incluido."""
    datos = {'tipo':'render_js','objetivo':url,'resultados':{}}
    if not url.startswith(('http://','https://')):
        url = 'https://' + url
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        datos['resultados']['error'] = 'Falta playwright — instalar con: pip install playwright && playwright install chromium'
        _guardar_dato(f'render_{url[:50]}', datos)
        return datos
    shots_dir = os.path.join(STATIC_DIR, 'screenshots')
    os.makedirs(shots_dir, exist_ok=True)
    nombre_img = f"{hashlib.md5(url.encode()).hexdigest()[:10]}.png"
    ruta_img = os.path.join(shots_dir, nombre_img)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width':1280,'height':900})
            page.goto(url, timeout=20000, wait_until='networkidle')
            datos['resultados']['titulo'] = page.title()
            html_render = page.content()
            page.screenshot(path=ruta_img, full_page=False)
            browser.close()
        datos['resultados']['screenshot'] = f'/static/screenshots/{nombre_img}'
        datos['resultados']['emails_en_render'] = list(set(re.findall(
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html_render)))[:15]
        datos['resultados']['tamano_html_render'] = len(html_render)
    except Exception as e:
        datos['resultados']['error'] = f'Error al renderizar: {e}'
    _guardar_dato(f'render_{url[:50]}', datos)
    return datos

def _recon_yara_bulk(carpeta):
    """Escanea todos los archivos de una carpeta con yara-rules — solo tiene sentido en PC."""
    datos = {'tipo':'yara_bulk','objetivo':carpeta,'resultados':{}}
    if not os.path.isdir(carpeta):
        datos['resultados']['error'] = f'No es una carpeta válida: {carpeta}'
        _guardar_dato(f'yara_bulk_{carpeta}', datos)
        return datos
    if not _which('yara-rules'):
        datos['resultados']['error'] = 'yara-rules no está instalado'
        _guardar_dato(f'yara_bulk_{carpeta}', datos)
        return datos
    archivos = []
    for root, _dirs, files in os.walk(carpeta):
        for f in files:
            archivos.append(os.path.join(root, f))
            if len(archivos) >= 200: break
        if len(archivos) >= 200: break
    hallazgos = []
    for archivo in archivos:
        try:
            if os.path.getsize(archivo) > 50_000_000: continue
        except OSError:
            continue
        try:
            r = subprocess.run(['yara-rules', '/etc/yara/', archivo],
                              capture_output=True, text=True, timeout=15)
            salida = (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            continue
        except Exception as _e:
            log.warning("yara error: %s", _e)
            continue
        if salida and 'no rules matched' not in salida.lower():
            hallazgos.append({'archivo': archivo, 'resultado': salida[:500]})
            if len(hallazgos) >= 50: break
    datos['resultados']['total_escaneados'] = len(archivos)
    datos['resultados']['con_coincidencias'] = hallazgos
    _guardar_dato(f'yara_bulk_{carpeta}', datos)
    return datos

def _gen_wordlist(objetivo):
    datos = {'tipo':'wordlist','objetivo':objetivo,'resultados':{}}
    datos_osint = json.dumps(case['datos'], default=str)[:3000]
    prompt = f"""Based on the OSINT data collected about "{objetivo}", generate a likely password wordlist.
Include variations of:
- Proper names found
- Important dates
- Company/organization
- Terms related to the target
- Common combinations (name+year, name+123, etc.)
- Leet speak of key terms

Available OSINT data:
{datos_osint}

Generate 30-50 entries. One per line. Only the passwords, no explanation."""
    wordlist = _ai(prompt).strip().split('\n')
    wordlist = [w.strip() for w in wordlist if w.strip() and len(w.strip()) >= 6]
    datos['resultados']['wordlist'] = wordlist
    datos['resultados']['total'] = len(wordlist)
    # Guardar archivo
    path = os.path.join(CASES_DIR, f'wordlist_{re.sub(r"[^a-z0-9]","_",objetivo.lower())}.txt')
    with open(path,'w') as f:
        f.write('\n'.join(wordlist))
    datos['resultados']['archivo'] = path
    _guardar_dato(f'wordlist_{objetivo}', datos)
    return datos

def _sim_escenario(objetivo):
    datos_osint = json.dumps(case['datos'], default=str)[:3500]
    prompt = f"""OSINT collected on "{objetivo}". Generate ethical pentesting scenario:

1. ENTRY VECTORS identified (with evidence from data)
2. PROBABLE KILL CHAIN step by step
3. RELEVANT MITRE ATT&CK TECHNIQUES (with IDs)
4. TOP 3 MOST CRITICAL VULNERABILITIES found
5. SPECIFIC COUNTERMEASURES for each vector
6. NEXT ACTIVE RECONNAISSANCE STEPS

Data: {datos_osint}"""
    return _ai(prompt)

def _sim_superficie(objetivo):
    datos_osint = json.dumps(case['datos'], default=str)[:3500]
    prompt = f"""Attack surface map for "{objetivo}":

1. EXPOSED ASSETS (IPs, domains, services, technologies)
2. LEAKED DATA found
3. TECHNOLOGIES with known CVEs (check versions in data)
4. WEAK CONFIGURATIONS detected
5. RISK SCORE 0-10 with justification
6. HARDENING RECOMMENDATIONS

Data: {datos_osint}"""
    return _ai(prompt)

KALI_TOOLS = {
    'recon': [
        {'id':'nmap',         'nombre':'nmap',         'desc':'Scan ports and services',               'cmd':'nmap -sT -sV --open {arg}',               'placeholder':'IP or domain'},
        {'id':'nmap_full',    'nombre':'nmap full',    'desc':'Full scan with versions and scripts',   'cmd':'nmap -sT -sV -sC {arg}',                  'placeholder':'IP or domain'},
        {'id':'harvester',    'nombre':'theHarvester', 'desc':'Emails and subdomains from OSINT',      'cmd':'theHarvester -d {arg} -b google,bing,duckduckgo', 'placeholder':'domain.com'},
        {'id':'whatweb',      'nombre':'whatweb',      'desc':'Detect website technologies',           'cmd':'whatweb {arg}',                            'placeholder':'http://target.com'},
        {'id':'wafw00f',      'nombre':'wafw00f',      'desc':'Detect WAF firewall',                   'cmd':'wafw00f {arg}',                            'placeholder':'http://target.com'},
        {'id':'dmitry',       'nombre':'dmitry',       'desc':'Full domain reconnaissance',            'cmd':'dmitry -winsepfb {arg}',                   'placeholder':'domain.com'},
        {'id':'whois_kali',   'nombre':'whois',        'desc':'Domain registration info',              'cmd':'whois {arg}',                              'placeholder':'domain.com'},
        {'id':'dig_kali',     'nombre':'dig',          'desc':'Full DNS queries',                      'cmd':'dig {arg} ANY',                            'placeholder':'domain.com'},
    ],
    'web': [
        {'id':'nikto',        'nombre':'nikto',        'desc':'Scan web vulnerabilities',              'cmd':'nikto -h {arg}',                           'placeholder':'http://target.com'},
        {'id':'gobuster',     'nombre':'gobuster',     'desc':'Directory brute force',                 'cmd':'gobuster dir -u {arg} -w /usr/share/wordlists/dirb/common.txt -q', 'placeholder':'http://target.com'},
        {'id':'dirb',         'nombre':'dirb',         'desc':'Find hidden directories',               'cmd':'dirb {arg}',                               'placeholder':'http://target.com'},
        {'id':'sqlmap',       'nombre':'sqlmap',       'desc':'Detect SQL injection',                  'cmd':'sqlmap -u {arg} --batch --dbs',            'placeholder':'http://target.com/page?id=1'},
        {'id':'wfuzz',        'nombre':'wfuzz',        'desc':'Advanced web fuzzing',                  'cmd':'wfuzz -c -w /usr/share/wordlists/dirb/common.txt {arg}/FUZZ', 'placeholder':'http://target.com'},
    ],
    'passwords': [
        {'id':'hashid',       'nombre':'hashid',       'desc':'Identify hash type',                    'cmd':'hashid {arg}',                             'placeholder':'paste hash here'},
        {'id':'john',         'nombre':'john',         'desc':'Crack hash with rockyou',               'cmd':'echo {arg} > /tmp/hash.txt && john /tmp/hash.txt --wordlist=/usr/share/wordlists/rockyou.txt', 'placeholder':'paste hash here'},
        {'id':'hashcat_md5',  'nombre':'hashcat MD5',  'desc':'Crack MD5 hash',                        'cmd':'hashcat -m 0 -a 0 {arg} /usr/share/wordlists/rockyou.txt --force', 'placeholder':'MD5 hash'},
        {'id':'hashcat_sha1', 'nombre':'hashcat SHA1', 'desc':'Crack SHA1 hash',                       'cmd':'hashcat -m 100 -a 0 {arg} /usr/share/wordlists/rockyou.txt --force', 'placeholder':'SHA1 hash'},
        {'id':'crunch',       'nombre':'crunch',       'desc':'Generate custom wordlist',              'cmd':'crunch {arg} | head -50',                  'placeholder':'6 8 abc123'},
        {'id':'cewl',         'nombre':'cewl',         'desc':'Wordlist from website',                 'cmd':'cewl {arg} -d 2 -m 5',                     'placeholder':'http://target.com'},
    ],
    'forensics': [
        {'id':'binwalk',      'nombre':'binwalk',      'desc':'Analyze firmware/binaries',             'cmd':'binwalk {arg}',                            'placeholder':'/path/to/file'},
        {'id':'exiftool_k',   'nombre':'exiftool',     'desc':'File metadata extractor',               'cmd':'exiftool {arg}',                           'placeholder':'/path/to/image.jpg'},
        {'id':'strings_cmd',  'nombre':'strings',      'desc':'Extract strings from binaries',         'cmd':'strings {arg} | head -100',                'placeholder':'/path/to/binary'},
        {'id':'file_cmd',     'nombre':'file',         'desc':'Identify file type',                    'cmd':'file {arg}',                               'placeholder':'/path/to/file'},
        {'id':'steghide_ext', 'nombre':'steghide',     'desc':'Extract hidden data from image',        'cmd':'steghide extract -sf {arg} -p ""',         'placeholder':'/path/to/image.jpg'},
    ],
    'exploits': [
        {'id':'searchsploit', 'nombre':'searchsploit', 'desc':'Search exploits in ExploitDB',          'cmd':'searchsploit {arg}',                       'placeholder':'apache 2.4 or wordpress 5.0'},
        {'id':'msfvenom_lin', 'nombre':'msfvenom Linux','desc':'Generate Linux reverse shell payload', 'cmd':'msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f elf 2>&1 | head -5', 'placeholder':'(no argument needed)'},
    ],
    'network': [
        {'id':'netstat_k',    'nombre':'netstat',      'desc':'Active network connections',            'cmd':'ss -tulnp',                                'placeholder':'(no argument needed)'},
        {'id':'arp_scan',     'nombre':'arp-scan',     'desc':'Discover hosts on local network',       'cmd':'arp-scan {arg}',                           'placeholder':'192.168.1.0/24'},
        {'id':'nc_banner',    'nombre':'netcat banner','desc':'Grab service banner',                   'cmd':'nc -w3 {arg}',                             'placeholder':'IP port (e.g. 192.168.1.1 80)'},
    ],
}

PARROT_TOOLS = {
    'anonymity': [
        {'id':'anonsurf_start', 'nombre':'anonsurf start', 'desc':'Route ALL traffic through Tor',    'cmd':'anonsurf start',                           'placeholder':'(no argument needed)'},
        {'id':'anonsurf_stop',  'nombre':'anonsurf stop',  'desc':'Disable Tor anonymity',            'cmd':'anonsurf stop',                            'placeholder':'(no argument needed)'},
        {'id':'anonsurf_ip',    'nombre':'my anon IP',     'desc':'Show current public IP via Tor',   'cmd':'anonsurf myip',                            'placeholder':'(no argument needed)'},
    ],
    'osint': [
        {'id':'spiderfoot',     'nombre':'spiderfoot',     'desc':'Full automated OSINT',             'cmd':'spiderfoot -s {arg} -m all -q 2>&1 | head -80', 'placeholder':'domain.com or IP'},
        {'id':'masscan',        'nombre':'masscan',        'desc':'Ultra-fast port scanner',          'cmd':'masscan {arg} -p1-1024 --rate=500 2>&1',   'placeholder':'192.168.1.0/24'},
        {'id':'amass',          'nombre':'amass',          'desc':'Advanced subdomain enumeration',   'cmd':'amass enum -passive -d {arg} 2>&1 | head -50', 'placeholder':'domain.com'},
    ],
    'wifi': [
        {'id':'wifite',         'nombre':'wifite',         'desc':'Automated WiFi auditing',          'cmd':'wifite --kill --all 2>&1 | head -40',      'placeholder':'(no argument needed)'},
        {'id':'wifiphisher',    'nombre':'wifiphisher',    'desc':'Advanced evil twin attack',        'cmd':'wifiphisher --essid {arg} 2>&1 | head -30', 'placeholder':'WiFi network name'},
    ],
    'passwords': [
        {'id':'crunch_p',       'nombre':'crunch',         'desc':'Generate custom wordlist',         'cmd':'crunch {arg} | head -100',                 'placeholder':'6 8 abc123'},
        {'id':'cewl_p',         'nombre':'cewl',           'desc':'Wordlist from website',            'cmd':'cewl {arg} -d 2 -m 5',                     'placeholder':'http://target.com'},
        {'id':'medusa',         'nombre':'medusa',         'desc':'Network service brute force',      'cmd':'medusa -h {arg} -M ssh 2>&1 | head -30',   'placeholder':'IP user'},
    ],
    'forensics': [
        {'id':'faraday_p',      'nombre':'faraday',        'desc':'Vulnerability management dashboard','cmd':'faraday-server --port 5985 &',             'placeholder':'(no argument needed)'},
        {'id':'autopsy_p',      'nombre':'autopsy',        'desc':'Full forensic suite with GUI',     'cmd':'autopsy',                                  'placeholder':'(no argument needed)'},
    ],
}

REMNUX_TOOLS = {
    'malware': [
        {'id':'capa',           'nombre':'capa',           'desc':'Detect malware capabilities',      'cmd':'capa {arg}',                               'placeholder':'/path/to/malware.exe'},
        {'id':'manalyze',       'nombre':'manalyze',       'desc':'Analyze PE binary for malware',    'cmd':'manalyze {arg}',                           'placeholder':'/path/to/malware.exe'},
        {'id':'peframe',        'nombre':'peframe',        'desc':'PE file internal structure',       'cmd':'peframe {arg}',                            'placeholder':'/path/to/malware.exe'},
        {'id':'speakeasy',      'nombre':'speakeasy',      'desc':'Emulate malware without running',  'cmd':'speakeasy -t {arg} -o /tmp/speakeasy_out.json && cat /tmp/speakeasy_out.json', 'placeholder':'/path/to/malware.exe'},
        {'id':'flarestrings',   'nombre':'flarestrings',   'desc':'Smart string extraction from malware','cmd':'flarestrings {arg}',                    'placeholder':'/path/to/malware.exe'},
    ],
    'documents': [
        {'id':'olevba',         'nombre':'olevba',         'desc':'Extract VBA macros from Office docs','cmd':'olevba {arg}',                           'placeholder':'/path/to/document.doc'},
        {'id':'oledump',        'nombre':'oledump',        'desc':'Analyze internal OLE structure',   'cmd':'oledump.py {arg}',                         'placeholder':'/path/to/document.doc'},
        {'id':'mraptor',        'nombre':'mraptor',        'desc':'Detect malicious macros',          'cmd':'mraptor {arg}',                            'placeholder':'/path/to/document.doc'},
        {'id':'vmonkey',        'nombre':'vmonkey',        'desc':'Emulate VBA macros safely',        'cmd':'vmonkey {arg}',                            'placeholder':'/path/to/document.doc'},
        {'id':'pdfid',          'nombre':'pdfid',          'desc':'Detect dangerous elements in PDF', 'cmd':'pdfid.py {arg}',                           'placeholder':'/path/to/document.pdf'},
        {'id':'pdfparser',      'nombre':'pdf-parser',     'desc':'Full PDF structure analysis',      'cmd':'pdf-parser.py {arg}',                      'placeholder':'/path/to/document.pdf'},
        {'id':'peepdf',         'nombre':'peepdf',         'desc':'Deep analysis of malicious PDFs',  'cmd':'peepdf -f {arg}',                          'placeholder':'/path/to/document.pdf'},
    ],
    'analysis': [
        {'id':'vol3',           'nombre':'volatility3',    'desc':'RAM memory dump analysis',         'cmd':'vol3 -f {arg} windows.pslist 2>&1 | head -50', 'placeholder':'/path/to/memory.raw'},
        {'id':'binwalk_r',      'nombre':'binwalk',        'desc':'Analyze and extract firmware',     'cmd':'binwalk {arg}',                            'placeholder':'/path/to/file.bin'},
        {'id':'yara',           'nombre':'yara-rules',     'desc':'Detect malware families with YARA','cmd':'yara-rules /etc/yara/ {arg} 2>&1 | head -30', 'placeholder':'/path/to/malware.exe'},
        {'id':'strings_r',      'nombre':'strings',        'desc':'Extract text from any binary',     'cmd':'strings {arg} | grep -E "http|cmd|pass|key|token" | head -50', 'placeholder':'/path/to/file'},
        {'id':'exiftool_r',     'nombre':'exiftool',       'desc':'Full metadata from any file',      'cmd':'exiftool {arg}',                           'placeholder':'/path/to/file'},
    ],
    'crypto': [
        {'id':'xortool',        'nombre':'xortool',        'desc':'Analyze and decrypt XOR data',     'cmd':'xortool {arg}',                            'placeholder':'/path/to/file.bin'},
        {'id':'chepy',          'nombre':'chepy',          'desc':'Crypto ops: base64, hex, etc.',    'cmd':'chepy {arg} b64_decode str_to_hex',        'placeholder':'text or file'},
        {'id':'trid',           'nombre':'trid',           'desc':'Identify real file type',          'cmd':'trid {arg}',                               'placeholder':'/path/to/file'},
    ],
}

BLACKARCH_TOOLS = {
    'recon': [
        {'id':'nmap',        'nombre':'nmap',        'desc':'Port and service scanner',                    'cmd':'nmap -sT -sV --open {arg}',                       'placeholder':'IP or domain'},
        {'id':'rustscan',    'nombre':'rustscan',    'desc':'Ultrafast scanner, passes results to nmap',   'cmd':'rustscan -a {arg} -- -sV -sC',                    'placeholder':'IP or range'},
        {'id':'masscan',     'nombre':'masscan',     'desc':'Mass scan millions of IPs per second',        'cmd':'masscan {arg} -p1-65535 --rate=1000',             'placeholder':'IP or CIDR'},
        {'id':'amass',       'nombre':'amass',       'desc':'Subdomain enumeration and ASN mapping',       'cmd':'amass enum -d {arg}',                             'placeholder':'domain.com'},
        {'id':'subfinder',   'nombre':'subfinder',   'desc':'Passive subdomain discovery',                 'cmd':'subfinder -d {arg}',                              'placeholder':'domain.com'},
        {'id':'dnsx',        'nombre':'dnsx',        'desc':'Mass DNS resolution with response filtering', 'cmd':'echo {arg} | dnsx -a -resp',                      'placeholder':'domain.com'},
        {'id':'httpx',       'nombre':'httpx',       'desc':'HTTP probing with tech detection',            'cmd':'echo {arg} | httpx-pd -title -tech-detect -sc',   'placeholder':'domain.com'},
    ],
    'web': [
        {'id':'gobuster',    'nombre':'gobuster',    'desc':'Directory and file brute force',              'cmd':'gobuster dir -u {arg} -w /usr/share/wordlists/dirb/common.txt', 'placeholder':'https://target.com'},
        {'id':'ffuf',        'nombre':'ffuf',        'desc':'Fast web fuzzer with filters',                'cmd':'ffuf -u {arg}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302', 'placeholder':'https://target.com'},
        {'id':'feroxbuster', 'nombre':'feroxbuster', 'desc':'Recursive auto fuzzer (Rust)',                'cmd':'feroxbuster -u {arg} -w /usr/share/wordlists/dirb/common.txt', 'placeholder':'https://target.com'},
        {'id':'nuclei',      'nombre':'nuclei',      'desc':'Vulnerability scanner using templates',       'cmd':'nuclei -u {arg} -severity medium,high,critical',  'placeholder':'https://target.com'},
        {'id':'sqlmap',      'nombre':'sqlmap',      'desc':'Automated SQL injection detection',           'cmd':'sqlmap -u {arg} --dbs --batch --level=2',          'placeholder':'https://target.com/page?id=1'},
    ],
    'passwords': [
        {'id':'hashcat',     'nombre':'hashcat',     'desc':'GPU/CPU hash cracker — all modes',            'cmd':'hashcat -m 0 {arg} /opt/wordlists/rockyou.txt',   'placeholder':'hash.txt or hash value'},
        {'id':'john',        'nombre':'john',        'desc':'John the Ripper — hashes and files',          'cmd':'john --wordlist=/opt/wordlists/rockyou.txt {arg}', 'placeholder':'hash.txt'},
    ],
    'windows': [
        {'id':'cme_smb',     'nombre':'crackmapexec smb',   'desc':'SMB recon and attack on AD',          'cmd':'cme smb {arg} --shares',                          'placeholder':'IP or 192.168.1.0/24'},
        {'id':'cme_ldap',    'nombre':'crackmapexec ldap',  'desc':'LDAP enumeration on Active Directory','cmd':'cme ldap {arg} -u "" -p "" --users',              'placeholder':'domain-controller-IP'},
        {'id':'evil_winrm',  'nombre':'evil-winrm',         'desc':'WinRM shell for Windows targets',     'cmd':'evil-winrm -i {arg} -u Administrator',            'placeholder':'target-IP'},
        {'id':'responder',   'nombre':'responder',          'desc':'LLMNR/NBT-NS poisoning — capture hashes','cmd':'sudo responder -I eth0 -wv',                  'placeholder':'(run on local network)'},
        {'id':'psexec',      'nombre':'impacket-psexec',    'desc':'Remote exec via SMB with credentials','cmd':'impacket-psexec {arg}',                           'placeholder':'domain/user:pass@IP'},
        {'id':'secretsdump', 'nombre':'secretsdump',        'desc':'Dump SAM, LSA, NTDS.dit remotely',   'cmd':'impacket-secretsdump {arg}',                      'placeholder':'domain/user:pass@IP'},
    ],
    'wireless': [
        {'id':'airmon',      'nombre':'airmon-ng',   'desc':'Enable monitor mode on WiFi adapter',        'cmd':'sudo airmon-ng start {arg}',                      'placeholder':'wlan0'},
        {'id':'airodump',    'nombre':'airodump-ng', 'desc':'Capture WiFi packets and handshakes',        'cmd':'sudo airodump-ng {arg}',                          'placeholder':'wlan0mon'},
        {'id':'aircrack',    'nombre':'aircrack-ng', 'desc':'Crack WPA/WEP captured handshakes',          'cmd':'aircrack-ng -w /opt/wordlists/rockyou.txt {arg}', 'placeholder':'capture.cap'},
    ],
    'forensics': [
        {'id':'volatility',  'nombre':'volatility3', 'desc':'RAM memory forensics analysis',              'cmd':'vol -f {arg} windows.pslist',                     'placeholder':'/path/to/memory.dmp'},
        {'id':'vol_netscan', 'nombre':'vol netscan', 'desc':'Network connections from memory dump',       'cmd':'vol -f {arg} windows.netscan',                    'placeholder':'/path/to/memory.dmp'},
        {'id':'vol_cmdline', 'nombre':'vol cmdline', 'desc':'Command lines executed from memory',         'cmd':'vol -f {arg} windows.cmdline',                    'placeholder':'/path/to/memory.dmp'},
    ],
}

def _distrobox_run(distro, tool_dict, tool_id, arg):
    """Ejecuta herramienta en un contenedor distrobox"""
    tool = None
    for cat in tool_dict.values():
        for t in cat:
            if t['id'] == tool_id:
                tool = t
                break
    if not tool:
        return {'error': f'Unknown tool: {tool_id}'}
    if not _objetivo_seguro(arg):
        return {'error': 'Argumento inválido: contiene caracteres no permitidos'}
    cmd = tool['cmd'].replace('{arg}', arg.strip())
    resultado = _cmd(f'distrobox enter {distro} -- bash -c "{cmd}"', timeout=90)
    return {'tool': tool['nombre'], 'cmd': cmd, 'output': resultado}

def _kali_run(tool_id, arg):
    """Ejecuta una herramienta de Kali dentro del contenedor distrobox"""
    tool = None
    for cat in KALI_TOOLS.values():
        for t in cat:
            if t['id'] == tool_id:
                tool = t
                break

    if not tool:
        return {'error': f'Unknown tool: {tool_id}'}

    cmd_template = tool['cmd']
    if not _objetivo_seguro(arg):
        return {'error': 'Argumento inválido: contiene caracteres no permitidos'}
    cmd = cmd_template.replace('{arg}', arg.strip())

    full_cmd = f'distrobox enter kali -- bash -c "{cmd}"'
    resultado = _cmd(full_cmd, timeout=60)
    return {
        'tool': tool['nombre'],
        'cmd': cmd,
        'output': resultado
    }

def _check_url(url):
    """Analiza URL con VirusTotal (si hay key) o heurísticas locales"""
    datos = {'tipo': 'url_check', 'url': url, 'resultados': {}}
    score = 0
    flags = []

    # Heurísticas de phishing
    u = url.lower()
    dominios_legitimos = ['paypal','amazon','google','facebook','microsoft','apple','netflix','bancomer','banamex','bbva','santander']
    for marca in dominios_legitimos:
        if marca in u and marca + '.com' not in u:
            flags.append(f'Posible phishing de {marca} (marca en URL pero dominio diferente)')
            score += 30

    sospechosos = ['login','secure','verify','account','update','confirm','signin','banking','wallet','password']
    for kw in sospechosos:
        if kw in u:
            flags.append(f'Keyword sospechosa: {kw}')
            score += 10

    if u.count('.') > 4:
        flags.append(f'Muchos subdominios ({u.count(".")} puntos)')
        score += 15

    if any(x in u for x in ['-paypal','-amazon','-google','-apple','-microsoft']):
        flags.append('Guion con marca conocida — phishing probable')
        score += 40

    if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', u):
        flags.append('URL con IP directa (no dominio)')
        score += 25

    if len(url) > 100:
        flags.append(f'URL muy larga ({len(url)} caracteres)')
        score += 10

    tlds_raros = ['.xyz','.top','.gq','.ml','.cf','.tk','.pw','.cc']
    for tld in tlds_raros:
        if tld in u:
            flags.append(f'TLD sospechoso: {tld}')
            score += 20

    # VirusTotal si hay API key
    vt_key = os.environ.get('VT_API_KEY','')
    if vt_key:
        try:
            import base64
            url_b64 = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
            r = SESSION.get(f'https://www.virustotal.com/api/v3/urls/{url_b64}',
                          headers={'x-apikey': vt_key}, timeout=10)
            if r.status_code == 200:
                stats = r.json().get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                datos['resultados']['virustotal'] = {
                    'malicioso': malicious, 'sospechoso': suspicious,
                    'limpio': stats.get('undetected', 0)
                }
                if malicious > 0:
                    flags.append(f'VirusTotal: {malicious} motores lo marcan como MALICIOSO')
                    score += 50
        except Exception as _e: log.debug("fuente no disponible: %s", _e)

    # AbuseIPDB para la IP del dominio
    try:
        dominio = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
        ip_check = socket.gethostbyname(dominio)
        abuse_key = os.environ.get('ABUSEIPDB_KEY','')
        if abuse_key:
            r = SESSION.get('https://api.abuseipdb.com/api/v2/check',
                          headers={'Key': abuse_key, 'Accept': 'application/json'},
                          params={'ipAddress': ip_check, 'maxAgeInDays': 90}, timeout=8)
            if r.status_code == 200:
                d2 = r.json().get('data', {})
                ab_score = d2.get('abuseConfidenceScore', 0)
                datos['resultados']['abuseipdb'] = {'ip': ip_check, 'abuse_score': ab_score, 'reportes': d2.get('totalReports',0)}
                if ab_score > 50:
                    flags.append(f'AbuseIPDB: IP con {ab_score}% de confianza de abuso')
                    score += 30
        else:
            datos['resultados']['ip_dominio'] = ip_check
    except Exception as _e: log.debug("fuente no disponible: %s", _e)

    score = min(score, 100)
    nivel = 'CRITICAL' if score >= 70 else 'HIGH' if score >= 40 else 'MEDIUM' if score >= 20 else 'LOW'
    datos['resultados']['score_phishing'] = score
    datos['resultados']['nivel_riesgo'] = nivel
    datos['resultados']['flags'] = flags
    _guardar_dato(f'url_check_{url[:50]}', datos)
    return datos

def _analizar_password(password):
    """Analyze password strength locally without sending it to any server"""
    datos = {'tipo': 'password', 'resultados': {}}
    score = 0
    problemas = []
    puntos_fuertes = []

    long = len(password)
    if long < 8:
        problemas.append(f'Too short ({long} chars — minimum 8)')
    elif long < 12:
        puntos_fuertes.append(f'Acceptable length ({long} chars)')
        score += 10
    else:
        puntos_fuertes.append(f'Good length ({long} chars)')
        score += 20

    if re.search(r'[a-z]', password): score += 10; puntos_fuertes.append('Lowercase letters')
    else: problemas.append('No lowercase letters')
    if re.search(r'[A-Z]', password): score += 15; puntos_fuertes.append('Uppercase letters')
    else: problemas.append('No uppercase letters')
    if re.search(r'[0-9]', password): score += 10; puntos_fuertes.append('Numbers')
    else: problemas.append('No numbers')
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]', password): score += 20; puntos_fuertes.append('Special symbols')
    else: problemas.append('No special symbols')

    comunes = ['123456','password','qwerty','abc123','111111','letmein','admin','welcome','monkey','dragon']
    if password.lower() in comunes:
        problemas.append('Password found in most common passwords list')
        score = max(0, score - 40)

    if re.search(r'(.)\1{2,}', password):
        problemas.append('Repeated characters (aaa, 111)')
        score = max(0, score - 10)

    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()):
        problemas.append('Obvious sequence (123, abc)')
        score = max(0, score - 10)

    # Entropía aproximada
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    import math
    entropia = round(long * math.log2(charset), 1) if charset > 0 else 0

    # Tiempo de crackeo aproximado (bcrypt 10k hashes/s)
    combinaciones = charset ** long if charset > 0 else 1
    segundos = combinaciones / 20000
    if segundos < 60: tiempo = f'{int(segundos)}s'
    elif segundos < 3600: tiempo = f'{int(segundos/60)}min'
    elif segundos < 86400: tiempo = f'{int(segundos/3600)}h'
    elif segundos < 31536000: tiempo = f'{int(segundos/86400)} days'
    else: tiempo = f'{int(segundos/31536000)} years'

    score = min(score, 100)
    nivel = 'VERY STRONG' if score >= 75 else 'STRONG' if score >= 55 else 'MEDIUM' if score >= 35 else 'WEAK'

    datos['resultados'] = {
        'score': score, 'nivel': nivel, 'longitud': long,
        'entropia_bits': entropia, 'tiempo_crackeo': tiempo,
        'puntos_fuertes': puntos_fuertes, 'problemas': problemas
    }
    return datos

def _cve_correlacion(tecnologias):
    prompt = f"""For the following technologies found in OSINT, list the most critical known CVEs:
{tecnologias}

For each technology:
- CVE ID
- Severity (CVSS)
- Brief description
- Whether it is remotely exploitable

Only real, documented CVEs."""
    return _ai(prompt)

def _analizar_todo():
    if not case['datos']:
        return 'No data collected yet.'
    datos_str = json.dumps(case['datos'], default=str)[:4500]
    prompt = f"""Full OSINT intelligence analysis on "{case.get('objetivo','?')}":

1. EXECUTIVE SUMMARY (3 lines max)
2. CRITICAL FINDINGS [!]
3. CONNECTIONS AND PATTERNS in the data
4. COMPLETE TARGET PROFILE
5. SECURITY RISKS identified and prioritized
6. RECOMMENDED NEXT STEPS

Data: {datos_str}"""
    return _ai(prompt)

def _build_grafo():
    """Convierte case['datos'] en nodos y aristas para vis.js"""
    nodes = {}  # id -> {id, label, title, group}
    edges = []
    eid   = [0]

    COLORES = {
        'objetivo':   '#d99a4e',
        'dominio':    '#5b9bd5',
        'subdominio': '#7fb8d9',
        'ip':         '#d9564b',
        'email':      '#6fae7c',
        'usuario':    '#cc9a3c',
        'plataforma': '#c17a52',
        'org':        '#b07a9e',
        'pais':       '#7a85b0',
        'bucket':     '#d9564b',
        'repo':       '#d99a4e',
        'cve':        '#d9564b',
        'subdominio_vuln': '#d9564b',
        'tech':       '#5fa8a0',
    }

    def nid(val):
        return hashlib.md5(str(val).encode()).hexdigest()[:10]

    def add_node(id_, label, grupo, title='', size=20):
        label = str(label) if label is not None else '?'
        if id_ not in nodes:
            nodes[id_] = {
                'id': id_, 'label': label[:30], 'title': title or label,
                'group': grupo, 'color': COLORES.get(grupo,'#8b8b98'),
                'size': size, 'font': {'color':'#e8e8ee','size':11}
            }

    def add_edge(src, dst, label=''):
        eid[0] += 1
        edges.append({'id': eid[0], 'from': src, 'to': dst,
                      'label': label, 'color': '#3a3a46',
                      'font': {'color':'#8b8b98','size':9}})

    # Nodo raíz — objetivo
    obj = case.get('objetivo') or '?'
    obj_id = nid(obj)
    add_node(obj_id, obj, 'objetivo', f'Objetivo: {obj}', size=35)

    for clave, valor in case['datos'].items():
        if not isinstance(valor, dict): continue
        res = valor.get('resultados', {})
        tipo = valor.get('tipo', '')

        # ── DOMINIO ──────────────────────────────────────────────
        if tipo == 'dominio':
            dom = valor.get('objetivo','')
            dom_id = nid('dom_'+dom)
            add_node(dom_id, dom, 'dominio', f'Dominio: {dom}', size=28)
            add_edge(obj_id, dom_id, 'dominio')

            for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', str(res.get('dns',{}).get('A',''))):
                iid = nid('ip_'+ip)
                add_node(iid, ip, 'ip', f'IP: {ip}')
                add_edge(dom_id, iid, 'A')

            for sub in res.get('subdominios',[])[:15]:
                sid = nid('sub_'+sub)
                add_node(sid, sub, 'subdominio', f'Subdominio: {sub}')
                add_edge(dom_id, sid, 'subdominio')

            for email in res.get('emails',[])[:10]:
                eid2 = nid('mail_'+email)
                add_node(eid2, email, 'email', f'Email: {email}')
                add_edge(dom_id, eid2, 'email')

            for h, v2 in res.get('tecnologias',{}).items():
                tid = nid('tech_'+v2)
                add_node(tid, v2[:20], 'tech', f'{h}: {v2}')
                add_edge(dom_id, tid, h.lower())

        # ── PASSIVE DNS ──────────────────────────────────────────
        elif tipo == 'passivedns':
            dom = valor.get('objetivo','')
            dom_id = nid('dom_'+dom)
            add_node(dom_id, dom, 'dominio', f'Dominio: {dom}', size=28)
            for h in res.get('historial', [])[:15]:
                ip_h = h.get('ip')
                if not ip_h: continue
                iid3 = nid('ip_'+ip_h)
                add_node(iid3, ip_h, 'ip', f'IP histórica ({h.get("fecha","?")})')
                add_edge(dom_id, iid3, f'resolvió {h.get("fecha","?")}')

        # ── IP ────────────────────────────────────────────────────
        elif tipo == 'ip':
            ip = valor.get('objetivo','')
            iid = nid('ip_'+ip)
            add_node(iid, ip, 'ip', f'IP: {ip}', size=25)
            add_edge(obj_id, iid, 'ip')
            geo = res.get('geo',{})
            if geo.get('country'):
                cid = nid('pais_'+geo['country'])
                add_node(cid, geo['country'], 'pais', f"Country: {geo['country']}")
                add_edge(iid, cid, 'location')
            if geo.get('org'):
                oid2 = nid('org_'+geo['org'])
                add_node(oid2, geo['org'][:25], 'org', f"Org: {geo['org']}")
                add_edge(iid, oid2, 'org')
            if res.get('ptr'):
                pid = nid('ptr_'+res['ptr'])
                add_node(pid, res['ptr'][:25], 'dominio', f"PTR: {res['ptr']}")
                add_edge(iid, pid, 'PTR')

        # ── FAVICON HASH ─────────────────────────────────────────
        elif tipo == 'favicon':
            dom = valor.get('objetivo','')
            for m in res.get('relacionados', [])[:15]:
                ip_f = m.get('ip')
                if not ip_f: continue
                iid2 = nid('favinfra_'+ip_f)
                org = m.get('org') or '?'
                add_node(iid2, ip_f, 'ip', f"Mismo favicon que {dom} — {org}", size=22)
                add_edge(obj_id, iid2, 'favicon compartido')

        # ── USUARIO ───────────────────────────────────────────────
        elif tipo == 'usuario':
            user = valor.get('objetivo','')
            uid = nid('user_'+user)
            add_node(uid, '@'+user, 'usuario', f'Usuario: {user}', size=28)
            add_edge(obj_id, uid, 'usuario')
            for p in res.get('plataformas',[]) + res.get('maigret',[]):
                plat = p.get('plataforma','?')
                pid2 = nid('plat_'+plat+user)
                add_node(pid2, plat, 'plataforma', p.get('url',''))
                add_edge(uid, pid2, 'perfil')
            gh = res.get('github',{})
            if gh.get('email') and gh['email'] != 'oculto':
                eid3 = nid('mail_'+gh['email'])
                add_node(eid3, gh['email'], 'email', f"GitHub email: {gh['email']}")
                add_edge(uid, eid3, 'email')
            for repo in res.get('github_repos',[])[:5]:
                rid = nid('repo_'+repo['nombre'])
                add_node(rid, repo['nombre'][:20], 'repo', f"⭐{repo['stars']} {repo['lenguaje']}")
                add_edge(uid, rid, 'repo')

        # ── EMAIL ─────────────────────────────────────────────────
        elif tipo == 'email':
            email = valor.get('objetivo','')
            eid4 = nid('mail_'+email)
            add_node(eid4, email, 'email', f'Email: {email}', size=25)
            add_edge(obj_id, eid4, 'email')
            sec = res.get('email_sec',{})
            if sec.get('spoofable'):
                sid2 = nid('spoof_'+email)
                add_node(sid2, '⚠ Spoofable', 'cve', 'Dominio vulnerable a spoofing')
                add_edge(eid4, sid2, 'riesgo')
            for breach in res.get('hibp_breaches',[])[:5]:
                bid = nid('breach_'+breach)
                add_node(bid, breach, 'cve', f'Breach: {breach}')
                add_edge(eid4, bid, 'filtrado en')

        # ── BUCKETS ───────────────────────────────────────────────
        elif tipo == 'buckets':
            for bucket in res.get('buckets',[]):
                bid2 = nid('bucket_'+bucket['bucket'])
                label = ('🔓 ' if bucket['publico'] else '🔒 ') + bucket['bucket']
                add_node(bid2, label, 'bucket', bucket['url'])
                add_edge(obj_id, bid2, 'bucket')

        # ── SUBDOMAIN TAKEOVER ────────────────────────────────────
        elif tipo == 'subdomain_takeover':
            for v2 in res.get('vulnerables',[]):
                vid = nid('vuln_'+v2['subdominio'])
                add_node(vid, '💀 '+v2['subdominio'][:20], 'subdominio_vuln',
                         f"Takeover via {v2['servicio']}: {v2['status']}")
                add_edge(obj_id, vid, 'takeover')

        # ── TYPOSQUATTING ─────────────────────────────────────────
        elif tipo == 'typosquatting':
            for dom2 in res.get('registrados',[]):
                tid2 = nid('typo_'+dom2['dominio'])
                add_node(tid2, '🎭 '+dom2['dominio'], 'subdominio',
                         f"IP: {dom2['ip']}")
                add_edge(obj_id, tid2, 'typosquat')

        # ── GITHUB SECRETS ────────────────────────────────────────
        elif tipo == 'github_secrets':
            for h in res.get('hallazgos',[])[:8]:
                hid = nid('secret_'+h['repo']+h['tipo'])
                add_node(hid, f"🔑 {h['tipo']}", 'cve',
                         f"{h['repo']} @{h['commit']}: {h['valor']}")
                add_edge(obj_id, hid, 'secreto expuesto')

    return {
        'nodes': list(nodes.values()),
        'edges': edges,
        'stats': {
            'nodos': len(nodes),
            'conexiones': len(edges),
            'objetivo': obj
        }
    }

# ── Cámara + Búsqueda Facial ──────────────────────────────────────────────────

# ── Dark Web Monitor ──────────────────────────────────────────────────────────

def _darkweb_search(query):
    datos = {'tipo': 'darkweb', 'objetivo': query, 'resultados': {}}

    # Ahmia — indexa .onion sin necesitar Tor
    try:
        r = SESSION.get(f'https://ahmia.fi/search/?q={requests.utils.quote(query)}', timeout=12)
        resultados = []
        for match in re.finditer(r'<h4[^>]*><a href="([^"]+)"[^>]*>([^<]+)</a></h4>.*?<p[^>]*>([^<]*)</p>',
                                  r.text, re.DOTALL):
            resultados.append({'url': match.group(1), 'titulo': match.group(2).strip(),
                               'descripcion': match.group(3).strip()[:200]})
        datos['resultados']['ahmia'] = resultados[:15]
    except Exception as e:
        datos['resultados']['ahmia_error'] = str(e)

    # Pastes — Pastebin y similares públicos
    try:
        r = SESSION.get(f'https://psbdmp.ws/api/v3/search/{requests.utils.quote(query)}', timeout=8)
        if r.status_code == 200:
            pastes = r.json().get('data', [])[:10]
            datos['resultados']['pastes'] = [{'id': p.get('id'), 'title': p.get('title','?'),
                                               'url': f"https://pastebin.com/{p.get('id')}"} for p in pastes]
    except Exception as _e: log.debug("fuente no disponible: %s", _e)

    # IntelligenceX (sin API key — búsqueda básica)
    try:
        r = SESSION.post('https://2.intelx.io/intelligent/search',
            json={'term': query, 'maxresults': 10, 'media': 0, 'sort': 2, 'terminate': []},
            headers={'x-key': 'PUBLIC'}, timeout=10)
        if r.status_code == 200:
            datos['resultados']['intelx_id'] = r.json().get('id','')
    except Exception as _e: log.debug("fuente no disponible: %s", _e)

    _guardar_dato(f'darkweb_{query}', datos)
    return datos

# ── Netlas ────────────────────────────────────────────────────────────────────

NETLAS_KEY = os.environ.get('NETLAS_API_KEY', '')

def _netlas_search(query):
    datos = {'tipo': 'netlas', 'objetivo': query, 'resultados': {}}
    if not NETLAS_KEY:
        datos['resultados']['nota'] = 'Add a free Netlas API key (50 searches/day at netlas.io) for infrastructure search'
        _guardar_dato(f'netlas_{query}', datos)
        return datos
    try:
        r = SESSION.get('https://app.netlas.io/api/responses/',
                       params={'q': query, 'fields': 'ip,host,port,protocol,geo,whois'},
                       headers={'Authorization': f'Bearer {NETLAS_KEY}'}, timeout=15)
        d = r.json()
        items = d.get('items', [])
        datos['resultados']['total'] = len(items)
        datos['resultados']['matches'] = [{
            'ip': it.get('data',{}).get('ip'),
            'host': it.get('data',{}).get('host'),
            'puerto': it.get('data',{}).get('port'),
            'protocolo': it.get('data',{}).get('protocol'),
            'pais': (it.get('data',{}).get('geo') or {}).get('country_name'),
            'org': (it.get('data',{}).get('whois') or {}).get('org'),
        } for it in items[:10]]
    except Exception as e:
        datos['resultados']['error'] = str(e)
    _guardar_dato(f'netlas_{query}', datos)
    return datos

# ── Shodan ────────────────────────────────────────────────────────────────────

SHODAN_KEY = os.environ.get('SHODAN_API_KEY', '')

def _shodan_search(query):
    datos = {'tipo': 'shodan', 'objetivo': query, 'resultados': {}}
    if not SHODAN_KEY:
        # Sin API key — usar Censys como alternativa gratuita
        try:
            r = SESSION.get(f'https://search.censys.io/api/v1/search/ipv4?q={requests.utils.quote(query)}&fields=ip,ports,autonomous_system.name,location.country',
                          timeout=10)
            if r.status_code == 200:
                d = r.json()
                datos['resultados']['censys'] = d.get('results', [])[:10]
            else:
                # Fallback: búsqueda en Shodan web pública (limitada)
                r2 = SESSION.get(f'https://internetdb.shodan.io/{query}', timeout=8)
                if r2.status_code == 200:
                    datos['resultados']['internetdb'] = r2.json()
                else:
                    datos['resultados']['nota'] = 'Add a Shodan API key (free at shodan.io) for full search results'
        except Exception as e:
            try:
                r2 = SESSION.get(f'https://internetdb.shodan.io/{query}', timeout=8)
                if r2.status_code == 200:
                    datos['resultados']['internetdb'] = r2.json()
                else:
                    datos['resultados']['nota'] = 'Add Shodan API key for full search results'
            except Exception as e2:
                datos['resultados']['error'] = f'Shodan no disponible: {e2}. (Con una API key gratis en shodan.io tienes búsqueda completa.)'
        # Banner grab manual de IPs encontradas
        ips = []
        for modulo in case['datos'].values():
            if isinstance(modulo, dict):
                res = modulo.get('resultados', {})
                for k, v in res.items():
                    if 'dns' in k.lower() or 'ip' in k.lower():
                        encontradas = re.findall(r'\d+\.\d+\.\d+\.\d+', str(v))
                        ips.extend(encontradas)
        ips = list(set(ips))[:5]
        banners = {}
        for ip in ips:
            out = _cmd(f'nc -w2 -z -v {ip} 80 2>&1; nc -w2 -z -v {ip} 443 2>&1; nc -w2 -z -v {ip} 22 2>&1', timeout=10)
            banners[ip] = out[:300]
        datos['resultados']['banners'] = banners
    else:
        try:
            r = SESSION.get(f'https://api.shodan.io/shodan/host/search?key={SHODAN_KEY}&query={requests.utils.quote(query)}', timeout=10)
            d = r.json()
            datos['resultados']['total'] = d.get('total', 0)
            datos['resultados']['matches'] = [{
                'ip': m.get('ip_str'), 'puerto': m.get('port'),
                'org': m.get('org'), 'pais': m.get('location',{}).get('country_name'),
                'banner': m.get('data','')[:200]
            } for m in d.get('matches', [])[:10]]
        except Exception as e:
            datos['resultados']['error'] = str(e)
    _guardar_dato(f'shodan_{query}', datos)
    return datos

def _shodan_ip(ip):
    datos = {'tipo': 'shodan_ip', 'objetivo': ip, 'resultados': {}}
    if not SHODAN_KEY:
        out = run_tool(['nmap','-sV','-T4','--top-ports','50',ip], timeout=60)
        datos['resultados']['nmap_full'] = out
    else:
        try:
            r = SESSION.get(f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}', timeout=10)
            d = r.json()
            datos['resultados'] = {
                'org': d.get('org'), 'pais': d.get('country_name'),
                'puertos': d.get('ports', []),
                'vulns': list(d.get('vulns', {}).keys()),
                'servicios': [{'puerto': s.get('port'), 'banner': s.get('data','')[:150]}
                              for s in d.get('data', [])[:10]]
            }
        except Exception as e:
            datos['resultados']['error'] = str(e)
    _guardar_dato(f'shodan_ip_{ip}', datos)
    return datos

# ── Timeline ──────────────────────────────────────────────────────────────────

def _build_timeline():
    eventos = []
    DATE_PATTERNS = [
        r'(\d{4}-\d{2}-\d{2})',
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})',
        r'(\d{2}/\d{2}/\d{4})',
        r'(\d{4}\d{2}\d{2})',
    ]
    for clave, valor in case['datos'].items():
        texto = json.dumps(valor, default=str)
        tipo  = valor.get('tipo', clave) if isinstance(valor, dict) else clave
        objetivo = valor.get('objetivo', '') if isinstance(valor, dict) else ''
        for pat in DATE_PATTERNS:
            for fecha in re.findall(pat, texto):
                try:
                    if len(fecha) == 8:
                        fecha_fmt = f"{fecha[:4]}-{fecha[4:6]}-{fecha[6:]}"
                    else:
                        fecha_fmt = fecha[:10]
                    dt = datetime.datetime.strptime(fecha_fmt[:10], '%Y-%m-%d')
                    eventos.append({
                        'fecha': fecha_fmt[:10], 'timestamp': dt.timestamp(),
                        'modulo': tipo, 'objetivo': objetivo,
                        'descripcion': f'{tipo}: {objetivo or clave}'
                    })
                except Exception as _e: log.debug("fuente no disponible: %s", _e)
    # Agregar historial de módulos ejecutados
    for h in case.get('historial', []):
        ts = h.get('ts', 0)
        eventos.append({
            'fecha': datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M'),
            'timestamp': ts, 'modulo': 'ejecucion',
            'objetivo': h.get('clave',''), 'descripcion': f"Module run: {h.get('clave','')}"
        })
    vistos = set()
    unicos = []
    for e in eventos:
        k = e['fecha'] + e['descripcion']
        if k not in vistos:
            vistos.add(k)
            unicos.append(e)
    return sorted(unicos, key=lambda x: x['timestamp'])

# ── Monitor continuo ──────────────────────────────────────────────────────────

monitor_state = {'activo': False, 'thread': None, 'alertas': [], 'objetivo': None, 'intervalo': 3600}

def _monitor_loop():
    while monitor_state['activo']:
        objetivo = monitor_state['objetivo']
        if not objetivo:
            time.sleep(60); continue
        # Re-escanear dominio y usuario
        try:
            tipo = 'dominio' if re.match(r'^[\w\.-]+\.[a-z]{2,}$', objetivo) else 'persona'
            if tipo == 'dominio':
                nuevo = _osint_dominio(objetivo)
                viejo = case['datos'].get(f'dominio_{objetivo}', {})
                if str(nuevo) != str(viejo):
                    monitor_state['alertas'].append({
                        'ts': datetime.datetime.now().isoformat(),
                        'tipo': 'cambio_dominio',
                        'mensaje': f'Cambio detectado en {objetivo}',
                        'nuevo': nuevo
                    })
        except Exception as _e: log.debug("fuente no disponible: %s", _e)
        time.sleep(monitor_state['intervalo'])

def _monitor_start(objetivo, intervalo=3600):
    if monitor_state['activo']: return False
    monitor_state.update({'activo': True, 'objetivo': objetivo,
                          'intervalo': intervalo, 'alertas': []})
    t = threading.Thread(target=_monitor_loop, daemon=True)
    monitor_state['thread'] = t
    t.start()
    return True

def _monitor_stop():
    monitor_state['activo'] = False

def _generar_reporte_html():
    nombre = case['nombre'] or f'reporte_{int(time.time())}'
    path = _ruta_caso_segura(nombre, '_reporte.html') or os.path.join(CASES_DIR, f'reporte_{int(time.time())}_reporte.html')
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    secciones = ''
    for clave, valor in case['datos'].items():
        v = json.dumps(valor, ensure_ascii=False, indent=2, default=str) if isinstance(valor,(dict,list)) else str(valor)
        secciones += f'<div class="section"><h2>{html.escape(clave.replace("_"," ").upper())}</h2><pre>{html.escape(v[:3000])}</pre></div>'
    contenido = f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>OBSIDIAN — {html.escape(str(case.get('objetivo','?')))}</title>
<style>body{{background:#0d0d1a;color:#cdd6f4;font-family:monospace;padding:40px}}
h1{{color:#cba6f7;letter-spacing:.2em;border-bottom:2px solid #313244;padding-bottom:12px}}
h2{{color:#89b4fa;font-size:.9rem;margin:20px 0 6px}}.meta{{color:#6c7086;margin-bottom:28px;font-size:.82rem}}
.section{{background:#1e1e2e;border:1px solid #313244;border-radius:8px;padding:14px;margin:10px 0}}
pre{{color:#a6e3a1;font-size:.78rem;white-space:pre-wrap;word-break:break-all}}
.badge{{background:#f38ba822;color:#f38ba8;padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:700}}</style>
</head><body><h1>⬛ OBSIDIAN REPORT <span class="badge">CONFIDENCIAL</span></h1>
<div class="meta"><b>Target:</b> {html.escape(str(case.get('objetivo','?')))} | <b>Case:</b> {html.escape(nombre)} | <b>Generado:</b> {ts}</div>
{secciones}</body></html>"""
    with open(path,'w') as f: f.write(contenido)
    return path

# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.route('/cert.pem')
def serve_cert():
    return send_from_directory(HOME, 'obsidian-cert.pem', mimetype='application/x-pem-file')

@app.route('/manifest.json')
def manifest():
    return jsonify({
        "name": "OBSIDIAN",
        "short_name": "OBSIDIAN",
        "description": "OSINT & Recon Framework",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0a0a0e",
        "theme_color": "#d99a4e",
        "orientation": "portrait-primary",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
        ]
    })

@app.route('/icon-<size>.png')
def icon(size):
    sz = int(size.replace('x','').split('.')[0]) if size[0].isdigit() else 192
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{sz}" height="{sz}" viewBox="0 0 100 100">
  <rect width="100" height="100" fill="#0a0a0e"/>
  <polygon points="50,10 90,30 90,70 50,90 10,70 10,30" fill="#16161c" stroke="#d99a4e" stroke-width="3"/>
  <polygon points="50,20 80,35 80,65 50,80 20,65 20,35" fill="#0a0a0e" stroke="#d99a4e" stroke-width="1"/>
  <polygon points="50,30 70,40 70,60 50,70 30,60 30,40" fill="#d99a4e" opacity="0.8"/>
  <rect x="44" y="44" width="12" height="12" fill="#0a0a0e"/>
</svg>'''
    from flask import Response
    import subprocess
    try:
        result = subprocess.run(['rsvg-convert', '-w', str(sz), '-h', str(sz), '-f', 'png'],
                              input=svg.encode(), capture_output=True, timeout=5)
        if result.returncode == 0:
            return Response(result.stdout, mimetype='image/png')
    except Exception as _e: log.debug("fuente no disponible: %s", _e)
    return Response(svg.encode(), mimetype='image/svg+xml')

@app.route('/sw.js')
def service_worker():
    sw = """
const CACHE = 'obsidian-v2';
const ASSETS = ['/', '/static/vis-network.min.js'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS))));
self.addEventListener('fetch', e => e.respondWith(
  fetch(e.request).catch(() => caches.match(e.request))
));
"""
    from flask import Response
    return Response(sw, mimetype='application/javascript')

@app.route('/')
def index():
    ip = _get_local_ip()
    return WEB_HTML.replace('{{LOCAL_IP}}', ip).replace('{{PORT}}', str(PORT))

@app.route('/api/status')
def api_status():
    with case_lock:
        return jsonify({'caso': case['nombre'], 'objetivo': case['objetivo'],
                       'modulos': len(case['datos']), 'ok': True})

@app.route('/api/caso', methods=['GET','POST','DELETE'])
def api_caso():
    if request.method == 'GET':
        archivos = [f[:-5] for f in os.listdir(CASES_DIR) if f.endswith('.json')]
        return jsonify({'casos': archivos, 'actual': case['nombre']})
    d = request.json or {}
    if request.method == 'POST':
        slug = _slug_caso(d.get('nombre','caso1'))
        if not slug:
            return jsonify({'error':'Nombre de caso inválido'}), 400
        with case_lock:
            case.update({'nombre':slug, 'objetivo':d.get('objetivo',''),
                         'datos':{}, 'historial':[], 'iniciado':datetime.datetime.now().isoformat()})
        return jsonify({'ok':True})
    if request.method == 'DELETE':
        with case_lock:
            case.update({'nombre':None,'objetivo':None,'datos':{},'historial':[]})
        return jsonify({'ok':True})

@app.route('/api/caso/guardar', methods=['POST'])
def api_guardar():
    if not case['nombre']: return jsonify({'error':'No active case'}), 400
    path = _ruta_caso_segura(case['nombre'])
    if not path: return jsonify({'error':'Nombre de caso inválido'}), 400
    with open(path,'w') as f: json.dump(case, f, ensure_ascii=False, indent=2, default=str)
    _db_guardar_caso(case)
    return jsonify({'ok':True, 'path':path})

@app.route('/api/buscar')
def api_buscar():
    termino = request.args.get('q','').strip()
    if not termino: return jsonify({'error':'Sin término de búsqueda'}), 400
    return jsonify({'resultados': _db_buscar(termino)})

@app.route('/api/caso/cargar', methods=['POST'])
def api_cargar():
    nombre = (request.json or {}).get('nombre','')
    path = _ruta_caso_segura(nombre)
    if not path: return jsonify({'error':'Nombre de caso inválido'}), 400
    if not os.path.exists(path): return jsonify({'error':'No encontrado'}), 404
    with open(path) as f: data = json.load(f)
    with case_lock: case.update(data)
    return jsonify({'ok':True, 'modulos':len(case['datos'])})

# Los validadores de seguridad (_validar, _objetivo_seguro, _slug_caso,
# _ruta_caso_segura, _url_publica...) viven ahora en core/validacion.py y se
# importan arriba. Aquí solo queda la lógica de negocio.


@app.route('/api/run', methods=['POST'])
def api_run():
    d    = request.json or {}
    mod  = d.get('modulo','')
    arg  = d.get('argumento','').strip()
    stream = d.get('stream', False)

    MODULOS = {
        'persona':    lambda: _osint_persona(arg),
        'usuario':    lambda: _osint_usuario(arg),
        'dominio':    lambda: _osint_dominio(arg),
        'ip':         lambda: _osint_ip(arg),
        'email':      lambda: _osint_email(arg),
        'telefono':   lambda: _osint_phone(arg),
        'github_sec': lambda: _recon_github_secrets(arg),
        'ssl':        lambda: _recon_ssl(arg),
        'favicon':    lambda: _recon_favicon(arg),
        'typosquatting': lambda: _recon_typosquatting(arg),
        'buckets':    lambda: _recon_buckets(arg),
        'takeover':   lambda: _recon_subdomain_takeover(arg),
        'metadata':   lambda: _recon_metadata(arg),
        'passivedns': lambda: _recon_passivedns(arg),
        'wordlist':   lambda: _gen_wordlist(arg or case.get('objetivo','')),
        'yara_bulk':  lambda: _recon_yara_bulk(arg),
        'render_js':  lambda: _recon_render_js(arg),
        'cve':        lambda: {'tipo':'cve','resultados':{'analisis':_cve_correlacion(arg)}},
        'escenario':  lambda: {'tipo':'escenario','resultados':{'analisis':_sim_escenario(arg or case.get('objetivo',''))}},
        'superficie': lambda: {'tipo':'superficie','resultados':{'analisis':_sim_superficie(arg or case.get('objetivo',''))}},
        'analizar':   lambda: {'tipo':'analisis','resultados':{'analisis':_analizar_todo()}},
        'darkweb':    lambda: _darkweb_search(arg),
        'shodan':     lambda: _shodan_search(arg),
        'netlas':     lambda: _netlas_search(arg),
        'url_check':  lambda: _check_url(arg),
        'password':   lambda: _analizar_password(arg),
    }

    if mod not in MODULOS:
        return jsonify({'error': f'Unknown module: {mod}'}), 400
    if not arg and mod not in ('wordlist','escenario','superficie','analizar'):
        return jsonify({'error': 'Argument required'}), 400
    if mod in _MODULO_TIPO and not _validar(arg, _MODULO_TIPO[mod]):
        return jsonify({'error': f'Objetivo inválido: no tiene forma de {_MODULO_TIPO[mod]}'}), 400

    def _run_stream():
        yield f"data: {json.dumps({'status':'iniciando','modulo':mod})}\n\n"
        try:
            resultado = MODULOS[mod]()
            yield f"data: {json.dumps({'status':'completado','resultado':resultado})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'status':'error','mensaje':str(e)})}\n\n"

    return Response(stream_with_context(_run_stream()),
                   mimetype='text/event-stream',
                   headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

# ════════════════════════════════════════════════════════════════════════════
# F2 — Motor de transforms integrado (endpoints /api/v2/*, aditivo)
# ════════════════════════════════════════════════════════════════════════════

@transform(entrada='dominio', salidas=('ip',), nombre='dns_a',
           descripcion='Registros A del dominio (dig)')
def _t_dns_a(entidad, ctx):
    out = run_tool(['dig', entidad.valor, 'A', '+short'], timeout=10)
    for linea in out.splitlines():
        linea = linea.strip()
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', linea):
            ctx.emitir('ip', linea, etiqueta='A')

@transform(entrada='ip', salidas=('dominio',), nombre='ptr',
           descripcion='PTR / DNS inverso (dig -x)')
def _t_ptr(entidad, ctx):
    out = run_tool(['dig', '-x', entidad.valor, '+short'], timeout=10)
    for linea in out.splitlines():
        linea = linea.strip().rstrip('.')
        if linea and not linea.startswith(';'):
            ctx.emitir('dominio', linea, etiqueta='PTR')

@transform(entrada='dominio', salidas=('subdominio', 'ip'), nombre='subdominios_ht',
           descripcion='Subdominios (+ su IP) vía HackerTarget hostsearch (keyless)')
def _t_subdominios_ht(entidad, ctx):
    try:
        texto = SESSION.get(f'https://api.hackertarget.com/hostsearch/?q={entidad.valor}', timeout=12).text
        if 'API count exceeded' in texto or 'error' in texto.lower():
            return
        for linea in texto.splitlines()[:150]:
            if ',' not in linea:
                continue
            sub, ip = (x.strip() for x in linea.split(',', 1))
            if not sub.endswith(entidad.valor) or sub == entidad.valor:
                continue
            sub_ent = ctx.emitir('subdominio', sub, etiqueta='subdominio')
            if sub_ent and re.fullmatch(r'\d+\.\d+\.\d+\.\d+', ip):
                ip_ent = ctx.almacen.crear('ip', ip, origenes={'subdominios_ht'})
                ip_ent.anotar_procedencia('subdominios_ht', input_id=sub_ent.id)
                ctx.almacen.relacionar(sub_ent, ip_ent, 'A')
    except Exception as _e:
        log.debug("subdominios_ht no disponible: %s", _e)

@transform(entrada='dominio', salidas=('subdominio',), nombre='crtsh',
           descripcion='Subdominios desde crt.sh (Certificate Transparency)')
def _t_crtsh(entidad, ctx):
    try:
        r = SESSION.get(f'https://crt.sh/?q=%.{entidad.valor}&output=json', timeout=12)
        vistos = set()
        for cert in r.json():
            for s in cert.get('name_value', '').split('\n'):
                s = s.strip().lstrip('*.')
                if s.endswith(entidad.valor) and s != entidad.valor and s not in vistos:
                    vistos.add(s)
                    ctx.emitir('subdominio', s, etiqueta='subdominio')
    except Exception as _e:
        log.debug("crtsh no disponible: %s", _e)

@transform(entrada='ip', salidas=('pais', 'org', 'asn'), nombre='geo_ip',
           descripcion='Geolocalización e info de red de la IP (ip-api.com)')
def _t_geo_ip(entidad, ctx):
    try:
        r = SESSION.get(f'http://ip-api.com/json/{entidad.valor}'
                        '?fields=status,country,org,isp,as', timeout=8)
        d = r.json()
        if d.get('status') != 'success':
            return
        if d.get('country'):
            ctx.emitir('pais', d['country'], etiqueta='location')
        org = d.get('org') or d.get('isp')
        if org:
            ctx.emitir('org', org, etiqueta='org')
        if d.get('as'):
            ctx.emitir('asn', d['as'], etiqueta='asn')
    except Exception as _e:
        log.debug("geo_ip no disponible: %s", _e)

@transform(entrada='usuario', salidas=('email', 'repo'), nombre='github_usuario',
           descripcion='Email y repos públicos del usuario en GitHub')
def _t_github(entidad, ctx):
    try:
        gh = SESSION.get(f'https://api.github.com/users/{entidad.valor}', timeout=8).json()
        if not gh.get('login'):
            return
        if gh.get('email') and gh['email'] != 'oculto':
            ctx.emitir('email', gh['email'], etiqueta='github email')
        repos = SESSION.get(f'https://api.github.com/users/{entidad.valor}/repos'
                            '?per_page=10&sort=updated', timeout=8)
        if repos.status_code == 200:
            for repo in repos.json():
                if repo.get('name'):
                    ctx.emitir('repo', repo['name'], etiqueta='repo',
                               lenguaje=repo.get('language'), stars=repo.get('stargazers_count'))
    except Exception as _e:
        log.debug("github_usuario no disponible: %s", _e)

@transform(entrada='ip', salidas=('puerto',), nombre='puertos',
           descripcion='Puertos abiertos y servicios (nmap top-20)')
def _t_puertos(entidad, ctx):
    if not _which('nmap'):
        return
    out = run_tool(['nmap', '-T4', '--top-ports', '20', '-sV', '--open', entidad.valor], timeout=60)
    for linea in out.splitlines():
        if '/tcp' not in linea and '/udp' not in linea:
            continue
        parts = linea.split()
        num = parts[0].split('/')[0] if parts else ''
        if not num.isdigit():
            continue
        servicio = parts[2] if len(parts) > 2 else '?'
        # el valor lleva la IP: puerto 80 de dos hosts != el mismo nodo
        ctx.emitir('puerto', f'{entidad.valor}:{num}', etiqueta='abierto', servicio=servicio)

@transform(entrada='dominio', salidas=('dominio',), nombre='dns_mx',
           descripcion='Servidores de correo del dominio (MX)')
def _t_dns_mx(entidad, ctx):
    out = run_tool(['dig', entidad.valor, 'MX', '+short'], timeout=10)
    for linea in out.splitlines():
        linea = linea.strip().rstrip('.')
        if not linea:
            continue
        host = linea.split()[-1]   # "10 mail.example.com" -> "mail.example.com"
        if host:
            ctx.emitir('dominio', host, etiqueta='MX')

@transform(entrada='dominio', salidas=('dominio',), nombre='dns_ns',
           descripcion='Name servers del dominio (NS)')
def _t_dns_ns(entidad, ctx):
    out = run_tool(['dig', entidad.valor, 'NS', '+short'], timeout=10)
    for linea in out.splitlines():
        host = linea.strip().rstrip('.')
        if host:
            ctx.emitir('dominio', host, etiqueta='NS')

@transform(entrada='email', salidas=('org',), nombre='email_breaches',
           descripcion='Brechas donde apareció el email (HIBP; requiere HIBP_API_KEY real)')
def _t_email_breaches(entidad, ctx):
    try:
        hibp_key = _boveda.obtener('hibp') or os.environ.get('HIBP_API_KEY', '')
        r = SESSION.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(entidad.valor)}',
            timeout=8,
            headers={'hibp-api-key': hibp_key, 'User-Agent': 'OBSIDIAN-OSINT'})
        if r.status_code == 200:
            for b in r.json():
                nombre = b.get('Name')
                if nombre:
                    ctx.emitir('org', nombre, etiqueta='filtrado en')
            entidad.etiquetar('filtrado')
    except Exception as _e:
        log.debug("hibp no disponible: %s", _e)

@transform(entrada='email', salidas=(), nombre='email_spoofable',
           descripcion='Revisa el SPF del dominio del email (riesgo de spoofing)')
def _t_email_spoofable(entidad, ctx):
    dominio = entidad.valor.split('@')[-1]
    if not dominio:
        return
    txt = run_tool(['dig', dominio, 'TXT', '+short'], timeout=10)
    tiene_spf = 'v=spf1' in txt.lower()
    entidad.propiedades['spf'] = 'configurado' if tiene_spf else 'NO CONFIGURADO'
    if not tiene_spf:
        entidad.etiquetar('spoofable')

def _screenshot(entidad):
    """Captura de la web con navegador headless (paso 68). No captura hosts
    internos (_url_publica). Guarda el PNG en el static y deja la URL como prop."""
    if not _url_publica('https://' + entidad.valor):
        return
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.debug("screenshot: falta playwright")
        return
    shots = os.path.join(STATIC_DIR, 'screenshots')
    os.makedirs(shots, exist_ok=True)
    archivo = hashlib.md5(entidad.valor.encode()).hexdigest()[:12] + '.png'
    try:
        with sync_playwright() as p:
            navegador = p.chromium.launch(headless=True)
            pagina = navegador.new_page(viewport={'width': 1280, 'height': 800})
            pagina.goto('https://' + entidad.valor, timeout=15000, wait_until='domcontentloaded')
            pagina.screenshot(path=os.path.join(shots, archivo))
            navegador.close()
        entidad.propiedades['screenshot'] = '/static/screenshots/' + archivo
        entidad.etiquetar('con-screenshot')
    except Exception as _e:
        log.debug("screenshot falló: %s", _e)

@transform(entrada='dominio', salidas=(), nombre='screenshot',
           descripcion='Captura de pantalla de la web (navegador headless)')
def _t_screenshot_dom(entidad, ctx):
    _screenshot(entidad)

@transform(entrada='subdominio', salidas=(), nombre='screenshot_sub',
           descripcion='Captura de pantalla del subdominio (headless)')
def _t_screenshot_sub(entidad, ctx):
    _screenshot(entidad)

def _nuclei(entidad):
    """Escaneo de vulns con plantillas nuclei (paso 69). Solo hosts públicos.
    Corre con run_tool (argv, sin shell); severidad media+ para no eternizarse."""
    if not _which('nuclei') or not _url_publica('https://' + entidad.valor):
        return
    out = run_tool(['nuclei', '-u', 'https://' + entidad.valor, '-jsonl', '-silent',
                    '-severity', 'medium,high,critical', '-timeout', '5'], timeout=150)
    hallados = []
    for linea in out.splitlines():
        try:
            j = json.loads(linea)
        except Exception:
            continue
        info = j.get('info', {}) or {}
        hallados.append({'id': j.get('template-id'), 'sev': info.get('severity'), 'nombre': info.get('name')})
        if info.get('severity') in ('high', 'critical'):
            entidad.etiquetar('vulnerable')
    if hallados:
        entidad.propiedades['nuclei'] = hallados[:20]

@transform(entrada='dominio', salidas=(), nombre='nuclei',
           descripcion='Escaneo de vulnerabilidades con plantillas (nuclei)')
def _t_nuclei_dom(entidad, ctx):
    _nuclei(entidad)

@transform(entrada='subdominio', salidas=(), nombre='nuclei_sub',
           descripcion='Escaneo de vulns del subdominio (nuclei)')
def _t_nuclei_sub(entidad, ctx):
    _nuclei(entidad)

def _http_probe(entidad):
    """Sondea un host por HTTP y enriquece la entidad. Usa _fetch_seguro:
    no sondea IPs internas (SSRF) y revalida redirects."""
    try:
        r = _fetch_seguro(entidad.valor, timeout=8, stream=False)
    except Exception:
        return
    entidad.propiedades['http_status'] = r.status_code
    entidad.propiedades['http_server'] = r.headers.get('Server', '?')
    powered = r.headers.get('X-Powered-By')
    if powered:
        entidad.propiedades['http_tech'] = powered
    try:
        m = re.search(r'<title[^>]*>(.*?)</title>', r.text[:8000], re.I | re.S)
        if m:
            entidad.propiedades['http_title'] = re.sub(r'\s+', ' ', m.group(1)).strip()[:120]
    except Exception:
        pass
    if str(r.url).rstrip('/') not in (f'https://{entidad.valor}', f'http://{entidad.valor}'):
        entidad.propiedades['http_redirect'] = str(r.url)
    entidad.etiquetar('http-vivo')

@transform(entrada='dominio', salidas=(), nombre='http_probe',
           descripcion='Sondeo HTTP: status, título, server, redirect (estilo httpx)')
def _t_http_probe_dom(entidad, ctx):
    _http_probe(entidad)

@transform(entrada='subdominio', salidas=(), nombre='http_probe_sub',
           descripcion='Sondeo HTTP del subdominio (estilo httpx)')
def _t_http_probe_sub(entidad, ctx):
    _http_probe(entidad)

@transform(entrada='dominio', salidas=('dominio', 'org'), nombre='rdap',
           descripcion='WHOIS moderno (RDAP, sin key): registrar, name servers, fechas')
def _t_rdap(entidad, ctx):
    try:
        r = SESSION.get(f'https://rdap.org/domain/{entidad.valor}', timeout=12,
                        headers={'Accept': 'application/rdap+json'})
        if r.status_code != 200:
            return
        d = r.json()
        for ent in d.get('entities', []):
            if 'registrar' in (ent.get('roles') or []):
                nombre, vc = None, ent.get('vcardArray')
                if vc and len(vc) > 1:
                    for campo in vc[1]:
                        if campo and campo[0] == 'fn':
                            nombre = campo[3]
                if nombre:
                    ctx.emitir('org', nombre, etiqueta='registrar')
        for ns in d.get('nameservers', []):
            if ns.get('ldhName'):
                ctx.emitir('dominio', ns['ldhName'], etiqueta='NS')
        fechas = {e.get('eventAction'): (e.get('eventDate') or '')[:10] for e in d.get('events', [])}
        if fechas.get('registration'):
            entidad.propiedades['creado'] = fechas['registration']
        if fechas.get('expiration'):
            entidad.propiedades['expira'] = fechas['expiration']
        if d.get('status'):
            entidad.propiedades['status'] = d['status']
    except Exception as _e:
        log.debug("rdap no disponible: %s", _e)

@transform(entrada='ip', salidas=('org',), nombre='greynoise',
           descripcion='Threat intel de la IP (GreyNoise Community, keyless pero 25/día; 404=no observada)')
def _t_greynoise(entidad, ctx):
    try:
        r = SESSION.get(f'https://api.greynoise.io/v3/community/{entidad.valor}', timeout=8)
        if r.status_code != 200:   # 404 = IP no observada scanando -> sin enriquecer
            return
        d = r.json()
        if d.get('noise'):
            entidad.etiquetar('escaneando-internet')
        if d.get('riot'):
            entidad.etiquetar('servicio-conocido')
            if d.get('name'):
                ctx.emitir('org', d['name'], etiqueta='greynoise')
        clasif = d.get('classification')
        if clasif:
            entidad.propiedades['greynoise'] = clasif
            if clasif == 'malicious':
                entidad.etiquetar('malicioso')
    except Exception as _e:
        log.debug("greynoise no disponible: %s", _e)

@transform(entrada='dominio', salidas=(), nombre='dns_txt',
           descripcion='Registros TXT del dominio (SPF, verificaciones, etc.)')
def _t_dns_txt(entidad, ctx):
    out = run_tool(['dig', entidad.valor, 'TXT', '+short'], timeout=10)
    txt = [l.strip().strip('"') for l in out.splitlines() if l.strip()]
    if txt:
        entidad.propiedades['txt'] = txt[:10]

@transform(entrada='dominio', salidas=('org',), nombre='ssl',
           descripcion='Certificado TLS del dominio: emisor y vigencia')
def _t_ssl(entidad, ctx):
    try:
        contexto = ssl.create_default_context()
        with socket.create_connection((entidad.valor, 443), timeout=8) as sock:
            with contexto.wrap_socket(sock, server_hostname=entidad.valor) as segura:
                cert = segura.getpeercert()
        issuer = dict(x[0] for x in cert.get('issuer', []))
        org = issuer.get('organizationName')
        if org:
            ctx.emitir('org', org, etiqueta='emisor cert')
        entidad.propiedades['cert_desde'] = cert.get('notBefore')
        entidad.propiedades['cert_expira'] = cert.get('notAfter')
    except Exception as _e:
        log.debug("ssl no disponible: %s", _e)


@app.route('/api/v2/transforms/<tipo>')
def api_v2_transforms(tipo):
    """Transforms que aplican a un tipo de entidad (paso 35)."""
    ts = [{'nombre': t.nombre, 'salidas': list(t.salidas),
           'requiere_key': t.requiere_key, 'descripcion': t.descripcion}
          for t in REGISTRO.aplicables(tipo)]
    return jsonify({'tipo': tipo, 'transforms': ts})

@app.route('/api/v2/run', methods=['POST'])
def api_v2_run():
    """Corre un transform sobre una entidad {tipo, valor} (paso 36)."""
    d = request.json or {}
    tipo = d.get('tipo', '')
    valor = (d.get('valor', '') or '').strip()
    nombre = d.get('transform', '')
    if not tipo_valido(tipo):
        return _error('tipo de entidad inválido', 400)
    try:
        semilla = Entidad(tipo, valor)
    except ValueError as e:
        return _error(str(e), 400)
    if not semilla.valor_bien_formado():
        return _error(f'valor con forma inválida para {tipo}', 400)
    semilla = _almacen.agregar(semilla)
    try:
        producidas = ejecutar_por_nombre(nombre, semilla, _almacen)
    except (KeyError, ValueError) as e:
        return _error(str(e), 400)
    if _ws_activo:                              # autosave (46) + auditoría (48)
        try:
            _gestor.guardar(_ws_activo, _almacen)
            _gestor.registrar(_ws_activo, nombre, valor, len(producidas))
        except Exception as _e:
            log.warning("autosave falló: %s", _e)
    return jsonify({'producidas': [e.to_dict() for e in producidas],
                    'total_entidades': len(_almacen), 'workspace': _ws_activo})

@app.route('/api/v2/grafo')
def api_v2_grafo():
    """Grafo tipado. ?migrar=1 convierte el case['datos'] viejo al modelo nuevo."""
    if request.args.get('migrar') == '1':
        return jsonify(migrar_caso(case).to_dict())
    return jsonify(_almacen.to_dict())

@app.route('/api/v2/workspaces', methods=['GET', 'POST', 'DELETE'])
def api_v2_workspaces():
    """CRUD de workspaces (F3 paso 44). Cada uno es un caso aislado en SQLite."""
    global _almacen, _ws_activo
    if request.method == 'GET':
        return jsonify({'workspaces': _gestor.listar(), 'activo': _ws_activo})
    nombre = (request.json or {}).get('nombre', '')
    if request.method == 'POST':
        try:
            _almacen = _gestor.crear(nombre)
        except ValueError as e:
            return _error(str(e), 400)
        _ws_activo = _slug_caso(nombre)
        return jsonify({'ok': True, 'activo': _ws_activo})
    if request.method == 'DELETE':
        _gestor.borrar(nombre)
        if _ws_activo == _slug_caso(nombre):
            _almacen, _ws_activo = Almacen(), None
        return jsonify({'ok': True, 'activo': _ws_activo})

@app.route('/api/v2/workspaces/abrir', methods=['POST'])
def api_v2_workspace_abrir():
    """Carga un workspace en memoria y lo hace el activo (F3 paso 45)."""
    global _almacen, _ws_activo
    nombre = (request.json or {}).get('nombre', '')
    try:
        _almacen = _gestor.cargar(nombre)
    except KeyError:
        return _error('workspace no encontrado', 404)
    _ws_activo = _slug_caso(nombre)
    return jsonify({'ok': True, 'activo': _ws_activo, 'total_entidades': len(_almacen)})

@app.route('/api/v2/workspaces/historial')
def api_v2_ws_historial():
    """Historial de transforms del workspace activo (F3 paso 48)."""
    return jsonify({'historial': _gestor.historial(_ws_activo) if _ws_activo else []})

@app.route('/api/v2/workspaces/snapshot', methods=['GET', 'POST'])
def api_v2_ws_snapshot():
    """Crear (POST) o listar (GET) snapshots del workspace activo (F3 paso 49)."""
    if not _ws_activo:
        return _error('no hay workspace activo', 400)
    if request.method == 'POST':
        try:
            sid = _gestor.snapshot(_ws_activo)
        except KeyError:
            return _error('workspace no encontrado', 404)
        return jsonify({'ok': True, 'snapshot': sid})
    return jsonify({'snapshots': _gestor.listar_snapshots(_ws_activo)})

@app.route('/api/v2/keys', methods=['GET', 'POST', 'DELETE'])
def api_v2_keys():
    """Bóveda de API keys cifrada (F3 paso 51). GET lista solo NOMBRES de
    servicio (nunca valores). POST guarda; DELETE borra."""
    if request.method == 'GET':
        return jsonify({'servicios': _boveda.servicios()})
    d = request.json or {}
    servicio = (d.get('servicio', '') or '').strip().lower()
    if not servicio:
        return _error('falta el servicio', 400)
    if request.method == 'POST':
        valor = d.get('valor', '')
        if not valor:
            return _error('falta el valor de la key', 400)
        _boveda.guardar(servicio, valor)
        return jsonify({'ok': True, 'servicios': _boveda.servicios()})
    _boveda.borrar(servicio)   # DELETE
    return jsonify({'ok': True, 'servicios': _boveda.servicios()})

@app.route('/api/v2/hallazgos')
def api_v2_hallazgos():
    """Corre el motor de correlación sobre el caso activo (F4 pasos 62, 64)."""
    h = correlacionar(_almacen)
    return jsonify({'hallazgos': [x.to_dict() for x in h], 'score': score_riesgo(h)})

@app.route('/api/v2/hallazgos/ia', methods=['POST'])
def api_v2_hallazgos_ia():
    """Correlación asistida por IA (F4 paso 65): Ollama resume el riesgo y
    sugiere el siguiente paso a partir de los hallazgos del caso."""
    h = correlacionar(_almacen)
    if not h:
        return jsonify({'resumen': 'Sin hallazgos que analizar todavía. Corre más transforms.'})
    conteo = {}
    for e in _almacen.entidades:
        conteo[e.tipo] = conteo.get(e.tipo, 0) + 1
    ents = ', '.join(f'{n} {t}' for t, n in conteo.items())
    lista = '\n'.join(f'- [{x.severidad}] {x.mensaje}' for x in h)
    prompt = (
        f"Eres un analista de ciberseguridad. En una investigación OSINT sobre un objetivo "
        f"(entidades: {ents}) se detectaron estos hallazgos:\n\n{lista}\n\n"
        f"Score de riesgo: {score_riesgo(h)}/100.\n\n"
        f"En 3-4 frases en español: resume el riesgo principal y sugiere el siguiente paso "
        f"concreto de investigación. Directo, sin relleno.")
    try:
        r = SESSION.post(f'{OLLAMA}/api/chat', json={
            'model': 'qwen2.5:3b',
            'messages': [{'role': 'user', 'content': prompt}],
            'stream': False,
            'options': {'num_ctx': 2048, 'num_predict': 300, 'temperature': 0.4},
        }, timeout=(10, 120))
        texto = (r.json().get('message', {}) or {}).get('content', '').strip()
        return jsonify({'resumen': texto or 'La IA no devolvió texto.'})
    except Exception as e:
        log.warning("IA correlación falló: %s", e)
        return _error('Ollama no disponible (¿está corriendo en :11434?)', 503)

@app.route('/v2')
def v2_page():
    """Página demo del motor v2: correr transforms y ver el grafo tipado.
    Protegida por el guard de auth (no está en _PUBLIC_PATHS)."""
    return _cargar_web('v2.html')


@app.route('/api/reporte', methods=['POST'])
def api_reporte():
    if not case['datos']: return jsonify({'error':'No data collected yet'}), 400
    path = _generar_reporte_html()
    return jsonify({'ok':True, 'path':path})

@app.route('/reporte_pdf')
def reporte_pdf():
    path = _generar_reporte_html()
    with open(path) as f: contenido = f.read()
    # Inyectar CSS de impresión para PDF
    contenido = contenido.replace('</head>',
        '<style>@media print{body{background:#fff!important;color:#000!important}.section{border:1px solid #ccc!important;background:#f9f9f9!important}pre{color:#333!important}h1,h2{color:#333!important}}</style></head>')
    return contenido

@app.route('/api/darkweb', methods=['POST'])
def api_darkweb():
    q = (request.json or {}).get('query','')
    if not q: return jsonify({'error':'Sin query'}), 400
    return jsonify(_darkweb_search(q))

@app.route('/api/shodan', methods=['POST'])
def api_shodan():
    d = request.json or {}
    if d.get('ip'):
        if not _objetivo_seguro(d['ip']):
            return jsonify({'error': 'IP inválida: caracteres no permitidos'}), 400
        return jsonify(_shodan_ip(d['ip']))
    q = d.get('query','')
    if not q: return jsonify({'error':'Sin query'}), 400
    return jsonify(_shodan_search(q))

@app.route('/api/netlas', methods=['POST'])
def api_netlas():
    q = (request.json or {}).get('query','')
    if not q: return jsonify({'error':'Sin query'}), 400
    return jsonify(_netlas_search(q))

@app.route('/api/kali', methods=['POST'])
def api_kali():
    d = request.json or {}
    tool_id = d.get('tool', '')
    arg = d.get('arg', '').strip()
    def _stream():
        yield f"data: {json.dumps({'status':'iniciando','tool':tool_id})}\n\n"
        try:
            resultado = _kali_run(tool_id, arg)
            yield f"data: {json.dumps({'status':'completado','resultado':resultado})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'status':'error','mensaje':str(e)})}\n\n"
    return Response(stream_with_context(_stream()),
                   mimetype='text/event-stream',
                   headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/api/kali/tools')
def api_kali_tools():
    return jsonify(KALI_TOOLS)

@app.route('/api/parrot', methods=['POST'])
def api_parrot():
    d = request.json or {}
    tool_id = d.get('tool','')
    arg = d.get('arg','').strip()
    def _stream():
        yield f"data: {json.dumps({'status':'iniciando','tool':tool_id})}\n\n"
        try:
            resultado = _distrobox_run('parrot', PARROT_TOOLS, tool_id, arg)
            yield f"data: {json.dumps({'status':'completado','resultado':resultado})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'status':'error','mensaje':str(e)})}\n\n"
    return Response(stream_with_context(_stream()),
                   mimetype='text/event-stream',
                   headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/api/parrot/tools')
def api_parrot_tools():
    return jsonify(PARROT_TOOLS)

@app.route('/api/remnux', methods=['POST'])
def api_remnux():
    d = request.json or {}
    tool_id = d.get('tool','')
    arg = d.get('arg','').strip()
    def _stream():
        yield f"data: {json.dumps({'status':'iniciando','tool':tool_id})}\n\n"
        try:
            resultado = _distrobox_run('remnux', REMNUX_TOOLS, tool_id, arg)
            yield f"data: {json.dumps({'status':'completado','resultado':resultado})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'status':'error','mensaje':str(e)})}\n\n"
    return Response(stream_with_context(_stream()),
                   mimetype='text/event-stream',
                   headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/api/remnux/tools')
def api_remnux_tools():
    return jsonify(REMNUX_TOOLS)

@app.route('/api/blackarch', methods=['POST'])
def api_blackarch():
    d       = request.json or {}
    tool_id = d.get('tool','')
    arg     = d.get('arg','')
    try:
        resultado = _distrobox_run('blackarch', BLACKARCH_TOOLS, tool_id, arg)
        return jsonify({'ok': True, 'resultado': resultado})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/blackarch/tools')
def api_blackarch_tools():
    return jsonify(BLACKARCH_TOOLS)

@app.route('/api/apikeys', methods=['POST'])
def api_keys():
    d = request.json or {}
    if 'vt_key' in d: os.environ['VT_API_KEY'] = d['vt_key']
    if 'abuse_key' in d: os.environ['ABUSEIPDB_KEY'] = d['abuse_key']
    return jsonify({'ok': True})

@app.route('/api/shodan/key', methods=['POST'])
def api_shodan_key():
    global SHODAN_KEY
    SHODAN_KEY = (request.json or {}).get('key','')
    return jsonify({'ok': True})

@app.route('/api/netlas/key', methods=['POST'])
def api_netlas_key():
    global NETLAS_KEY
    NETLAS_KEY = (request.json or {}).get('key','')
    return jsonify({'ok': True})

@app.route('/api/timeline')
def api_timeline():
    return jsonify({'eventos': _build_timeline()})

@app.route('/api/monitor', methods=['GET','POST','DELETE'])
def api_monitor():
    if request.method == 'GET':
        return jsonify({'activo': monitor_state['activo'],
                       'objetivo': monitor_state['objetivo'],
                       'alertas': monitor_state['alertas'][-20:],
                       'intervalo': monitor_state['intervalo']})
    if request.method == 'POST':
        d = request.json or {}
        ok = _monitor_start(d.get('objetivo', case.get('objetivo','')),
                            int(d.get('intervalo', 3600)))
        return jsonify({'ok': ok})
    if request.method == 'DELETE':
        _monitor_stop()
        return jsonify({'ok': True})

@app.route('/api/grafo')
def api_grafo():
    return jsonify(_build_grafo())

@app.route('/api/datos')
def api_datos():
    with case_lock:
        return jsonify({'datos': case['datos'], 'historial': case['historial'][-20:]})

# ── Frontend ──────────────────────────────────────────────────────────────────

WEB_HTML = _cargar_web('app.html')

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    ip = _get_local_ip()
    print(f"""
⬛ OBSIDIAN Web — iniciando...
   PC:      http://localhost:{PORT}
   Celular: http://{ip}:{PORT}
""")
    app.run(host=os.environ.get('OBSIDIAN_HOST', '127.0.0.1'), port=PORT, debug=False, threaded=True)
