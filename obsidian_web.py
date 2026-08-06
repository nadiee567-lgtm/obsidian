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
from core.modelo import Almacen, Entidad, tipo_valido, TIPOS
from core.transforms import transform, REGISTRO, ejecutar_por_nombre, ejecutar_lote
from core.migracion import migrar_caso
from core.workspaces import Gestor
from core.boveda import Boveda
from core.correlacion import correlacionar, score_riesgo, cargar_reglas_yaml, score_exposicion
from core.reporte import generar_reporte
from core.exportar import exportar_json, exportar_csv
from core.monitor import Monitor, snapshot as _snap_estado
from core.notificar import enviar_ntfy, construir_ntfy
from core.estado import render_estado
from core.motores import traducir as _motor_query, traducir_todos, MOTORES
from core.tareas import GestorTareas
from core.personas import GestorPersonas
from core.extraccion import extraer_entidades
from core import multiidioma as _ml
from core.imagen import (enlaces_reverse, enlaces_facial, parse_gps,
                         enlaces_cronolocalizacion, enlaces_satelital, enlaces_landmark,
                         phash as _phash, ela as _ela)
import core.ia as ia

log = get_logger()

app   = Flask(__name__,
              static_folder=os.path.join(HOME_INIT, 'obsidian-static'),
              static_url_path='/static')
os.makedirs(CASES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# ── Uniform error handling (step 11) ─────────────────────────────────────────
def _error(mensaje, codigo=400):
    """Consistent JSON error response: {'error': msg, 'code': n}."""
    return jsonify({'error': mensaje, 'code': codigo}), codigo

@app.errorhandler(Exception)
def _manejar_error(e):
    """Any error ends as uniform JSON for /api routes. Unhandled exceptions are
    logged in full server-side, but the client only gets a generic message --
    do not leak the stack trace."""
    if isinstance(e, HTTPException):
        if request.path.startswith('/api/'):
            return _error(e.description or e.name, e.code)
        return e   # normal pages: default 404/405 HTML
    log.exception("unhandled error in %s %s", request.method, request.path)
    if request.path.startswith('/api/'):
        return _error('Internal server error', 500)
    return 'Internal server error', 500

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
    """Mirror of the case in SQLite -- does not replace the JSON, only makes it searchable."""
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
        log.error("error saving SQLite mirror: %s", e)

def _db_buscar(termino):
    """Searches a term (email, domain, username...) across all saved cases."""
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
# If vis.js (graph) is missing from the user static dir, copy the one shipped with the program
_HERE = os.path.dirname(os.path.abspath(__file__))
_WEB_DIR = os.path.join(_HERE, 'web')
def _cargar_web(nombre):
    """Loads a UI file (HTML/JS/CSS) from web/. The front-end lives in files, not
    embedded in the .py. It is read as text: the usual .replace()/.format() still
    apply (no Jinja, which would clash with the CSS braces and the ${} of JS)."""
    with open(os.path.join(_WEB_DIR, nombre), encoding='utf-8') as _f:
        return _f.read()

if not os.path.exists(os.path.join(STATIC_DIR, _VIS)) and os.path.exists(os.path.join(_HERE, _VIS)):
    shutil.copy(os.path.join(_HERE, _VIS), os.path.join(STATIC_DIR, _VIS))
OLLAMA    = 'http://localhost:11434'
MODEL     = 'qwen2.5:3b'

# ── Auth: mandatory if the server is exposed beyond 127.0.0.1 ─────────────────
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
    print(f"\n[OBSIDIAN] Generated password: {pw}")
    print(f"[OBSIDIAN] Save it -- it is not shown again. To change it: delete {AUTH_FILE} or use OBSIDIAN_PASSWORD=your_key\n")
    return auth

app.secret_key = _load_secret_key()
app.permanent_session_lifetime = datetime.timedelta(days=7)
_AUTH = _load_or_create_auth()
_login_attempts = {}   # ip -> [attempts, locked_until_ts]
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
        return jsonify({'error': 'Not authenticated'}), 401
    session['next'] = request.path   # remember where they were headed, to return after login
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    now = time.time()
    intentos, bloqueado_hasta = _login_attempts.get(ip, [0, 0])
    if now < bloqueado_hasta:
        err = f'<div class="err">Too many attempts. Wait {int(bloqueado_hasta - now)}s.</div>'
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
            # internal routes only (anti open-redirect)
            if not dest.startswith('/') or dest.startswith('//'):
                dest = '/'
            return redirect(dest)
        intentos += 1
        bloqueado_hasta = now + _LOCK_SECONDS if intentos >= _LOCK_THRESHOLD else 0
        _login_attempts[ip] = [intentos, bloqueado_hasta]
        return _LOGIN_HTML.format(error_html='<div class="err">Incorrect password</div>'), 401
    return _LOGIN_HTML.format(error_html='')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ── OBSIDIAN is free and open -- no licenses, tiers or locks ──────────────────

SESSION = requests.Session()
SESSION.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0'})

# Global investigation state
case = {'nombre': None, 'objetivo': None, 'datos': {}, 'historial': [], 'iniciado': None}
case_lock = threading.Lock()

# Typed session model (F2, transform-engine integration).
# Coexists with `case` during migration; the /api/v2/* endpoints use this.
_almacen = Almacen()

# F3: workspace manager (isolated SQLite cases). _ws_activo = None -> ephemeral
# mode (not saved); if one is active, each transform autosaves.
_gestor = Gestor(WORKSPACES_DIR)
_ws_activo = None

# F3 step 51: encrypted API-key vault (Fernet).
_boveda = Boveda(os.path.join(HOME, '.obsidian'))

SYSTEM = """You are OBSIDIAN AI, an OSINT intelligence analysis engine.
ROLE: Expert analyst. Correlate data, find patterns, generate actionable conclusions.
RULES: NEVER fabricate data. Be direct and technical. Use [!] critical, [+] positive, [-] negative.
Always respond in English."""

# ── Utilities ─────────────────────────────────────────────────────────────────

def _cmd(cmd, timeout=25):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout, cwd=HOME, env={**os.environ,'HOME':HOME})
        return (r.stdout + r.stderr).strip() or '(no output)'
    except subprocess.TimeoutExpired:
        return f'[Timeout {timeout}s]'
    except Exception as e:
        return f'[Error: {e}]'

def run_tool(argv, timeout=25, stdin=None):
    """Runs a tool WITHOUT a shell: argv is a list, not a string. Closes
    metacharacter injection (;, |, `, $()...) because it never passes through a
    shell interpreter. To ALSO close argument injection (a value starting with
    '-' is read as a flag), validate the target by type with _validar() BEFORE
    calling here. Prefer this function over _cmd for anything that interpolates
    user data. _cmd is left only for internal pipelines with already-validated
    values."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           cwd=HOME, env={**os.environ, 'HOME': HOME}, input=stdin)
        return (r.stdout + r.stderr).strip() or '(no output)'
    except subprocess.TimeoutExpired:
        return f'[Timeout {timeout}s]'
    except FileNotFoundError:
        return f'[Error: {argv[0] if argv else "?"} not found]'
    except Exception as e:
        return f'[Error: {e}]'

# ── Security: anti-SSRF fetch (uses _url_publica from core.validacion + SESSION) ─
def _fetch_seguro(url, timeout=10, stream=False, max_redirs=3):
    """GET that closes SSRF: validates that EVERY hop points to a public IP. It
    follows redirects manually and revalidates each one (a public site can
    redirect to 169.254.169.254). Raises ValueError if any destination is
    internal. Note: does not cover DNS rebinding (TOCTOU); advanced vector, future work."""
    if '://' not in url:
        url = 'https://' + url
    for _ in range(max_redirs + 1):
        if not _url_publica(url):
            raise ValueError('URL blocked (SSRF): internal/private network or disallowed scheme')
        r = SESSION.get(url, timeout=timeout, stream=stream, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get('Location'):
            url = urljoin(url, r.headers['Location'])
            continue
        return r
    raise ValueError('Too many redirects')

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
        yield f'[AI error: {e}]'

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

def _tailscale_ip():
    """Tailscale IP (100.64.0.0/10) if the mesh is up, else None."""
    try:
        out = subprocess.run(['tailscale', 'ip', '-4'], capture_output=True,
                             text=True, timeout=3)
        ip = (out.stdout or '').strip().splitlines()[0].strip() if out.stdout else ''
        return ip if ip.startswith('100.') else None
    except Exception:
        return None

# ── OSINT modules ─────────────────────────────────────────────────────────────

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
    except Exception as _e: log.debug("source unavailable: %s", _e)
    # Dorks
    datos['resultados']['dorks'] = [
        f'"{nombre}" site:linkedin.com',
        f'"{nombre}" site:twitter.com OR site:x.com',
        f'"{nombre}" email OR phone OR address',
        f'"{nombre}" filetype:pdf',
        f'"{nombre}" site:github.com',
        f'"{nombre}" "date of birth" OR "birthday"',
        f'"{nombre}" site:facebook.com',
    ]
    # HIBP check
    try:
        r = SESSION.get(f"https://haveibeenpwned.com/unifiedsearch/{requests.utils.quote(nombre)}",
                       timeout=6, headers={'User-Agent':'OSINT-Research'})
        datos['resultados']['hibp'] = 'Possible presence in HIBP' if r.status_code==200 else 'Not found in HIBP'
    except Exception as _e: log.debug("source unavailable: %s", _e)
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
        except Exception as _e: log.debug("source unavailable: %s", _e)
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
                'ubicacion': gh.get('location','?'), 'email': gh.get('email','hidden'),
                'web': gh.get('blog','?'), 'creado': gh.get('created_at','?')
            }
            # Public repos
            repos_r = SESSION.get(f'https://api.github.com/users/{username}/repos?per_page=10&sort=updated', timeout=8)
            if repos_r.status_code == 200:
                repos = [{'nombre':r['name'],'url':r['html_url'],'stars':r['stargazers_count'],
                          'lenguaje':r.get('language','?')} for r in repos_r.json()]
                datos['resultados']['github_repos'] = repos
    except Exception as _e: log.debug("source unavailable: %s", _e)
    # Sherlock
    if _which('sherlock'):
        out = _cmd(f'sherlock {username} --timeout 5 --print-found 2>/dev/null', timeout=60)
        encontrados_sh = [l.strip() for l in out.splitlines() if '[+]' in l]
        datos['resultados']['sherlock'] = encontrados_sh
    # Maigret -- more platform coverage than Sherlock
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
    # Subdomains crt.sh
    try:
        r = SESSION.get(f'https://crt.sh/?q=%.{dominio}&output=json', timeout=12)
        subs = set()
        for cert in r.json():
            for s in cert.get('name_value','').split('\n'):
                s = s.strip().lstrip('*.')
                if s.endswith(dominio) and s != dominio: subs.add(s)
        datos['resultados']['subdominios'] = sorted(list(subs))[:30]
    except Exception as _e: log.debug("source unavailable: %s", _e)
    # Headers / Technologies
    try:
        import urllib3; urllib3.disable_warnings()
        r = SESSION.get(f'https://{dominio}', timeout=8, verify=False)
        h = r.headers
        tech = {k:h[k] for k in ['Server','X-Powered-By','X-Generator','X-Framework'] if k in h}
        missing_sec = [k for k in ['Strict-Transport-Security','Content-Security-Policy',
                                    'X-Frame-Options','X-Content-Type-Options'] if k not in h]
        datos['resultados']['tecnologias'] = tech
        datos['resultados']['headers_faltantes'] = missing_sec
    except Exception as _e: log.debug("source unavailable: %s", _e)
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
    except Exception as _e: log.debug("source unavailable: %s", _e)
    _guardar_dato(f'dominio_{dominio}', datos)
    return datos

def _osint_ip(ip):
    datos = {'tipo':'ip','objetivo':ip,'resultados':{}}
    # Geo
    try:
        r = SESSION.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,mobile,proxy,hosting', timeout=8)
        d = r.json()
        if d.get('status') == 'success': datos['resultados']['geo'] = d
    except Exception as _e: log.debug("source unavailable: %s", _e)
    # Ports
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
    except Exception as _e: log.debug("source unavailable: %s", _e)
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
    except Exception as _e: log.debug("source unavailable: %s", _e)
    # HIBP
    try:
        r = SESSION.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}',
                       timeout=8, headers={'hibp-api-key':'free','User-Agent':'OBSIDIAN-OSINT'})
        if r.status_code == 200:
            breaches = [b.get('Name','?') for b in r.json()]
            datos['resultados']['hibp_breaches'] = breaches
        elif r.status_code == 404:
            datos['resultados']['hibp_breaches'] = []
    except Exception as _e: log.debug("source unavailable: %s", _e)
    # SPF/DKIM/DMARC of the domain
    if dominio:
        spf   = _cmd(f'dig {dominio} TXT +short 2>/dev/null')
        dmarc = _cmd(f'dig _dmarc.{dominio} TXT +short 2>/dev/null')
        dkim  = _cmd(f'dig default._domainkey.{dominio} TXT +short 2>/dev/null')
        spoofable = not any('v=spf1' in spf.lower() for _ in [1])
        datos['resultados']['email_sec'] = {
            'spf': spf.strip()[:200] or 'NOT CONFIGURED',
            'dmarc': dmarc.strip()[:200] or 'NOT CONFIGURED',
            'dkim': dkim.strip()[:200] or 'NOT CONFIGURED',
            'spoofable': spoofable
        }
    _guardar_dato(f'email_{email}', datos)
    return datos

def _osint_phone(numero):
    datos = {'tipo':'telefono','objetivo':numero,'resultados':{}}
    numero_limpio = re.sub(r'[^\d+]','',numero)
    # Basic public API
    try:
        r = SESSION.get(f'https://api.hackertarget.com/ipgeo/?q={numero_limpio}', timeout=8)
        datos['resultados']['raw'] = r.text.strip()
    except Exception as _e: log.debug("source unavailable: %s", _e)
    # NumVerify (no key -- basic)
    try:
        r = SESSION.get(f'http://apilayer.net/api/validate?number={numero_limpio}', timeout=8)
        if r.status_code == 200:
            d = r.json()
            datos['resultados']['info'] = {
                'valid': d.get('valid', False),
                'pais': d.get('country_name','?'),
                'carrier': d.get('carrier','?'),
                'tipo': d.get('line_type','?')
            }
    except Exception as _e: log.debug("source unavailable: %s", _e)
    # Search social networks
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
            # Search recent commits
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
    # Basic info
    cert_info = _cmd(f'echo | openssl s_client -connect {dominio}:443 -servername {dominio} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint 2>/dev/null')
    datos['resultados']['certificado'] = cert_info
    # Vulnerable cipher suites
    for cipher, vuln in [('RC4','OBSOLETE'),('DES','VULNERABLE'),('NULL','CRITICAL'),('EXPORT','CRITICAL')]:
        out = _cmd(f'openssl s_client -connect {dominio}:443 -cipher {cipher} 2>/dev/null | head -3')
        if 'Cipher' in out and 'NONE' not in out:
            datos['resultados'][f'cipher_{cipher}'] = f'VULNERABLE -- {vuln}'
    # HSTS
    try:
        import urllib3; urllib3.disable_warnings()
        r = SESSION.get(f'https://{dominio}', timeout=8, verify=False)
        datos['resultados']['hsts'] = r.headers.get('Strict-Transport-Security','NOT CONFIGURED')
        datos['resultados']['ocsp'] = 'Verify manually'
    except Exception as _e: log.debug("source unavailable: %s", _e)
    _guardar_dato(f'ssl_{dominio}', datos)
    return datos

def _recon_favicon(dominio):
    """mmh3 hash of the favicon (Shodan algorithm) -- pivots to related infrastructure."""
    datos = {'tipo':'favicon','objetivo':dominio,'resultados':{}}
    dominio = dominio.replace('https://','').replace('http://','').split('/')[0]
    try:
        import mmh3
    except ImportError:
        datos['resultados']['error'] = "Missing the mmh3 library -- install with: pip install mmh3"
        _guardar_dato(f'favicon_{dominio}', datos)
        return datos
    favicon_bytes = None
    for esquema in ('https', 'http'):
        try:
            r = SESSION.get(f'{esquema}://{dominio}/favicon.ico', timeout=8, verify=False)
            if r.status_code == 200 and r.content:
                favicon_bytes = r.content
                break
        except Exception as _e: log.debug("source unavailable: %s", _e)
    if not favicon_bytes:
        datos['resultados']['error'] = 'favicon.ico not found on the target (try another path manually)'
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
        datos['resultados']['nota'] = f'Computed hash: {hash_mmh3}. Add a Shodan API key (free at shodan.io) to search related infrastructure, or paste the hash manually into shodan.io/search?query=http.favicon.hash:{hash_mmh3}'
    _guardar_dato(f'favicon_{dominio}', datos)
    return datos

def _recon_typosquatting(dominio):
    datos = {'tipo':'typosquatting','objetivo':dominio,'resultados':{}}
    nombre, ext = dominio.rsplit('.',1) if '.' in dominio else (dominio,'com')
    variantes = set()
    # Common substitutions
    subs = {'a':'4','e':'3','i':'1','o':'0','s':'5','l':'1'}
    for i, c in enumerate(nombre):
        if c in subs:
            v = nombre[:i]+subs[c]+nombre[i+1:]
            variantes.add(f'{v}.{ext}')
    # Keyboard typos
    teclado = {'q':'w','w':'e','e':'r','r':'t','t':'y','a':'s','s':'d','d':'f',
               'f':'g','g':'h','z':'x','x':'c','c':'v','v':'b'}
    for i, c in enumerate(nombre.lower()):
        if c in teclado:
            v = nombre[:i]+teclado[c]+nombre[i+1:]
            variantes.add(f'{v}.{ext}')
    # Letter omission/duplication
    for i in range(len(nombre)):
        variantes.add(f'{nombre[:i]+nombre[i+1:]}.{ext}')
        variantes.add(f'{nombre[:i]+nombre[i]*2+nombre[i:]}.{ext}')
    # Check which exist
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
            except Exception as _e: log.debug("source unavailable: %s", _e)
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
    # Services vulnerable to takeover
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
                    vulnerables.append({'subdominio':sub,'cname':cname,'servicio':servicio,'status':'POSSIBLE'})
    ths = [threading.Thread(target=_check_sub, args=(s,)) for s in list(subs)[:20]]
    for t in ths: t.start()
    for t in ths: t.join(timeout=20)
    datos['resultados']['subdominios_analizados'] = len(list(subs)[:20])
    datos['resultados']['vulnerables'] = vulnerables
    _guardar_dato(f'takeover_{dominio}', datos)
    return datos

def _recon_passivedns(dominio):
    """History of IPs the domain has resolved to, via VirusTotal (reuses the Analyze key)."""
    datos = {'tipo':'passivedns','objetivo':dominio,'resultados':{}}
    dominio = dominio.replace('https://','').replace('http://','').split('/')[0]
    vt_key = os.environ.get('VT_API_KEY','')
    if not vt_key:
        datos['resultados']['nota'] = 'Add a VirusTotal API key (free, Analyze tab) to see the IP history'
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
        # If it is an image, extract EXIF
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
                # Search for GPS
                gps = re.findall(r'GPS.*?:\s*(.+)', exif)
                if gps: datos['resultados']['gps'] = gps
            os.unlink(fname)
        else:
            # HTML -- extract meta tags
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
    """Renders the page with a headless browser -- sees what loads via JS, screenshot included."""
    datos = {'tipo':'render_js','objetivo':url,'resultados':{}}
    if not url.startswith(('http://','https://')):
        url = 'https://' + url
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        datos['resultados']['error'] = 'Missing playwright -- install with: pip install playwright && playwright install chromium'
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
        datos['resultados']['error'] = f'Render error: {e}'
    _guardar_dato(f'render_{url[:50]}', datos)
    return datos

def _recon_yara_bulk(carpeta):
    """Scans every file in a folder with yara-rules -- only makes sense on a full PC."""
    datos = {'tipo':'yara_bulk','objetivo':carpeta,'resultados':{}}
    if not os.path.isdir(carpeta):
        datos['resultados']['error'] = f'Not a valid folder: {carpeta}'
        _guardar_dato(f'yara_bulk_{carpeta}', datos)
        return datos
    if not _which('yara-rules'):
        datos['resultados']['error'] = 'yara-rules is not installed'
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
    # Save file
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
    """Runs a tool inside a distrobox container"""
    tool = None
    for cat in tool_dict.values():
        for t in cat:
            if t['id'] == tool_id:
                tool = t
                break
    if not tool:
        return {'error': f'Unknown tool: {tool_id}'}
    if not _objetivo_seguro(arg):
        return {'error': 'Invalid argument: contains disallowed characters'}
    cmd = tool['cmd'].replace('{arg}', arg.strip())
    resultado = _cmd(f'distrobox enter {distro} -- bash -c "{cmd}"', timeout=90)
    return {'tool': tool['nombre'], 'cmd': cmd, 'output': resultado}

def _kali_run(tool_id, arg):
    """Runs a Kali tool inside the distrobox container"""
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
        return {'error': 'Invalid argument: contains disallowed characters'}
    cmd = cmd_template.replace('{arg}', arg.strip())

    full_cmd = f'distrobox enter kali -- bash -c "{cmd}"'
    resultado = _cmd(full_cmd, timeout=60)
    return {
        'tool': tool['nombre'],
        'cmd': cmd,
        'output': resultado
    }

def _check_url(url):
    """Analyzes a URL with VirusTotal (if a key exists) or local heuristics"""
    datos = {'tipo': 'url_check', 'url': url, 'resultados': {}}
    score = 0
    flags = []

    # Phishing heuristics
    u = url.lower()
    dominios_legitimos = ['paypal','amazon','google','facebook','microsoft','apple','netflix','bancomer','banamex','bbva','santander']
    for marca in dominios_legitimos:
        if marca in u and marca + '.com' not in u:
            flags.append(f'Possible phishing of {marca} (brand in URL but different domain)')
            score += 30

    sospechosos = ['login','secure','verify','account','update','confirm','signin','banking','wallet','password']
    for kw in sospechosos:
        if kw in u:
            flags.append(f'Suspicious keyword: {kw}')
            score += 10

    if u.count('.') > 4:
        flags.append(f'Many subdomains ({u.count(".")} dots)')
        score += 15

    if any(x in u for x in ['-paypal','-amazon','-google','-apple','-microsoft']):
        flags.append('Hyphen with a known brand -- probable phishing')
        score += 40

    if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', u):
        flags.append('URL with a direct IP (not a domain)')
        score += 25

    if len(url) > 100:
        flags.append(f'Very long URL ({len(url)} characters)')
        score += 10

    tlds_raros = ['.xyz','.top','.gq','.ml','.cf','.tk','.pw','.cc']
    for tld in tlds_raros:
        if tld in u:
            flags.append(f'Suspicious TLD: {tld}')
            score += 20

    # VirusTotal if an API key exists
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
                    flags.append(f'VirusTotal: {malicious} engines flag it as MALICIOUS')
                    score += 50
        except Exception as _e: log.debug("source unavailable: %s", _e)

    # AbuseIPDB for the domain's IP
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
                    flags.append(f'AbuseIPDB: IP with {ab_score}% abuse confidence')
                    score += 30
        else:
            datos['resultados']['ip_dominio'] = ip_check
    except Exception as _e: log.debug("source unavailable: %s", _e)

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

    # Approximate entropy
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    import math
    entropia = round(long * math.log2(charset), 1) if charset > 0 else 0

    # Approximate crack time (bcrypt 10k hashes/s)
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
    """Converts case['datos'] into nodes and edges for vis.js"""
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

    # Root node -- target
    obj = case.get('objetivo') or '?'
    obj_id = nid(obj)
    add_node(obj_id, obj, 'objetivo', f'Target: {obj}', size=35)

    for clave, valor in case['datos'].items():
        if not isinstance(valor, dict): continue
        res = valor.get('resultados', {})
        tipo = valor.get('tipo', '')

        # ── DOMAIN ───────────────────────────────────────────────
        if tipo == 'dominio':
            dom = valor.get('objetivo','')
            dom_id = nid('dom_'+dom)
            add_node(dom_id, dom, 'dominio', f'Domain: {dom}', size=28)
            add_edge(obj_id, dom_id, 'dominio')

            for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', str(res.get('dns',{}).get('A',''))):
                iid = nid('ip_'+ip)
                add_node(iid, ip, 'ip', f'IP: {ip}')
                add_edge(dom_id, iid, 'A')

            for sub in res.get('subdominios',[])[:15]:
                sid = nid('sub_'+sub)
                add_node(sid, sub, 'subdominio', f'Subdomain: {sub}')
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
            add_node(dom_id, dom, 'dominio', f'Domain: {dom}', size=28)
            for h in res.get('historial', [])[:15]:
                ip_h = h.get('ip')
                if not ip_h: continue
                iid3 = nid('ip_'+ip_h)
                add_node(iid3, ip_h, 'ip', f'historical IP ({h.get("fecha","?")})')
                add_edge(dom_id, iid3, f'resolved {h.get("fecha","?")}')

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
                add_node(iid2, ip_f, 'ip', f"Same favicon as {dom} -- {org}", size=22)
                add_edge(obj_id, iid2, 'shared favicon')

        # ── USER ─────────────────────────────────────────────────
        elif tipo == 'usuario':
            user = valor.get('objetivo','')
            uid = nid('user_'+user)
            add_node(uid, '@'+user, 'usuario', f'User: {user}', size=28)
            add_edge(obj_id, uid, 'usuario')
            for p in res.get('plataformas',[]) + res.get('maigret',[]):
                plat = p.get('plataforma','?')
                pid2 = nid('plat_'+plat+user)
                add_node(pid2, plat, 'plataforma', p.get('url',''))
                add_edge(uid, pid2, 'profile')
            gh = res.get('github',{})
            if gh.get('email') and gh['email'] != 'hidden':
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
                add_node(sid2, '⚠ Spoofable', 'cve', 'Domain vulnerable to spoofing')
                add_edge(eid4, sid2, 'risk')
            for breach in res.get('hibp_breaches',[])[:5]:
                bid = nid('breach_'+breach)
                add_node(bid, breach, 'cve', f'Breach: {breach}')
                add_edge(eid4, bid, 'leaked in')

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
                add_edge(obj_id, hid, 'exposed secret')

    return {
        'nodes': list(nodes.values()),
        'edges': edges,
        'stats': {
            'nodos': len(nodes),
            'conexiones': len(edges),
            'objetivo': obj
        }
    }

# ── Camera + Facial Search ────────────────────────────────────────────────────

# ── Dark Web Monitor ──────────────────────────────────────────────────────────

def _darkweb_search(query):
    datos = {'tipo': 'darkweb', 'objetivo': query, 'resultados': {}}

    # Ahmia -- indexes .onion without needing Tor
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

    # Pastes -- Pastebin and similar public sites
    try:
        r = SESSION.get(f'https://psbdmp.ws/api/v3/search/{requests.utils.quote(query)}', timeout=8)
        if r.status_code == 200:
            pastes = r.json().get('data', [])[:10]
            datos['resultados']['pastes'] = [{'id': p.get('id'), 'title': p.get('title','?'),
                                               'url': f"https://pastebin.com/{p.get('id')}"} for p in pastes]
    except Exception as _e: log.debug("source unavailable: %s", _e)

    # IntelligenceX (no API key -- basic search)
    try:
        r = SESSION.post('https://2.intelx.io/intelligent/search',
            json={'term': query, 'maxresults': 10, 'media': 0, 'sort': 2, 'terminate': []},
            headers={'x-key': 'PUBLIC'}, timeout=10)
        if r.status_code == 200:
            datos['resultados']['intelx_id'] = r.json().get('id','')
    except Exception as _e: log.debug("source unavailable: %s", _e)

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
        # No API key -- use Censys as a free alternative
        try:
            r = SESSION.get(f'https://search.censys.io/api/v1/search/ipv4?q={requests.utils.quote(query)}&fields=ip,ports,autonomous_system.name,location.country',
                          timeout=10)
            if r.status_code == 200:
                d = r.json()
                datos['resultados']['censys'] = d.get('results', [])[:10]
            else:
                # Fallback: public Shodan web search (limited)
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
                datos['resultados']['error'] = f'Shodan unavailable: {e2}. (With a free API key at shodan.io you get full search.)'
        # Manual banner grab of the IPs found
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
                except Exception as _e: log.debug("source unavailable: %s", _e)
    # Add the history of executed modules
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

# ── Continuous monitor ────────────────────────────────────────────────────────

monitor_state = {'activo': False, 'thread': None, 'alertas': [], 'objetivo': None, 'intervalo': 3600}

def _monitor_loop():
    while monitor_state['activo']:
        objetivo = monitor_state['objetivo']
        if not objetivo:
            time.sleep(60); continue
        # Re-scan domain and user
        try:
            tipo = 'dominio' if re.match(r'^[\w\.-]+\.[a-z]{2,}$', objetivo) else 'persona'
            if tipo == 'dominio':
                nuevo = _osint_dominio(objetivo)
                viejo = case['datos'].get(f'dominio_{objetivo}', {})
                if str(nuevo) != str(viejo):
                    monitor_state['alertas'].append({
                        'ts': datetime.datetime.now().isoformat(),
                        'tipo': 'cambio_dominio',
                        'mensaje': f'Change detected on {objetivo}',
                        'nuevo': nuevo
                    })
        except Exception as _e: log.debug("source unavailable: %s", _e)
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
    contenido = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>OBSIDIAN — {html.escape(str(case.get('objetivo','?')))}</title>
<style>body{{background:#0d0d1a;color:#cdd6f4;font-family:monospace;padding:40px}}
h1{{color:#cba6f7;letter-spacing:.2em;border-bottom:2px solid #313244;padding-bottom:12px}}
h2{{color:#89b4fa;font-size:.9rem;margin:20px 0 6px}}.meta{{color:#6c7086;margin-bottom:28px;font-size:.82rem}}
.section{{background:#1e1e2e;border:1px solid #313244;border-radius:8px;padding:14px;margin:10px 0}}
pre{{color:#a6e3a1;font-size:.78rem;white-space:pre-wrap;word-break:break-all}}
.badge{{background:#f38ba822;color:#f38ba8;padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:700}}</style>
</head><body><h1>⬛ OBSIDIAN REPORT <span class="badge">CONFIDENTIAL</span></h1>
<div class="meta"><b>Target:</b> {html.escape(str(case.get('objetivo','?')))} | <b>Case:</b> {html.escape(nombre)} | <b>Generated:</b> {ts}</div>
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
    except Exception as _e: log.debug("source unavailable: %s", _e)
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
            return jsonify({'error':'Invalid case name'}), 400
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
    if not path: return jsonify({'error':'Invalid case name'}), 400
    with open(path,'w') as f: json.dump(case, f, ensure_ascii=False, indent=2, default=str)
    _db_guardar_caso(case)
    return jsonify({'ok':True, 'path':path})

@app.route('/api/buscar')
def api_buscar():
    termino = request.args.get('q','').strip()
    if not termino: return jsonify({'error':'No search term'}), 400
    return jsonify({'resultados': _db_buscar(termino)})

@app.route('/api/caso/cargar', methods=['POST'])
def api_cargar():
    nombre = (request.json or {}).get('nombre','')
    path = _ruta_caso_segura(nombre)
    if not path: return jsonify({'error':'Invalid case name'}), 400
    if not os.path.exists(path): return jsonify({'error':'Not found'}), 404
    with open(path) as f: data = json.load(f)
    with case_lock: case.update(data)
    return jsonify({'ok':True, 'modulos':len(case['datos'])})

# The security validators (_validar, _objetivo_seguro, _slug_caso,
# _ruta_caso_segura, _url_publica...) now live in core/validacion.py and are
# imported above. Only the business logic remains here.


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
        return jsonify({'error': f'Invalid target: not shaped like {_MODULO_TIPO[mod]}'}), 400

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
# F2 -- Integrated transform engine (endpoints /api/v2/*, additive)
# ════════════════════════════════════════════════════════════════════════════

@transform(entrada='dominio', salidas=('ip',), nombre='dns_a',
           descripcion='A records of the domain (dig)')
def _t_dns_a(entidad, ctx):
    out = run_tool(['dig', entidad.valor, 'A', '+short'], timeout=10)
    for linea in out.splitlines():
        linea = linea.strip()
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', linea):
            ctx.emitir('ip', linea, etiqueta='A')

@transform(entrada='ip', salidas=('dominio',), nombre='ptr',
           descripcion='PTR / reverse DNS (dig -x)')
def _t_ptr(entidad, ctx):
    out = run_tool(['dig', '-x', entidad.valor, '+short'], timeout=10)
    for linea in out.splitlines():
        linea = linea.strip().rstrip('.')
        if linea and not linea.startswith(';'):
            ctx.emitir('dominio', linea, etiqueta='PTR')

@transform(entrada='url', salidas=('tech', 'persona', 'url'), nombre='metadata',
           descripcion='EXIF metadata as pivotable entities: GPS, device, software, author (F9)')
def _t_metadata(entidad, ctx):
    if not _which('exiftool'):
        return
    try:
        r = _fetch_seguro(entidad.valor, timeout=10, stream=True)   # anti-SSRF
    except Exception:
        return
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        for chunk in r.iter_content(8192):
            f.write(chunk)
            if f.tell() > 15_000_000:
                break
        fname = f.name
    try:
        out = run_tool(['exiftool', fname], timeout=20)
        interesantes = {}
        for linea in out.splitlines():
            if ':' not in linea:
                continue
            k, v = (x.strip() for x in linea.split(':', 1))
            if any(t in k.lower() for t in ('gps', 'author', 'creator', 'software',
                                            'camera', 'make', 'model', 'artist')):
                interesantes[k] = v[:100]
        if interesantes:
            entidad.propiedades['metadata'] = interesantes
            # ── EXIF as pivotable entities (step 120) ──
            from urllib.parse import quote as _q
            disp = (f"{interesantes.get('Make', '')} "
                    f"{interesantes.get('Camera Model Name') or interesantes.get('Model', '')}").strip()
            if disp:
                ctx.emitir('tech', disp, etiqueta='device')
            if interesantes.get('Software'):
                ctx.emitir('tech', interesantes['Software'], etiqueta='software')
            for kk in ('Author', 'Creator', 'Artist'):
                if interesantes.get(kk):
                    ctx.emitir('persona', interesantes[kk], etiqueta=kk.lower())
            gps = interesantes.get('GPS Position') or interesantes.get('GPS Latitude')
            if gps:
                entidad.etiquetar('tiene-gps')
                ctx.emitir('url', f'https://www.google.com/maps/search/?api=1&query={_q(gps)}',
                           etiqueta='gps', gps=gps)
    finally:
        try:
            os.unlink(fname)
        except OSError:
            pass

@transform(entrada='dominio', salidas=(), nombre='dorks',
           descripcion='Generates useful Google dorks for the domain (files, panels, indexes, backups)')
def _t_dorks(entidad, ctx):
    from urllib.parse import quote_plus
    d = entidad.valor
    plantillas = [
        ('Exposed files', f'site:{d} (filetype:pdf OR filetype:xls OR filetype:doc)'),
        ('Directory indexes', f'site:{d} intitle:"index of"'),
        ('Login/admin panels', f'site:{d} (inurl:login OR inurl:admin)'),
        ('Config/backups/secrets', f'site:{d} (ext:env OR ext:sql OR ext:bak OR ext:log)'),
        ('Subdomains', f'site:*.{d}'),
        ('Error messages', f'site:{d} ("stack trace" OR "sql syntax" OR "warning")'),
    ]
    entidad.propiedades['dorks'] = [
        {'que': q, 'url': f'https://www.google.com/search?q={quote_plus(query)}'}
        for q, query in plantillas]

@transform(entrada='wallet', salidas=(), nombre='wallet_balance',
           descripcion='Balance and activity of a BTC wallet (blockchain.info, keyless)')
def _t_wallet_balance(entidad, ctx):
    if not re.fullmatch(r'[a-zA-Z0-9]{20,90}', entidad.valor):   # BTC shape, no junk in the URL
        return
    try:
        d = SESSION.get(f'https://blockchain.info/rawaddr/{entidad.valor}?limit=0', timeout=10).json()
        entidad.propiedades['btc_balance'] = round(d.get('final_balance', 0) / 1e8, 8)
        entidad.propiedades['btc_tx'] = d.get('n_tx', 0)
        entidad.propiedades['btc_recibido'] = round(d.get('total_received', 0) / 1e8, 8)
        if d.get('n_tx'):
            entidad.etiquetar('wallet-activa')
    except Exception as _e:
        log.debug("wallet_balance unavailable: %s", _e)

@transform(entrada='dominio', salidas=('hash',), nombre='favicon_hash',
           descripcion='mmh3 hash of the favicon -- pivotable node for Shodan/FOFA (F8)')
def _t_favicon_hash(entidad, ctx):
    try:
        import mmh3
        import codecs
    except ImportError:
        return
    try:
        r = _fetch_seguro(f'https://{entidad.valor}/favicon.ico', timeout=8, stream=False)
        if r.status_code != 200 or not r.content:
            return
        # standard Shodan/FOFA method: base64 (with line breaks) + mmh3
        h = mmh3.hash(codecs.encode(r.content, 'base64'))
        entidad.propiedades['favicon_hash'] = h
        ctx.emitir('hash', str(h), etiqueta='favicon', tipo_hash='favicon')   # pivotable node
    except Exception as _e:
        log.debug("favicon_hash unavailable: %s", _e)

def _pivote_ips(campos):
    """Searches FOFA + Shodan by unified `campos` and returns the set of matching
    IPs. Basis of the pivots (favicon, cert). Free cross-engine dedup (set)."""
    ips = set()
    cred = _key_rotativa('fofa') or os.environ.get('FOFA_KEY', '')
    if cred and ':' in cred:
        email, key = cred.split(':', 1)
        try:
            qb = base64.b64encode(_motor_query('fofa', campos).encode()).decode()
            r = SESSION.get('https://fofa.info/api/v1/search/all',
                            params={'email': email, 'key': key, 'qbase64': qb,
                                    'fields': 'ip', 'size': 100}, timeout=12)
            d = r.json() or {}
            if not d.get('error'):
                for row in d.get('results', []):
                    ips.add(row[0] if isinstance(row, list) else row)
        except Exception as _e:
            log.debug("pivote fofa: %s", _e)
    skey = _key_rotativa('shodan') or os.environ.get('SHODAN_API_KEY', '')
    if skey:
        try:
            r = SESSION.get('https://api.shodan.io/shodan/host/search',
                            params={'key': skey, 'query': _motor_query('shodan', campos)}, timeout=12)
            for m in (r.json() or {}).get('matches', []):
                if m.get('ip_str'):
                    ips.add(m['ip_str'])
        except Exception as _e:
            log.debug("pivote shodan: %s", _e)
    return ips

@transform(entrada='hash', salidas=('ip',), nombre='favicon_pivote', requiere_key=True,
           descripcion='Enumerates IPs serving this favicon (FOFA/Shodan) -- without touching the target (F8)')
def _t_favicon_pivote(entidad, ctx):
    if entidad.propiedades.get('tipo_hash') != 'favicon':
        return
    for ip in _pivote_ips({'favicon': entidad.valor}):
        ctx.emitir('ip', ip, etiqueta='mismo-favicon')

@transform(entrada='dominio', salidas=('subdominio',), nombre='wayback',
           descripcion='Historical snapshot + old subdomains of the domain (Wayback Machine)')
def _t_wayback(entidad, ctx):
    # 1. is there a snapshot? ('available' endpoint, reliable)
    try:
        snap = ((SESSION.get(f'http://archive.org/wayback/available?url={entidad.valor}', timeout=8).json()
                 .get('archived_snapshots', {}) or {}).get('closest', {}))
        if snap.get('available'):
            entidad.propiedades['wayback_desde'] = (snap.get('timestamp', '') or '')[:8]
            entidad.propiedades['wayback_url'] = snap.get('url')
            entidad.etiquetar('archivado')
    except Exception as _e:
        log.debug("wayback available: %s", _e)
    # 2. historical subdomains (CDX; may be blocked in some environments)
    try:
        filas = SESSION.get('http://web.archive.org/cdx/search/cdx',
                            params={'url': f'*.{entidad.valor}', 'output': 'json', 'limit': 300,
                                    'collapse': 'urlkey', 'fl': 'original'}, timeout=15).json()
        vistos = set()
        for fila in (filas[1:] if isinstance(filas, list) else []):
            host = (urlparse(fila[0] if isinstance(fila, list) else fila).hostname or '').lstrip('*.')
            if host.endswith(entidad.valor) and host != entidad.valor and host not in vistos:
                vistos.add(host)
                ctx.emitir('subdominio', host, etiqueta='historical (wayback)')
    except Exception as _e:
        log.debug("wayback cdx: %s", _e)

@transform(entrada='dominio', salidas=('subdominio', 'ip'), nombre='subdominios_ht',
           descripcion='Subdomains (+ their IP) via HackerTarget hostsearch (keyless)')
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
        log.debug("subdominios_ht unavailable: %s", _e)

@transform(entrada='dominio', salidas=('subdominio',), nombre='crtsh',
           descripcion='Subdomains from crt.sh (Certificate Transparency)')
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
        log.debug("crtsh unavailable: %s", _e)

@transform(entrada='dominio', salidas=('subdominio',), nombre='ct_certspotter',
           descripcion='Subdomains from Certificate Transparency (certspotter, keyless)')
def _t_ct_certspotter(entidad, ctx):
    try:
        data = SESSION.get('https://api.certspotter.com/v1/issuances',
                           params={'domain': entidad.valor, 'include_subdomains': 'true',
                                   'expand': 'dns_names'}, timeout=12).json()
        if not isinstance(data, list):   # rate limit / error -> {message: ...}
            return
        vistos = set()
        for cert in data:
            for nombre in cert.get('dns_names', []):
                nombre = nombre.lstrip('*.')
                if nombre.endswith(entidad.valor) and nombre != entidad.valor and nombre not in vistos:
                    vistos.add(nombre)
                    ctx.emitir('subdominio', nombre, etiqueta='subdominio')
    except Exception as _e:
        log.debug("certspotter unavailable: %s", _e)

@transform(entrada='ip', salidas=('pais', 'org', 'asn'), nombre='geo_ip',
           descripcion='Geolocation and network info of the IP (ip-api.com)')
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
        log.debug("geo_ip unavailable: %s", _e)

@transform(entrada='usuario', salidas=('plataforma',), nombre='sherlock',
           descripcion='User accounts across 400+ platforms (Sherlock)')
def _t_sherlock(entidad, ctx):
    if not _which('sherlock'):
        return
    out = run_tool(['sherlock', entidad.valor, '--timeout', '5', '--print-found', '--no-color'], timeout=150)
    for linea in out.splitlines():
        m = re.match(r'\[\+\]\s*(.+?):\s*(https?://\S+)', linea.strip())
        if m:
            ctx.emitir('plataforma', m.group(1).strip(), etiqueta='profile', url=m.group(2).strip())

@transform(entrada='usuario', salidas=('email', 'repo'), nombre='github_usuario',
           descripcion='User email and public repos on GitHub')
def _t_github(entidad, ctx):
    try:
        gh = SESSION.get(f'https://api.github.com/users/{entidad.valor}', timeout=8).json()
        if not gh.get('login'):
            return
        if gh.get('email') and gh['email'] != 'hidden':
            ctx.emitir('email', gh['email'], etiqueta='github email')
        repos = SESSION.get(f'https://api.github.com/users/{entidad.valor}/repos'
                            '?per_page=10&sort=updated', timeout=8)
        if repos.status_code == 200:
            for repo in repos.json():
                if repo.get('name'):
                    ctx.emitir('repo', repo['name'], etiqueta='repo',
                               lenguaje=repo.get('language'), stars=repo.get('stargazers_count'))
    except Exception as _e:
        log.debug("github_usuario unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto',), nombre='puertos',
           descripcion='Open ports and services (nmap top-20)')
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
        # the value carries the IP: port 80 of two hosts != the same node
        ctx.emitir('puerto', f'{entidad.valor}:{num}', etiqueta='open', servicio=servicio)

@transform(entrada='dominio', salidas=('dominio',), nombre='dns_mx',
           descripcion='Mail servers of the domain (MX)')
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
           descripcion='Name servers of the domain (NS)')
def _t_dns_ns(entidad, ctx):
    out = run_tool(['dig', entidad.valor, 'NS', '+short'], timeout=10)
    for linea in out.splitlines():
        host = linea.strip().rstrip('.')
        if host:
            ctx.emitir('dominio', host, etiqueta='NS')

@transform(entrada='email', salidas=('org',), nombre='email_breaches',
           descripcion='Breaches the email appeared in (HIBP; requires a real HIBP_API_KEY)')
def _t_email_breaches(entidad, ctx):
    try:
        hibp_key = _key_rotativa('hibp') or os.environ.get('HIBP_API_KEY', '')
        r = SESSION.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(entidad.valor)}',
            timeout=8,
            headers={'hibp-api-key': hibp_key, 'User-Agent': 'OBSIDIAN-OSINT'})
        if r.status_code == 200:
            for b in r.json():
                nombre = b.get('Name')
                if nombre:
                    ctx.emitir('org', nombre, etiqueta='leaked in')
            entidad.etiquetar('filtrado')
    except Exception as _e:
        log.debug("hibp unavailable: %s", _e)

def _pastes_github(entidad):
    """Target mentions + secret indicators in public GitHub code (where credentials
    really leak). psbdmp is dead; this is the real path, but it needs a free
    GitHub token (in the vault)."""
    token = _key_rotativa('github') or os.environ.get('GITHUB_TOKEN', '')
    if not token:
        return
    try:
        d = SESSION.get('https://api.github.com/search/code',
                        params={'q': f'"{entidad.valor}" (password OR secret OR api_key OR token)', 'per_page': 10},
                        headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'},
                        timeout=12).json()
        n = d.get('total_count')
        if n:
            entidad.propiedades['github_menciones'] = n
            entidad.etiquetar('mencionado-github')
    except Exception as _e:
        log.debug("pastes_github unavailable: %s", _e)

@transform(entrada='dominio', salidas=(), nombre='pastes_github',
           descripcion='Domain mentions + secrets on GitHub (free token in the vault)')
def _t_pastes_github_dom(entidad, ctx):
    _pastes_github(entidad)

@transform(entrada='email', salidas=(), nombre='pastes_github_email',
           descripcion='Email mentions in public GitHub code (free token in the vault)')
def _t_pastes_github_email(entidad, ctx):
    _pastes_github(entidad)

@transform(entrada='email', salidas=('org',), nombre='breaches_xon',
           descripcion='Breaches the email appeared in (XposedOrNot, keyless)')
def _t_breaches_xon(entidad, ctx):
    try:
        r = SESSION.get(f'https://api.xposedornot.com/v1/check-email/{requests.utils.quote(entidad.valor)}',
                        timeout=10)
        if r.status_code != 200:
            return
        breaches = r.json().get('breaches') or []
        lista = breaches[0] if breaches and isinstance(breaches[0], list) else breaches
        for nombre in (lista or [])[:30]:
            if nombre:
                ctx.emitir('org', str(nombre), etiqueta='leaked in')
        if lista:
            entidad.etiquetar('filtrado')
    except Exception as _e:
        log.debug("xposedornot unavailable: %s", _e)

@transform(entrada='email', salidas=(), nombre='stealer_hudsonrock',
           descripcion='Did the email come from an infostealer-infected machine? (HudsonRock, keyless)')
def _t_stealer(entidad, ctx):
    try:
        r = SESSION.get('https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email',
                        params={'email': entidad.valor}, timeout=10)
        msg = (r.json() or {}).get('message', '')
        if 'infected by an info-stealer' in msg:
            entidad.etiquetar('stealer-infectado')
            entidad.propiedades['stealer'] = 'yes (HudsonRock)'
    except Exception as _e:
        log.debug("hudsonrock unavailable: %s", _e)

@transform(entrada='email', salidas=('org',), nombre='breaches',
           descripcion='Breach aggregator: XposedOrNot + LeakCheck (keyless) + HIBP (if key), unified (F10 step 135)')
def _t_breaches(entidad, ctx):
    email = entidad.valor
    fuentes = set()
    try:                                             # XposedOrNot (keyless)
        d = SESSION.get(f'https://api.xposedornot.com/v1/check-email/{email}', timeout=10).json() or {}
        br = d.get('breaches')
        if isinstance(br, list) and br and isinstance(br[0], list):
            fuentes.update(b for b in br[0] if b)
    except Exception as _e:
        log.debug("breaches xon: %s", _e)
    try:                                             # LeakCheck public (keyless)
        d = SESSION.get('https://leakcheck.io/api/public', params={'check': email}, timeout=10).json() or {}
        if d.get('success'):
            for s in d.get('sources', []):
                nombre = s.get('name') if isinstance(s, dict) else s
                if nombre:
                    fuentes.add(nombre)
    except Exception as _e:
        log.debug("breaches leakcheck: %s", _e)
    hibp = _key_rotativa('hibp') or os.environ.get('HIBP_API_KEY', '')
    if hibp:                                          # HIBP (paid, optional)
        try:
            r = SESSION.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                            headers={'hibp-api-key': hibp, 'User-Agent': 'OBSIDIAN'}, timeout=10)
            if r.status_code == 200:
                fuentes.update(b['Name'] for b in (r.json() or []) if b.get('Name'))
        except Exception as _e:
            log.debug("breaches hibp: %s", _e)
    if fuentes:
        entidad.etiquetar('filtrado')
        entidad.propiedades['brechas'] = sorted(fuentes)
        for f in sorted(fuentes)[:30]:
            ctx.emitir('org', f, etiqueta='breach')

@transform(entrada='email', salidas=('url',), nombre='intelx', requiere_key=True,
           descripcion='Historical leak search by selector (Intelligence X, key in vault) (F10 step 134)')
def _t_intelx(entidad, ctx):
    key = _key_rotativa('intelx') or os.environ.get('INTELX_KEY', '')
    if not key:
        return
    try:
        sid = (SESSION.post('https://2.intelx.io/intelligent/search',
                            headers={'x-key': key, 'Content-Type': 'application/json'},
                            json={'term': entidad.valor, 'maxresults': 20, 'media': 0,
                                  'sort': 2, 'terminate': []}, timeout=12).json() or {}).get('id')
        if not sid:
            return
        recs = (SESSION.get('https://2.intelx.io/intelligent/search/result',
                            headers={'x-key': key}, params={'id': sid}, timeout=12).json()
                or {}).get('records', [])
        for rec in recs[:20]:
            sysid = rec.get('systemid')
            if sysid:
                ctx.emitir('url', f'https://intelx.io/?did={sysid}', etiqueta='intelx',
                           nombre=(rec.get('name') or '')[:120], bucket=rec.get('bucket', ''))
    except Exception as _e:
        log.debug("intelx unavailable: %s", _e)

@transform(entrada='email', salidas=('url',), nombre='pastes',
           descripcion='Paste monitoring: psbdmp + dorks to Pastebin/Ghostbin/etc (keyless) (F10 step 133)')
def _t_pastes(entidad, ctx):
    from urllib.parse import quote as _q
    q = entidad.valor
    try:
        d = SESSION.get(f'https://psbdmp.ws/api/v3/search/{_q(q)}', timeout=8).json() or {}
        for p in (d.get('data') or [])[:10]:
            pid = p.get('id')
            if pid:
                ctx.emitir('url', f'https://pastebin.com/{pid}', etiqueta='paste', fuente='psbdmp')
    except Exception as _e:
        log.debug("psbdmp unavailable: %s", _e)
    for sitio in ('pastebin.com', 'ghostbin.com', 'rentry.co', 'justpaste.it'):
        ctx.emitir('url', f'https://www.google.com/search?q={_q(f"{q} site:{sitio}")}',
                   etiqueta=f'paste-dork:{sitio}', sitio=sitio)

@transform(entrada='dominio', salidas=(), nombre='stealer_dominio',
           descripcion='Domain exposure in stealer logs (infected employees/users, HudsonRock keyless) (F10 step 132)')
def _t_stealer_dominio(entidad, ctx):
    try:
        d = SESSION.get('https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain',
                        params={'domain': entidad.valor}, timeout=10).json() or {}
        data = d.get('data', d) or {}
        emp = data.get('employees') or data.get('total_employees') or 0
        usr = data.get('users') or data.get('total_users') or 0
        if isinstance(emp, dict):
            emp = emp.get('total', 0)
        if isinstance(usr, dict):
            usr = usr.get('total', 0)
        if emp or usr:
            entidad.propiedades['stealer_empleados'] = emp
            entidad.propiedades['stealer_usuarios'] = usr
            entidad.etiquetar('stealer-expuesto')
    except Exception as _e:
        log.debug("stealer_dominio unavailable: %s", _e)

@transform(entrada='email', salidas=(), nombre='email_spoofable',
           descripcion='Checks the SPF of the email domain (spoofing risk)')
def _t_email_spoofable(entidad, ctx):
    dominio = entidad.valor.split('@')[-1]
    if not dominio:
        return
    txt = run_tool(['dig', dominio, 'TXT', '+short'], timeout=10)
    tiene_spf = 'v=spf1' in txt.lower()
    entidad.propiedades['spf'] = 'configured' if tiene_spf else 'NOT CONFIGURED'
    if not tiene_spf:
        entidad.etiquetar('spoofable')

def _screenshot(entidad):
    """Web capture with a headless browser (step 68). Does not capture internal
    hosts (_url_publica). Saves the PNG in static and leaves the URL as a prop."""
    if not _url_publica('https://' + entidad.valor):
        return
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.debug("screenshot: playwright missing")
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
        log.debug("screenshot failed: %s", _e)

@transform(entrada='dominio', salidas=(), nombre='screenshot',
           descripcion='Screenshot of the site (headless browser)')
def _t_screenshot_dom(entidad, ctx):
    _screenshot(entidad)

@transform(entrada='subdominio', salidas=(), nombre='screenshot_sub',
           descripcion='Screenshot of the subdomain (headless)')
def _t_screenshot_sub(entidad, ctx):
    _screenshot(entidad)

def _nuclei(entidad):
    """Vulnerability scan with nuclei templates (step 69). Public hosts only.
    Runs via run_tool (argv, no shell); medium+ severity so it does not drag on."""
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
           descripcion='Template-based vulnerability scan (nuclei)')
def _t_nuclei_dom(entidad, ctx):
    _nuclei(entidad)

@transform(entrada='subdominio', salidas=(), nombre='nuclei_sub',
           descripcion='Subdomain vulnerability scan (nuclei)')
def _t_nuclei_sub(entidad, ctx):
    _nuclei(entidad)

def _http_probe(entidad):
    """Probes a host over HTTP and enriches the entity. Uses _fetch_seguro:
    does not probe internal IPs (SSRF) and revalidates redirects."""
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
    # login/admin panel detection (step 56)
    cuerpo = (r.text[:8000] or '').lower()
    titulo = (entidad.propiedades.get('http_title', '') or '').lower()
    señales = ('login', 'log in', 'sign in', 'iniciar sesión', 'admin', 'dashboard',
               'wp-admin', 'phpmyadmin', 'authentication', 'panel')
    if (any(s in titulo for s in señales)
            or 'type="password"' in cuerpo or "type='password'" in cuerpo):
        entidad.etiquetar('panel-login')

def _tech_detect(entidad):
    """Lightweight technology fingerprint from the HTTP response (server,
    powered-by, meta generator, common hints). Not Wappalyzer, but it works."""
    try:
        r = _fetch_seguro(entidad.valor, timeout=8, stream=False)
    except Exception:
        return set()
    techs = set()
    for cab in ('Server', 'X-Powered-By'):
        v = r.headers.get(cab)
        if v:
            techs.add(v.split('/')[0].strip())
    try:
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text[:10000], re.I)
        if m:
            techs.add(m.group(1).split()[0])
    except Exception:
        pass
    cuerpo = r.text[:20000].lower()
    for pista, nombre in [('wp-content', 'WordPress'), ('/_next/', 'Next.js'), ('drupal', 'Drupal'),
                          ('joomla', 'Joomla'), ('cf-ray', 'Cloudflare'), ('x-shopify', 'Shopify')]:
        if pista in cuerpo:
            techs.add(nombre)
    return {t for t in techs if t and len(t) < 40}

@transform(entrada='dominio', salidas=('tech',), nombre='tech',
           descripcion='Technologies the site uses (HTTP fingerprint)')
def _t_tech_dom(entidad, ctx):
    for t in _tech_detect(entidad):
        ctx.emitir('tech', t, etiqueta='uses')

@transform(entrada='subdominio', salidas=('tech',), nombre='tech_sub',
           descripcion='Subdomain technologies (HTTP fingerprint)')
def _t_tech_sub(entidad, ctx):
    for t in _tech_detect(entidad):
        ctx.emitir('tech', t, etiqueta='uses')

@transform(entrada='tech', salidas=('cve',), nombre='cve_lookup',
           descripcion='Critical CVEs associated with the technology (NVD). NO version -> verify applicability')
def _t_cve_lookup(entidad, ctx):
    kw = entidad.valor
    try:
        d = SESSION.get('https://services.nvd.nist.gov/rest/json/cves/2.0',
                        params={'keywordSearch': kw, 'cvssV3Severity': 'CRITICAL', 'resultsPerPage': 8},
                        timeout=15).json()
    except Exception as _e:
        log.debug("nvd unavailable: %s", _e)
        return
    for v in d.get('vulnerabilities', [])[:15]:
        cve = v.get('cve', {}) or {}
        cid = cve.get('id')
        if not cid:
            continue
        # PRECISE anti-noise filter: the tech must be in the CPE (official affected
        # product), not just mentioned in passing in the description.
        cpes = json.dumps(cve.get('configurations', [])).lower()
        if f':{kw.lower()}:' in cpes:
            e = ctx.emitir('cve', cid, etiqueta='critical CVE')
            if e:
                e.etiquetar('sin-verificar-version')

@transform(entrada='dominio', salidas=(), nombre='http_probe',
           descripcion='HTTP probe: status, title, server, redirect (httpx-style)')
def _t_http_probe_dom(entidad, ctx):
    _http_probe(entidad)

@transform(entrada='subdominio', salidas=(), nombre='http_probe_sub',
           descripcion='HTTP probe of the subdomain (httpx-style)')
def _t_http_probe_sub(entidad, ctx):
    _http_probe(entidad)

@transform(entrada='dominio', salidas=('dominio',), nombre='reverse_whois',
           descripcion='Other domains of the same registrant (ViewDNS, free key in the vault). The only F5 one without a keyless option.')
def _t_reverse_whois(entidad, ctx):
    key = _key_rotativa('viewdns') or os.environ.get('VIEWDNS_KEY', '')
    if not key:
        return
    try:
        d = SESSION.get('https://api.viewdns.info/reversewhois/',
                        params={'q': entidad.valor, 'apikey': key, 'output': 'json'}, timeout=12).json()
        for reg in (d.get('response', {}) or {}).get('matches', [])[:50]:
            dom = reg.get('domain')
            if dom and dom != entidad.valor:
                ctx.emitir('dominio', dom, etiqueta='same registrant')
    except Exception as _e:
        log.debug("reverse_whois unavailable: %s", _e)

@transform(entrada='dominio', salidas=('dominio', 'org'), nombre='rdap',
           descripcion='Modern WHOIS (RDAP, no key): registrar, name servers, dates')
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
        log.debug("rdap unavailable: %s", _e)

@transform(entrada='ip', salidas=(), nombre='reputacion_ip',
           descripcion='IP reputation: proxy/VPN, hosting/datacenter, mobile (ip-api, keyless)')
def _t_reputacion_ip(entidad, ctx):
    try:
        d = SESSION.get(f'http://ip-api.com/json/{entidad.valor}?fields=status,proxy,hosting,mobile',
                        timeout=8).json()
        if d.get('status') != 'success':
            return
        if d.get('proxy'):
            entidad.etiquetar('proxy-vpn')
        if d.get('hosting'):
            entidad.etiquetar('hosting')
        if d.get('mobile'):
            entidad.etiquetar('movil')
        entidad.propiedades['proxy'] = bool(d.get('proxy'))
        entidad.propiedades['hosting'] = bool(d.get('hosting'))
    except Exception as _e:
        log.debug("reputacion_ip unavailable: %s", _e)

@transform(entrada='ip', salidas=(), nombre='abuseipdb',
           descripcion='Abuse score of the IP (AbuseIPDB, free key in the vault)')
def _t_abuseipdb(entidad, ctx):
    key = _key_rotativa('abuseipdb') or os.environ.get('ABUSEIPDB_KEY', '')
    if not key:
        return
    try:
        r = SESSION.get('https://api.abuseipdb.com/api/v2/check',
                        params={'ipAddress': entidad.valor, 'maxAgeInDays': 90},
                        headers={'Key': key, 'Accept': 'application/json'}, timeout=8)
        d = (r.json() or {}).get('data', {}) or {}
        score = d.get('abuseConfidenceScore')
        if score is not None:
            entidad.propiedades['abuse_score'] = score
            if score >= 50:
                entidad.etiquetar('abusiva')
    except Exception as _e:
        log.debug("abuseipdb unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto', 'org', 'tech'), nombre='shodan',
           requiere_key=True,
           descripcion='Ports/services/org of the IP (Shodan, key in the vault)')
def _t_shodan(entidad, ctx):
    key = _key_rotativa('shodan') or os.environ.get('SHODAN_API_KEY', '')
    if not key:
        return
    try:
        r = SESSION.get(f'https://api.shodan.io/shodan/host/{entidad.valor}',
                        params={'key': key}, timeout=12)
        d = r.json() or {}
        if d.get('org'):
            ctx.emitir('org', d['org'], etiqueta='org')
        vistos_prod = set()
        for serv in d.get('data', []):
            port = serv.get('port')
            if port:
                ctx.emitir('puerto', f'{entidad.valor}:{port}', etiqueta='shodan',
                           servicio=serv.get('_shodan', {}).get('module') or serv.get('product', ''))
            prod = serv.get('product')
            if prod and prod not in vistos_prod:
                vistos_prod.add(prod)
                ctx.emitir('tech', prod, etiqueta='shodan')
    except Exception as _e:
        log.debug("shodan unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto', 'org', 'tech', 'asn'), nombre='censys',
           requiere_key=True,
           descripcion='Services of the IP (Censys, key "id:secret" in the vault)')
def _t_censys(entidad, ctx):
    cred = _key_rotativa('censys') or os.environ.get('CENSYS_API', '')
    if not cred or ':' not in cred:
        return
    cid, secret = cred.split(':', 1)
    try:
        r = SESSION.get(f'https://search.censys.io/api/v2/hosts/{entidad.valor}',
                        auth=(cid, secret), timeout=12)
        res = (r.json() or {}).get('result', {}) or {}
        aut = res.get('autonomous_system', {}) or {}
        if aut.get('name'):
            ctx.emitir('org', aut['name'], etiqueta='censys')
        if aut.get('asn'):
            ctx.emitir('asn', f"AS{aut['asn']}", etiqueta='censys')
        vistos = set()
        for s in res.get('services', []):
            p = s.get('port')
            if p:
                ctx.emitir('puerto', f"{entidad.valor}:{p}", etiqueta='censys',
                           servicio=s.get('service_name', ''))
            prod = s.get('service_name')
            if prod and prod not in vistos:
                vistos.add(prod)
                ctx.emitir('tech', prod, etiqueta='censys')
    except Exception as _e:
        log.debug("censys unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto', 'tech'), nombre='zoomeye',
           requiere_key=True,
           descripcion='Services of the IP in ZoomEye (CN engine, key in the vault)')
def _t_zoomeye(entidad, ctx):
    key = _key_rotativa('zoomeye') or os.environ.get('ZOOMEYE_KEY', '')
    if not key:
        return
    try:
        r = SESSION.get('https://api.zoomeye.org/host/search',
                        params={'query': _motor_query('zoomeye', {'ip': entidad.valor})},
                        headers={'API-KEY': key}, timeout=12)
        for m in (r.json() or {}).get('matches', []):
            pi = m.get('portinfo', {}) or {}
            p = pi.get('port') or m.get('port')
            if p:
                ctx.emitir('puerto', f"{entidad.valor}:{p}", etiqueta='zoomeye',
                           servicio=pi.get('service', ''))
            app = pi.get('app')
            if app:
                ctx.emitir('tech', app, etiqueta='zoomeye')
    except Exception as _e:
        log.debug("zoomeye unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto', 'dominio'), nombre='fofa',
           requiere_key=True,
           descripcion='Hosts/domains in FOFA (CN engine, key "email:key" in the vault)')
def _t_fofa(entidad, ctx):
    cred = _key_rotativa('fofa') or os.environ.get('FOFA_KEY', '')
    if not cred or ':' not in cred:
        return
    email, key = cred.split(':', 1)
    q = _motor_query('fofa', {'ip': entidad.valor})
    qb = base64.b64encode(q.encode()).decode()
    try:
        r = SESSION.get('https://fofa.info/api/v1/search/all',
                        params={'email': email, 'key': key, 'qbase64': qb,
                                'fields': 'ip,port,domain', 'size': 100}, timeout=12)
        d = r.json() or {}
        if d.get('error'):
            return
        for row in d.get('results', []):
            port = row[1] if len(row) > 1 else None
            dom = row[2] if len(row) > 2 else None
            if port:
                ctx.emitir('puerto', f"{entidad.valor}:{port}", etiqueta='fofa')
            if dom:
                ctx.emitir('dominio', dom, etiqueta='fofa')
    except Exception as _e:
        log.debug("fofa unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto', 'tech'), nombre='quake',
           requiere_key=True,
           descripcion='Services of the IP in Quake/360 (CN engine, key in the vault)')
def _t_quake(entidad, ctx):
    key = _key_rotativa('quake') or os.environ.get('QUAKE_KEY', '')
    if not key:
        return
    try:
        r = SESSION.post('https://quake.360.net/api/v3/search/quake_service',
                         headers={'X-QuakeToken': key, 'Content-Type': 'application/json'},
                         json={'query': _motor_query('quake', {'ip': entidad.valor}), 'size': 50},
                         timeout=12)
        for m in (r.json() or {}).get('data', []):
            p = m.get('port')
            nombre = (m.get('service', {}) or {}).get('name')
            if p:
                ctx.emitir('puerto', f"{entidad.valor}:{p}", etiqueta='quake', servicio=nombre or '')
            if nombre:
                ctx.emitir('tech', nombre, etiqueta='quake')
    except Exception as _e:
        log.debug("quake unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto', 'dominio'), nombre='hunter',
           requiere_key=True,
           descripcion='Hosts/domains in Hunter.how (CN engine, key in the vault)')
def _t_hunter(entidad, ctx):
    key = _key_rotativa('hunter') or os.environ.get('HUNTER_KEY', '')
    if not key:
        return
    q = base64.urlsafe_b64encode(_motor_query('hunter', {'ip': entidad.valor}).encode()).decode()
    try:
        r = SESSION.get('https://api.hunter.how/search',
                        params={'api-key': key, 'query': q, 'page': 1, 'page_size': 20}, timeout=12)
        for m in ((r.json() or {}).get('data', {}) or {}).get('list', []):
            p, dom = m.get('port'), m.get('domain')
            if p:
                ctx.emitir('puerto', f"{entidad.valor}:{p}", etiqueta='hunter')
            if dom:
                ctx.emitir('dominio', dom, etiqueta='hunter')
    except Exception as _e:
        log.debug("hunter unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto',), nombre='netlas',
           requiere_key=True,
           descripcion='Responses of the IP in Netlas (key in the vault)')
def _t_netlas(entidad, ctx):
    key = _key_rotativa('netlas') or os.environ.get('NETLAS_KEY', '')
    if not key:
        return
    try:
        r = SESSION.get('https://app.netlas.io/api/responses/',
                        params={'q': _motor_query('netlas', {'ip': entidad.valor})},
                        headers={'X-API-Key': key}, timeout=12)
        for it in (r.json() or {}).get('items', []):
            p = (it.get('data', {}) or {}).get('port')
            if p:
                ctx.emitir('puerto', f"{entidad.valor}:{p}", etiqueta='netlas')
    except Exception as _e:
        log.debug("netlas unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto',), nombre='criminalip',
           requiere_key=True,
           descripcion='Ports/exposure of the IP (Criminal IP, key in the vault)')
def _t_criminalip(entidad, ctx):
    key = _key_rotativa('criminalip') or os.environ.get('CRIMINALIP_KEY', '')
    if not key:
        return
    try:
        r = SESSION.get('https://api.criminalip.io/v1/asset/ip/report',
                        params={'ip': entidad.valor}, headers={'x-api-key': key}, timeout=12)
        for p in ((r.json() or {}).get('port', {}) or {}).get('data', []) or []:
            num = p.get('open_port_no') or p.get('port')
            if num:
                ctx.emitir('puerto', f"{entidad.valor}:{num}", etiqueta='criminalip',
                           servicio=p.get('app_name', ''))
    except Exception as _e:
        log.debug("criminalip unavailable: %s", _e)

@transform(entrada='ip', salidas=('puerto',), nombre='binaryedge',
           requiere_key=True,
           descripcion='Exposed ports of the IP (BinaryEdge, key in the vault)')
def _t_binaryedge(entidad, ctx):
    key = _key_rotativa('binaryedge') or os.environ.get('BINARYEDGE_KEY', '')
    if not key:
        return
    try:
        r = SESSION.get(f'https://api.binaryedge.io/v2/query/ip/{entidad.valor}',
                        headers={'X-Key': key}, timeout=12)
        for ev in (r.json() or {}).get('events', []):
            p = ev.get('port')
            if p:
                ctx.emitir('puerto', f"{entidad.valor}:{p}", etiqueta='binaryedge')
    except Exception as _e:
        log.debug("binaryedge unavailable: %s", _e)

@transform(entrada='url', salidas=('url',), nombre='reverse_image',
           descripcion='Reverse image search in Yandex/Google/TinEye/Bing (F9, keyless)')
def _t_reverse_image(entidad, ctx):
    for motor, enlace in enlaces_reverse(entidad.valor).items():
        ctx.emitir('url', enlace, etiqueta=f'reverse:{motor}', motor=motor)

@transform(entrada='url', salidas=('url',), nombre='busqueda_facial',
           descripcion='Facial recognition: Yandex (by URL) + FaceCheck/PimEyes (manual upload) (F9)')
def _t_busqueda_facial(entidad, ctx):
    for motor, info in enlaces_facial(entidad.valor).items():
        ctx.emitir('url', info['url'], etiqueta=f'facial:{motor}', motor=motor, modo=info['modo'])

@transform(entrada='telefono', salidas=('url', 'pais'), nombre='telefono_dorks',
           descripcion='Phone search dorks (Truecaller/messaging) + carrier if key (F2 step 33)')
def _t_telefono_dorks(entidad, ctx):
    from urllib.parse import quote as _q
    num = entidad.valor
    limpio = re.sub(r'[^\d+]', '', num)
    dorks = {
        'truecaller': f'{num} site:truecaller.com',
        'whitepages': f'{num} site:whitepages.com',
        'messaging': f'{num} whatsapp OR telegram',
        'general': limpio,
    }
    for nombre, q in dorks.items():
        ctx.emitir('url', f'https://www.google.com/search?q={_q(q)}', etiqueta=f'dork:{nombre}', dork=nombre)
    key = _key_rotativa('numverify') or os.environ.get('NUMVERIFY_KEY', '')
    if key:
        try:
            r = SESSION.get('http://apilayer.net/api/validate',
                            params={'access_key': key, 'number': limpio}, timeout=8)
            d = r.json() or {}
            if d.get('valid'):
                entidad.propiedades['carrier'] = d.get('carrier', '')
                entidad.propiedades['tipo_linea'] = d.get('line_type', '')
                if d.get('country_name'):
                    ctx.emitir('pais', d['country_name'], etiqueta='country')
        except Exception as _e:
            log.debug("numverify unavailable: %s", _e)

@transform(entrada='dominio', salidas=('dominio',), nombre='typosquatting',
           descripcion='Typosquat variants of the domain that ARE registered (F2 step 34)')
def _t_typosquatting(entidad, ctx):
    dom = entidad.valor
    nombre, ext = dom.rsplit('.', 1) if '.' in dom else (dom, 'com')
    variantes = set()
    subs = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 'l': '1'}
    for i, c in enumerate(nombre):
        if c in subs:
            variantes.add(f'{nombre[:i] + subs[c] + nombre[i+1:]}.{ext}')
    teclado = {'q': 'w', 'w': 'e', 'e': 'r', 'r': 't', 't': 'y', 'a': 's', 's': 'd',
               'd': 'f', 'f': 'g', 'g': 'h', 'z': 'x', 'x': 'c', 'c': 'v', 'v': 'b'}
    for i, c in enumerate(nombre.lower()):
        if c in teclado:
            variantes.add(f'{nombre[:i] + teclado[c] + nombre[i+1:]}.{ext}')
    for i in range(len(nombre)):
        variantes.add(f'{nombre[:i] + nombre[i+1:]}.{ext}')
        variantes.add(f'{nombre[:i] + nombre[i]*2 + nombre[i:]}.{ext}')
    variantes.discard(dom)
    registrados, lock = {}, threading.Lock()
    def _chk(v):
        out = run_tool(['dig', v, 'A', '+short'], timeout=4)
        ip = next((l.strip() for l in out.splitlines()
                   if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', l.strip())), None)
        if ip:
            with lock:
                registrados[v] = ip
    ths = [threading.Thread(target=_chk, args=(v,)) for v in list(variantes)[:25]]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout=12)
    for v, ip in registrados.items():
        d = ctx.emitir('dominio', v, etiqueta='typosquat', resuelve=ip)
        if d:
            d.etiquetar('typosquat')

@transform(entrada='org', salidas=('bucket',), nombre='buckets',
           descripcion='Public S3/GCS/Azure buckets by organization name (F2 step 34)')
def _t_buckets(entidad, ctx):
    base = re.sub(r'[^a-z0-9-]', '', entidad.valor.lower().replace(' ', '-').replace('_', '-'))
    if not base:
        return
    variantes = [base, f'{base}-backup', f'{base}-dev', f'{base}-prod', f'{base}-staging',
                 f'{base}-assets', f'{base}-media', f'backup-{base}', f'dev-{base}', f'assets-{base}']
    hallados, lock = {}, threading.Lock()
    def _chk(bucket):
        for url in (f'https://{bucket}.s3.amazonaws.com',
                    f'https://storage.googleapis.com/{bucket}',
                    f'https://{bucket}.blob.core.windows.net'):
            try:
                r = SESSION.get(url, timeout=5)
                if r.status_code in (200, 403):
                    with lock:
                        hallados[bucket] = {'url': url, 'publico': r.status_code == 200}
                    return
            except Exception:
                pass
    ths = [threading.Thread(target=_chk, args=(b,)) for b in variantes]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout=15)
    for bucket, info in hallados.items():
        b = ctx.emitir('bucket', bucket, etiqueta='bucket', url=info['url'], publico=info['publico'])
        if b and info['publico']:
            b.etiquetar('publico')

_TAKEOVER_FP = {
    'github.io': "There isn't a GitHub Pages site here", 'herokuapp.com': 'No such app',
    'amazonaws.com': 'NoSuchBucket', 'azurewebsites.net': '404 Web Site not found',
    'netlify.app': 'Not Found', 'surge.sh': 'project not found',
    'readme.io': "Project doesnt exist", 'zendesk.com': 'Help Center Closed',
    'shopify.com': 'Sorry, this shop is currently unavailable',
}

@transform(entrada='dominio', salidas=('subdominio',), nombre='takeover',
           descripcion='Orphaned subdomains vulnerable to takeover (CNAME to abandoned service) (F2 step 34)')
def _t_takeover(entidad, ctx):
    dom = entidad.valor
    try:
        r = SESSION.get(f'https://crt.sh/?q=%.{dom}&output=json', timeout=12)
        subs = {s.strip().lstrip('*.') for cert in r.json()
                for s in cert.get('name_value', '').split('\n')
                if s.strip().lstrip('*.').endswith(dom) and s.strip().lstrip('*.') != dom}
    except Exception:
        subs = set()
    vulnerables, lock = {}, threading.Lock()
    def _chk(sub):
        cname = run_tool(['dig', sub, 'CNAME', '+short'], timeout=4).strip()
        if not cname:
            return
        for servicio, fp in _TAKEOVER_FP.items():
            if servicio in cname:
                estado = 'POSSIBLE'
                try:
                    if fp.lower() in SESSION.get(f'http://{sub}', timeout=5).text.lower():
                        estado = 'VULNERABLE'
                except Exception:
                    pass
                with lock:
                    vulnerables[sub] = {'cname': cname, 'servicio': servicio, 'estado': estado}
                return
    ths = [threading.Thread(target=_chk, args=(s,)) for s in list(subs)[:20]]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout=20)
    for sub, info in vulnerables.items():
        s = ctx.emitir('subdominio', sub, etiqueta='takeover',
                       servicio=info['servicio'], cname=info['cname'], estado=info['estado'])
        if s:
            s.etiquetar('takeover')          # triggers the r_takeover rule (F4/55)

@transform(entrada='dominio', salidas=('ip',), nombre='passivedns', requiere_key=True,
           descripcion='IP history of the domain (Passive DNS via VirusTotal, key in the vault) (F2 step 34)')
def _t_passivedns(entidad, ctx):
    key = _key_rotativa('virustotal') or os.environ.get('VT_API_KEY', '')
    if not key:
        return
    try:
        r = SESSION.get(f'https://www.virustotal.com/api/v3/domains/{entidad.valor}/resolutions',
                        headers={'x-apikey': key}, params={'limit': 20}, timeout=12)
        for item in (r.json() or {}).get('data', []):
            attr = item.get('attributes', {}) or {}
            ip = attr.get('ip_address')
            if ip:
                fecha = attr.get('date')
                visto = (datetime.datetime.fromtimestamp(fecha, datetime.timezone.utc)
                         .strftime('%Y-%m-%d')) if fecha else ''
                ctx.emitir('ip', ip, etiqueta='pdns-historical', visto=visto)
    except Exception as _e:
        log.debug("passivedns unavailable: %s", _e)

_SECRET_PATTERNS = [
    ('API Key', r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})'),
    ('Secret', r'secret\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})'),
    ('Password', r'password\s*[=:]\s*["\']?([^\s"\']{8,})'),
    ('Token', r'token\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})'),
    ('AWS Key', r'(AKIA[0-9A-Z]{16})'),
    ('Private Key', r'-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----'),
]

@transform(entrada='usuario', salidas=('credencial', 'repo'), nombre='github_sec',
           descripcion='Hardcoded secrets in commits of the user public repos (F4 step 60)')
def _t_github_sec(entidad, ctx):
    user = entidad.valor
    tok = _key_rotativa('github') or os.environ.get('GITHUB_TOKEN', '')
    hdr = {'Authorization': f'token {tok}'} if tok else {}
    try:
        rr = SESSION.get(f'https://api.github.com/users/{user}/repos?per_page=20', headers=hdr, timeout=8)
        if rr.status_code != 200:
            rr = SESSION.get(f'https://api.github.com/orgs/{user}/repos?per_page=20', headers=hdr, timeout=8)
        repos = rr.json()
        if not isinstance(repos, list):
            return
        for repo in repos[:10]:
            full = repo.get('full_name', '')
            if full:
                ctx.emitir('repo', full, etiqueta='repo')
            cr = SESSION.get(f'https://api.github.com/repos/{full}/commits?per_page=5', headers=hdr, timeout=8)
            if cr.status_code != 200:
                continue
            for commit in (cr.json() or [])[:3]:
                sha = commit.get('sha', '')
                dr = SESSION.get(f'https://api.github.com/repos/{full}/commits/{sha}', headers=hdr, timeout=8)
                if dr.status_code != 200:
                    continue
                for f in (dr.json().get('files', []) or [])[:5]:
                    patch = f.get('patch', '') or ''
                    for nombre_pat, patron in _SECRET_PATTERNS:
                        for m in re.findall(patron, patch, re.IGNORECASE):
                            val = (m if isinstance(m, str) else ':'.join(x for x in m if x)) or nombre_pat
                            c = ctx.emitir('credencial', val[:60], etiqueta='secret',
                                           tipo_secreto=nombre_pat, repo=full,
                                           commit=sha[:8], archivo=f.get('filename', '?'))
                            if c:
                                c.etiquetar('secreto-github')
    except Exception as _e:
        log.debug("github_sec unavailable: %s", _e)

@transform(entrada='persona', salidas=('url',), nombre='persona',
           descripcion='OSINT on a person: summary (DuckDuckGo) + dorks (LinkedIn/X/GitHub...) (keyless)')
def _t_persona(entidad, ctx):
    from urllib.parse import quote as _q
    nombre = entidad.valor
    try:
        d = SESSION.get(f'https://api.duckduckgo.com/?q={_q(nombre)}&format=json&no_html=1', timeout=8).json()
        if d.get('AbstractText'):
            entidad.propiedades['resumen'] = d['AbstractText'][:400]
    except Exception as _e:
        log.debug("persona ddg: %s", _e)
    dorks = {'linkedin': f'"{nombre}" site:linkedin.com',
             'x': f'"{nombre}" site:twitter.com OR site:x.com',
             'contact': f'"{nombre}" email OR phone OR address',
             'pdf': f'"{nombre}" filetype:pdf',
             'github': f'"{nombre}" site:github.com',
             'facebook': f'"{nombre}" site:facebook.com'}
    for k, q in dorks.items():
        ctx.emitir('url', f'https://www.google.com/search?q={_q(q)}', etiqueta=f'dork:{k}', dork=k)

@transform(entrada='persona', salidas=('url',), nombre='darkweb',
           descripcion='Dark web search (Ahmia, clearnet .onion index, no Tor) (keyless)')
def _t_darkweb(entidad, ctx):
    from urllib.parse import quote as _q
    try:
        r = SESSION.get(f'https://ahmia.fi/search/?q={_q(entidad.valor)}', timeout=12)
        n = 0
        for m in re.finditer(r'<h4[^>]*><a href="([^"]+)"[^>]*>([^<]+)</a>', r.text, re.DOTALL):
            ctx.emitir('url', m.group(1), etiqueta='onion', titulo=m.group(2).strip()[:80])
            n += 1
            if n >= 15:
                break
    except Exception as _e:
        log.debug("darkweb ahmia: %s", _e)

@transform(entrada='url', salidas=(), nombre='url_check',
           descripcion='URL reputation in URLhaus (abuse.ch, CC0, keyless)')
def _t_url_check(entidad, ctx):
    try:
        d = SESSION.post('https://urlhaus-api.abuse.ch/v1/url/',
                         data={'url': entidad.valor}, timeout=8).json() or {}
        if d.get('query_status') == 'ok':
            entidad.propiedades['urlhaus'] = d.get('threat', 'listed')
            entidad.etiquetar('url-maliciosa')
    except Exception as _e:
        log.debug("url_check urlhaus: %s", _e)

@transform(entrada='url', salidas=('email',), nombre='render_js',
           descripcion='Renders the page with a headless browser (playwright): emails from the final DOM')
def _t_render_js(entidad, ctx):
    url = entidad.valor
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if not _url_publica(url):                    # anti-SSRF: do not render internal hosts
        return
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': 1280, 'height': 900})
            page.goto(url, timeout=20000, wait_until='networkidle')
            entidad.propiedades['render_titulo'] = page.title()
            html_render = page.content()
            browser.close()
        for em in list(set(re.findall(
                r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html_render)))[:15]:
            ctx.emitir('email', em, etiqueta='in-render')
    except Exception as _e:
        log.debug("render_js: %s", _e)

@transform(entrada='archivo', salidas=(), nombre='yara_bulk',
           descripcion='Scans a folder with yara-rules (local only)')
def _t_yara_bulk(entidad, ctx):
    carpeta = entidad.valor
    if not os.path.isdir(carpeta) or not _which('yara-rules'):
        return
    archivos = []
    for root, _dirs, files in os.walk(carpeta):
        for f in files:
            archivos.append(os.path.join(root, f))
        if len(archivos) >= 200:
            break
    hallazgos = []
    for archivo in archivos[:200]:
        try:
            if os.path.getsize(archivo) > 50_000_000:
                continue
            r = subprocess.run(['yara-rules', '/etc/yara/', archivo],
                               capture_output=True, text=True, timeout=15)
            salida = (r.stdout + r.stderr).strip()
        except Exception:
            continue
        if salida and 'no rules matched' not in salida.lower():
            hallazgos.append({'archivo': archivo, 'resultado': salida[:300]})
            if len(hallazgos) >= 50:
                break
    if hallazgos:
        entidad.propiedades['yara_hallazgos'] = hallazgos[:20]
        entidad.etiquetar('yara-match')

@transform(entrada='persona', salidas=(), nombre='wordlist',
           descripcion='Likely password wordlist from the case via AI (Ollama)')
def _t_wordlist(entidad, ctx):
    if not ia.disponible():
        return
    contexto = json.dumps(ctx.almacen.to_dict(), default=str)[:3000]
    prompt = (f'From the OSINT of the target "{entidad.valor}", generate a wordlist of '
              f'likely passwords: names, dates, organization, combinations (name+year, '
              f'name+123), leet speak. 30-50 entries, one per line, passwords only.\n\n'
              f'Data:\n{contexto}')
    try:
        resp = ia.consultar(prompt, max_tokens=600, temp=0.6) or ''
    except Exception as _e:
        log.debug("wordlist ia: %s", _e)
        return
    palabras = [w.strip() for w in resp.split('\n') if len(w.strip()) >= 6][:50]
    if not palabras:
        return
    entidad.propiedades['wordlist'] = palabras
    entidad.propiedades['wordlist_total'] = len(palabras)
    try:
        slug = _slug_caso(entidad.valor.lower()) or 'objetivo'
        ruta = os.path.join(CASES_DIR, f'wordlist_{slug}.txt')
        with open(ruta, 'w', encoding='utf-8') as f:
            f.write('\n'.join(palabras))
        entidad.propiedades['wordlist_archivo'] = ruta
    except Exception as _e:
        log.debug("wordlist guardar: %s", _e)

@transform(entrada='url', salidas=('url',), nombre='cronolocalizacion',
           descripcion='Chronolocation by shadows: SunCalc/ShadowMap (Bellingcat technique) (F9 step 121)')
def _t_cronolocalizacion(entidad, ctx):
    coords = parse_gps(entidad.propiedades.get('gps', ''))
    enlaces = enlaces_cronolocalizacion(*(coords if coords else (None, None)))
    for herr, url in enlaces.items():
        ctx.emitir('url', url, etiqueta=f'sun:{herr}', herramienta=herr)

@transform(entrada='url', salidas=('url',), nombre='satelital',
           descripcion='Satellite cross-check of the location (Google Earth/Sentinel/Bing) -- requires GPS (F9 step 122)')
def _t_satelital(entidad, ctx):
    coords = parse_gps(entidad.propiedades.get('gps', ''))
    if not coords:
        return
    for herr, url in enlaces_satelital(*coords).items():
        ctx.emitir('url', url, etiqueta=f'satellite:{herr}', herramienta=herr)

@transform(entrada='url', salidas=('url',), nombre='landmarks',
           descripcion='Landmark matching by image (Google Lens/Mapillary/Wikimapia) (F9 step 123)')
def _t_landmarks(entidad, ctx):
    for herr, url in enlaces_landmark(entidad.valor).items():
        ctx.emitir('url', url, etiqueta=f'landmark:{herr}', herramienta=herr)

@transform(entrada='url', salidas=(), nombre='ocr',
           descripcion='Cyrillic/Chinese/Latin OCR of the image (tesseract, langs rus+chi_sim+eng) (F9 step 125)')
def _t_ocr(entidad, ctx):
    if not _which('tesseract'):
        return                                       # degrades: tesseract + langs missing
    try:
        r = _fetch_seguro(entidad.valor, timeout=10, stream=True)
    except Exception:
        return
    with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as f:
        for chunk in r.iter_content(8192):
            f.write(chunk)
            if f.tell() > 15_000_000:
                break
        fn = f.name
    try:
        out = run_tool(['tesseract', fn, 'stdout', '-l', 'rus+chi_sim+eng'], timeout=25)
        texto = (out or '').strip()
        if not texto:                                # langs not installed -> try eng only
            texto = (run_tool(['tesseract', fn, 'stdout'], timeout=25) or '').strip()
        if texto:
            entidad.propiedades['ocr'] = texto[:1000]
            entidad.etiquetar('tiene-texto')
    finally:
        try:
            os.unlink(fn)
        except OSError:
            pass

# ── .onion routing over Tor (F10 step 128) -- uses the system tor ─────────────
TOR_PROXY = os.environ.get('OBSIDIAN_TOR', 'socks5h://127.0.0.1:9050')

def _tor_disponible():
    try:
        with socket.create_connection(('127.0.0.1', 9050), timeout=2):
            return True
    except Exception:
        return False

def _fetch_tor(url, timeout=25):
    """GET over Tor (socks5h resolves .onion through Tor itself)."""
    return SESSION.get(url, proxies={'http': TOR_PROXY, 'https': TOR_PROXY},
                       timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})

@transform(entrada='url', salidas=('email', 'url'), nombre='onion_fetch',
           descripcion='Opens a .onion site via Tor and extracts title, emails and .onion links (F10 step 128)')
def _t_onion_fetch(entidad, ctx):
    url = entidad.valor
    if '.onion' not in url:
        return                                       # .onion ONLY (no SSRF to internal IPs)
    if not url.startswith('http'):
        url = 'http://' + url
    if not _tor_disponible():
        entidad.propiedades['tor'] = 'Tor unavailable (start the tor service)'
        return
    try:
        r = _fetch_tor(url)
    except Exception as _e:
        log.debug("onion_fetch: %s", _e)
        return
    m = re.search(r'<title[^>]*>(.*?)</title>', r.text[:8000], re.I | re.S)
    if m:
        entidad.propiedades['onion_titulo'] = re.sub(r'\s+', ' ', m.group(1)).strip()[:120]
    for em in list(set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', r.text)))[:15]:
        ctx.emitir('email', em, etiqueta='in-onion')
    for on in list(set(re.findall(r'[a-z2-7]{16,56}\.onion', r.text)))[:15]:
        ctx.emitir('url', 'http://' + on, etiqueta='onion-link')
    entidad.etiquetar('onion-vivo')

_TG_SESION = os.path.join(HOME, '.obsidian', 'telegram.session')

def _tg_mensajes(usuario, limite=30):
    """Fetches the latest messages from a Telegram user/channel. Returns
    (True, (id, [texts])) or (False, failure_reason). Shared by the Telegram
    transforms (steps 130, 131)."""
    cred = _boveda.obtener('telegram') or os.environ.get('TELEGRAM_API', '')
    if not cred or ':' not in cred:
        return False, 'missing api_id:api_hash (free at my.telegram.org) in the vault'
    if not os.path.exists(_TG_SESION):
        return False, 'login once first: python telegram_login.py'
    api_id, api_hash = cred.split(':', 1)
    try:
        import asyncio
        from telethon import TelegramClient

        async def _run():
            cli = TelegramClient(_TG_SESION, int(api_id), api_hash)
            await cli.connect()
            if not await cli.is_user_authorized():
                return None
            objetivo = await cli.get_entity(usuario)
            textos = [m.text async for m in cli.iter_messages(objetivo, limit=limite) if m.text]
            await cli.disconnect()
            return getattr(objetivo, 'id', None), textos

        res = asyncio.run(_run())
        if not res:
            return False, 'unauthorized session -- re-login'
        return True, res
    except Exception as e:
        return False, f'error: {e}'

@transform(entrada='usuario', salidas=('email', 'url'), nombre='telegram',
           requiere_key=True,
           descripcion='Mentions/links of the user or channel in Telegram (Telethon) (F10 step 130)')
def _t_telegram(entidad, ctx):
    ok, res = _tg_mensajes(entidad.valor)
    if not ok:
        entidad.propiedades['telegram'] = res
        return
    tid, textos = res
    entidad.propiedades['telegram_id'] = tid
    texto = '\n'.join(textos)
    for em in list(set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', texto)))[:15]:
        ctx.emitir('email', em, etiqueta='in-telegram')
    for u in list(set(re.findall(r'https?://[^\s"\'<>]+', texto)))[:15]:
        ctx.emitir('url', u[:200], etiqueta='in-telegram')

_LEAK_KW = ['leak', 'breach', 'database', 'combolist', 'stealer', 'ransomware',
            'dump', 'fullz', 'rdp access', 'initial access', 'base de datos', 'filtracion']

def coincidencias_leak(textos, keywords=None):
    """Messages that mention leak/breach terms (step 131). PURE/testable."""
    kws = keywords or _LEAK_KW
    hits = []
    for t in textos:
        tl = t.lower()
        kw = next((k for k in kws if k in tl), None)
        if kw:
            hits.append({'keyword': kw, 'texto': t[:200]})
    return hits

@transform(entrada='usuario', salidas=('dominio', 'email'), nombre='canal_leaks',
           requiere_key=True,
           descripcion='Watches a Telegram channel for mentions of leaks/breaches/ransomware (F10 step 131)')
def _t_canal_leaks(entidad, ctx):
    ok, res = _tg_mensajes(entidad.valor, limite=100)
    if not ok:
        entidad.propiedades['canal_leaks'] = res
        return
    _tid, textos = res
    hits = coincidencias_leak(textos)
    if not hits:
        return
    entidad.etiquetar('canal-leaks')
    entidad.propiedades['leaks_menciones'] = len(hits)
    entidad.propiedades['leaks_muestra'] = [h['texto'] for h in hits[:5]]
    unido = '\n'.join(h['texto'] for h in hits)
    for dom in list(set(re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', unido.lower())))[:15]:
        ctx.emitir('dominio', dom, etiqueta='mentioned-in-leaks')
    for em in list(set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', unido)))[:15]:
        ctx.emitir('email', em, etiqueta='mentioned-in-leaks')

_HAYSTAK_ONION = ('http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion')

@transform(entrada='persona', salidas=('url',), nombre='haystak',
           descripcion='Dark web search in Haystak (via Tor) -- .onion links (F10 step 129)')
def _t_haystak(entidad, ctx):
    if not _tor_disponible():
        entidad.propiedades['haystak'] = 'requires Tor (start the tor service)'
        return
    from urllib.parse import quote as _q
    try:
        r = _fetch_tor(f'{_HAYSTAK_ONION}/?q={_q(entidad.valor)}', timeout=30)
    except Exception as _e:
        log.debug("haystak: %s", _e)
        return
    for on in list(set(re.findall(r'[a-z2-7]{16,56}\.onion', r.text)))[:15]:
        ctx.emitir('url', 'http://' + on, etiqueta='haystak')

def _descargar_imagen(url):
    """Downloads an image to a temp file (anti-SSRF). Returns the path or None."""
    try:
        r = _fetch_seguro(url, timeout=10, stream=True)
    except Exception:
        return None
    with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as f:
        for chunk in r.iter_content(8192):
            f.write(chunk)
            if f.tell() > 15_000_000:
                break
        return f.name

@transform(entrada='url', salidas=(), nombre='ela', requiere_key=False,
           descripcion='Edit detection via Error Level Analysis (generates ELA image) (F9 step 126)')
def _t_ela(entidad, ctx):
    fn = _descargar_imagen(entidad.valor)
    if not fn:
        return
    try:
        salida_dir = os.path.join(STATIC_DIR, 'ela')
        os.makedirs(salida_dir, exist_ok=True)
        nombre_img = f'{hashlib.md5(entidad.valor.encode()).hexdigest()[:10]}.png'
        max_diff = _ela(fn, os.path.join(salida_dir, nombre_img))
        if max_diff is not None:
            entidad.propiedades['ela_img'] = f'/static/ela/{nombre_img}'
            entidad.propiedades['ela_max_diff'] = max_diff
            entidad.etiquetar('ela-generado')
            if max_diff >= 50:                       # heuristic: review visually
                entidad.etiquetar('revisar-edicion')
    finally:
        try:
            os.unlink(fn)
        except OSError:
            pass

@transform(entrada='url', salidas=('hash',), nombre='phash',
           descripcion='Perceptual hash (dHash): groups the same image reused across profiles (F9 step 127)')
def _t_phash(entidad, ctx):
    fn = _descargar_imagen(entidad.valor)
    if not fn:
        return
    try:
        h = _phash(fn)
        if h:
            entidad.propiedades['phash'] = h
            ctx.emitir('hash', h, etiqueta='phash', tipo_hash='phash')
    finally:
        try:
            os.unlink(fn)
        except OSError:
            pass

_WALLET_RE = {
    'btc': re.compile(r'\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
    'eth': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
}

_ES_BTC = re.compile(r'(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\Z')

@transform(entrada='wallet', salidas=('wallet',), nombre='tx_grafo',
           descripcion='Transaction counterparties of a BTC wallet (blockchain.info, keyless) (F11 step 138)')
def _t_tx_grafo(entidad, ctx):
    addr = entidad.valor
    if not _ES_BTC.match(addr):
        return                                       # BTC only for now (keyless)
    try:
        d = SESSION.get(f'https://blockchain.info/rawaddr/{addr}',
                        params={'limit': 5}, timeout=12).json() or {}
    except Exception as _e:
        log.debug("tx_grafo unavailable: %s", _e)
        return
    contrapartes = set()
    for tx in d.get('txs', [])[:5]:
        for inp in tx.get('inputs', []):
            a = (inp.get('prev_out') or {}).get('addr')
            if a and a != addr:
                contrapartes.add(a)
        for out in tx.get('out', []):
            a = out.get('addr')
            if a and a != addr:
                contrapartes.add(a)
    for c in list(contrapartes)[:30]:
        ctx.emitir('wallet', c, etiqueta='tx', cadena='btc')

_ES_ETH = re.compile(r'0x[a-fA-F0-9]{40}\Z')

@transform(entrada='wallet', salidas=(), nombre='eth_balance',
           descripcion='Balance of an Ethereum wallet (public RPC cloudflare-eth, keyless) (F11 step 142)')
def _t_eth_balance(entidad, ctx):
    if not _ES_ETH.match(entidad.valor):
        return                                       # ETH addresses only
    try:
        d = SESSION.post('https://cloudflare-eth.com',
                         json={'jsonrpc': '2.0', 'method': 'eth_getBalance',
                               'params': [entidad.valor, 'latest'], 'id': 1}, timeout=10).json() or {}
        wei = int(d.get('result', '0x0'), 16)
        entidad.propiedades['eth_balance'] = wei / 1e18
        entidad.propiedades['cadena'] = 'eth'
    except Exception as _e:
        log.debug("eth_balance unavailable: %s", _e)

_RANSOM = {'addrs': None, 'ts': 0}

def _ransom_addrs():
    """Known ransomware addresses (Ransomwhere, CC0). 6h cache."""
    if _RANSOM['addrs'] is not None and time.time() - _RANSOM['ts'] < 21600:
        return _RANSOM['addrs']
    try:
        d = SESSION.get('https://api.ransomwhe.re/addresses', timeout=20).json() or {}
        _RANSOM['addrs'] = {x.get('address') for x in d.get('result', []) if x.get('address')}
        _RANSOM['ts'] = time.time()
    except Exception as _e:
        log.debug("ransomwhere unavailable: %s", _e)
    return _RANSOM['addrs'] or set()

@transform(entrada='wallet', salidas=(), nombre='riesgo_wallet',
           descripcion='Address risk: linked to ransomware? (Ransomwhere, CC0, keyless) (F11 step 141)')
def _t_riesgo_wallet(entidad, ctx):
    if entidad.valor in _ransom_addrs():
        entidad.etiquetar('ransomware')
        entidad.propiedades['riesgo'] = 'linked to ransomware (Ransomwhere)'

@transform(entrada='wallet', salidas=('url',), nombre='exchange_attrib',
           descripcion='Exchange attribution: links to Blockchair/WalletExplorer/Arkham/OXT (F11 step 140)')
def _t_exchange_attrib(entidad, ctx):
    from urllib.parse import quote as _q
    a = _q(entidad.valor)
    enlaces = {'blockchair': f'https://blockchair.com/search?q={a}',
               'walletexplorer': f'https://www.walletexplorer.com/address/{a}',
               'arkham': f'https://intel.arkm.com/explorer/address/{a}',
               'oxt': f'https://oxt.me/address/{a}'}
    for herr, url in enlaces.items():
        ctx.emitir('url', url, etiqueta=f'attrib:{herr}', herramienta=herr)

@transform(entrada='wallet', salidas=('wallet',), nombre='cluster_wallets',
           descripcion='Clustering by co-inputs: addresses of the same owner (heuristic, blockchain.info) (F11 step 139)')
def _t_cluster_wallets(entidad, ctx):
    addr = entidad.valor
    if not _ES_BTC.match(addr):
        return
    try:
        d = SESSION.get(f'https://blockchain.info/rawaddr/{addr}',
                        params={'limit': 20}, timeout=12).json() or {}
    except Exception as _e:
        log.debug("cluster_wallets unavailable: %s", _e)
        return
    mismo = set()
    for tx in d.get('txs', [])[:20]:
        inputs = [(i.get('prev_out') or {}).get('addr') for i in tx.get('inputs', [])]
        inputs = [a for a in inputs if a]
        if addr in inputs:                           # the seed spent alongside these -> same owner
            mismo.update(a for a in inputs if a != addr)
    for a in list(mismo)[:30]:
        w = ctx.emitir('wallet', a, etiqueta='mismo-dueño', cadena='btc')
        if w:
            w.etiquetar('mismo-dueño')

@transform(entrada='url', salidas=('wallet',), nombre='extraer_wallets',
           descripcion='Extracts BTC/ETH addresses from a page (F11 step 137)')
def _t_extraer_wallets(entidad, ctx):
    try:
        r = _fetch_seguro(entidad.valor, timeout=10, stream=False)
    except Exception:
        return
    texto = r.text[:200000]
    for cadena, rx in _WALLET_RE.items():
        for addr in list(set(rx.findall(texto)))[:30]:
            ctx.emitir('wallet', addr, etiqueta=cadena, cadena=cadena)

@transform(entrada='persona', salidas=('url',), nombre='dorks_idioma',
           descripcion='Dorks adapted to the name language (Cyrillic/Chinese/Latin) (F15 step 176)')
def _t_dorks_idioma(entidad, ctx):
    from urllib.parse import quote as _q
    idioma = _ml.detectar_idioma(entidad.valor)
    for d in _ml.dorks_por_idioma(entidad.valor, idioma):
        ctx.emitir('url', f'https://www.google.com/search?q={_q(d)}', etiqueta=f'dork:{idioma}', idioma=idioma)

@transform(entrada='persona', salidas=('url',), nombre='motores_locales',
           descripcion='Search in local engines: Yandex, Baidu, Sogou (they index another internet) (F15 step 174)')
def _t_motores_locales(entidad, ctx):
    for motor, url in _ml.motores_locales(entidad.valor).items():
        ctx.emitir('url', url, etiqueta=f'motor:{motor}', motor=motor)

@transform(entrada='org', salidas=('url',), nombre='registros_regionales',
           descripcion='Company registries by region: QCC (China), RusProfile (Russia), OpenCorporates (F15 step 173)')
def _t_registros_regionales(entidad, ctx):
    for reg, url in _ml.registros_regionales(entidad.valor).items():
        ctx.emitir('url', url, etiqueta=f'registro:{reg}', registro=reg)

@transform(entrada='persona', salidas=('persona',), nombre='transliterar',
           descripcion='Name variants in Cyrillic/Latin to search in each alphabet (F15 step 172)')
def _t_transliterar(entidad, ctx):
    for alfabeto, variante in _ml.transliterar(entidad.valor).items():
        if variante and variante.lower() != entidad.valor.lower():
            ctx.emitir('persona', variante, etiqueta=f'translit:{alfabeto}')

@transform(entrada='usuario', salidas=('url',), nombre='plataformas_regionales',
           descripcion='Profiles on regional platforms: VK, Weibo, Douyin, OK, Telegram (F15 step 171)')
def _t_plataformas_regionales(entidad, ctx):
    for plat, url in _ml.perfiles_regionales(entidad.valor).items():
        ctx.emitir('url', url, etiqueta=f'plataforma:{plat}', plataforma=plat)

_BLOCKLIST = {'nets': None, 'ts': 0}   # in-memory cache (refreshes every 6h)

# ONLY clean-license sources (abuse.ch = CC0) and HIGH confidence (curated C2).
# Do NOT use noisy aggregators like FireHOL: mixed licenses + serious false
# positives (they block whole countries, include TOR which is NOT malicious). A
# match here is a SIGNAL with source, not a "malicious" verdict.
_FEEDS_AMENAZA = [
    ('Feodo Tracker (botnet C2)', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'),
]

def _cargar_blocklist():
    if _BLOCKLIST['nets'] is not None and time.time() - _BLOCKLIST['ts'] < 21600:
        return _BLOCKLIST['nets']
    nets = []
    for fuente, url in _FEEDS_AMENAZA:
        try:
            for linea in SESSION.get(url, timeout=15).text.splitlines():
                linea = linea.strip()
                if not linea or linea.startswith('#'):
                    continue
                try:
                    nets.append((ipaddress.ip_network(linea, strict=False), fuente))
                except ValueError:
                    pass
        except Exception as _e:
            log.debug("feed %s unavailable: %s", url, _e)
    _BLOCKLIST['nets'] = nets
    _BLOCKLIST['ts'] = time.time()
    return nets

@transform(entrada='ip', salidas=(), nombre='ip_blocklist',
           descripcion='Is the IP in high-confidence CC0 threat feeds? (abuse.ch, keyless)')
def _t_ip_blocklist(entidad, ctx):
    try:
        ip = ipaddress.ip_address(entidad.valor)
    except ValueError:
        return
    for red, fuente in _cargar_blocklist():
        if ip in red:
            entidad.etiquetar('listado-amenaza')   # signal, NOT a 'malicious' verdict
            entidad.propiedades['amenaza_fuente'] = fuente
            return

@transform(entrada='ip', salidas=('org',), nombre='greynoise',
           descripcion='Threat intel of the IP (GreyNoise Community, keyless but 25/day; 404=not observed)')
def _t_greynoise(entidad, ctx):
    try:
        r = SESSION.get(f'https://api.greynoise.io/v3/community/{entidad.valor}', timeout=8)
        if r.status_code != 200:   # 404 = IP not observed scanning -> no enrichment
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
        log.debug("greynoise unavailable: %s", _e)

@transform(entrada='dominio', salidas=(), nombre='dns_txt',
           descripcion='TXT records of the domain (SPF, verifications, etc.)')
def _t_dns_txt(entidad, ctx):
    out = run_tool(['dig', entidad.valor, 'TXT', '+short'], timeout=10)
    txt = [l.strip().strip('"') for l in out.splitlines() if l.strip()]
    if txt:
        entidad.propiedades['txt'] = txt[:10]

@transform(entrada='dominio', salidas=('org',), nombre='ssl',
           descripcion='TLS certificate of the domain: issuer and validity')
def _t_ssl(entidad, ctx):
    try:
        contexto = ssl.create_default_context()
        with socket.create_connection((entidad.valor, 443), timeout=8) as sock:
            with contexto.wrap_socket(sock, server_hostname=entidad.valor) as segura:
                cert = segura.getpeercert()
        issuer = dict(x[0] for x in cert.get('issuer', []))
        org = issuer.get('organizationName')
        if org:
            ctx.emitir('org', org, etiqueta='cert issuer')
        cn = dict(x[0] for x in cert.get('subject', [])).get('commonName')
        if cn:
            entidad.propiedades['cert_cn'] = cn          # to pivot (step 115)
        entidad.propiedades['cert_desde'] = cert.get('notBefore')
        entidad.propiedades['cert_expira'] = cert.get('notAfter')
    except Exception as _e:
        log.debug("ssl unavailable: %s", _e)

@transform(entrada='dominio', salidas=('ip',), nombre='cert_pivote', requiere_key=True,
           descripcion='IPs with the same TLS cert (CN) across FOFA/Shodan -- same infra (F8)')
def _t_cert_pivote(entidad, ctx):
    cn = entidad.propiedades.get('cert_cn')
    if not cn:                                            # if ssl did not run, get the CN now
        try:
            contexto = ssl.create_default_context()
            with socket.create_connection((entidad.valor, 443), timeout=8) as sock:
                with contexto.wrap_socket(sock, server_hostname=entidad.valor) as segura:
                    cert = segura.getpeercert()
            cn = dict(x[0] for x in cert.get('subject', [])).get('commonName')
        except Exception:
            cn = None
    if not cn:
        return
    for ip in _pivote_ips({'cert': cn}):
        ctx.emitir('ip', ip, etiqueta='mismo-cert')


@app.route('/api/v2/transforms/<tipo>')
def api_v2_transforms(tipo):
    """Transforms that apply to an entity type (step 35)."""
    ts = [{'nombre': t.nombre, 'salidas': list(t.salidas),
           'requiere_key': t.requiere_key, 'descripcion': t.descripcion}
          for t in REGISTRO.aplicables(tipo)]
    return jsonify({'tipo': tipo, 'transforms': ts})

# The store is mutated by the /run endpoint AND the monitor thread (step 95): a
# lock serializes those writes and the monitor's snapshot reads.
_almacen_lock = threading.RLock()

def _correr_transform_interno(tipo, valor, nombre):
    """Runs a transform and persists (autosave). Shared by /run and the monitor.
    Raises ValueError/KeyError; the caller decides what to do with the error."""
    if not tipo_valido(tipo):
        raise ValueError('invalid entity type')
    semilla = Entidad(tipo, (valor or '').strip())          # may raise ValueError
    if not semilla.valor_bien_formado():
        raise ValueError(f'malformed value for {tipo}')
    if _PROXIES['pool']:
        _rotar_proxy()                                      # OPSEC: rotate proxy per transform (154)
    _higiene_request()                                      # OPSEC: randomize UA (155)
    _jitter()                                               # OPSEC: spacing between requests (156)
    _registrar_huella(nombre, tipo, valor)                  # OPSEC: log your footprint (160)
    with _almacen_lock:
        semilla = _almacen.agregar(semilla)
        producidas = ejecutar_por_nombre(nombre, semilla, _almacen)
        if _ws_activo:                          # autosave (46) + audit (48)
            try:
                _gestor.guardar(_ws_activo, _almacen)
                _gestor.registrar(_ws_activo, nombre, valor, len(producidas))
            except Exception as _e:
                log.warning("autosave failed: %s", _e)
    return producidas

@app.route('/api/v2/run', methods=['POST'])
def api_v2_run():
    """Runs a transform on an entity {tipo, valor} (step 36)."""
    d = request.json or {}
    try:
        producidas = _correr_transform_interno(
            d.get('tipo', ''), d.get('valor', ''), d.get('transform', ''))
    except (KeyError, ValueError) as e:
        return _error(str(e), 400)
    return jsonify({'producidas': [e.to_dict() for e in producidas],
                    'total_entidades': len(_almacen), 'workspace': _ws_activo})

def _estado_datos():
    """Collects system health (touches disk/processes)."""
    por_tipo = {}
    con_key = []
    total = 0
    for tp in TIPOS:
        ts = REGISTRO.aplicables(tp)
        if ts:
            por_tipo[tp] = len(ts)
            total += len(ts)
            con_key += [t.nombre for t in ts if t.requiere_key]
    def _existe(cmd):
        return shutil.which(cmd) is not None
    try:
        import playwright  # noqa: F401
        pw = True
    except Exception:
        pw = False
    herramientas = {'dig': _existe('dig'), 'nmap': _existe('nmap'),
                    'whois': _existe('whois'), 'exiftool': _existe('exiftool'),
                    'nuclei': _existe('nuclei'), 'tailscale': _existe('tailscale'),
                    'playwright': pw}
    try:
        keys = _boveda.servicios()
    except Exception:
        keys = []
    return {
        'generado': datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
        'transforms': {'total': total, 'por_tipo': por_tipo, 'con_key': sorted(set(con_key))},
        'herramientas': herramientas,
        'keys': keys,
        'ia': {'disponible': ia.disponible(), 'modelo': ia.MODELO},
        'workspaces': len(_gestor.listar()),
        'monitor': bool(_monitor and _monitor.activo),
        'ntfy': bool(_ntfy_topic()),
    }

_REGLAS_FILE = os.path.join(HOME, '.obsidian', 'reglas.yaml')

def _cargar_reglas_usuario():
    try:
        if os.path.exists(_REGLAS_FILE):
            with open(_REGLAS_FILE, encoding='utf-8') as f:
                n = cargar_reglas_yaml(f.read())
                log.info("user YAML rules loaded: %d", n)
    except Exception as _e:
        log.warning("could not load YAML rules: %s", _e)

@app.route('/api/v2/reglas', methods=['GET', 'POST'])
def api_v2_reglas():
    """User YAML correlation rules (step 63). POST {yaml} loads and persists them;
    GET returns the active ones."""
    if request.method == 'POST':
        texto = (request.json or {}).get('yaml', '')
        n = cargar_reglas_yaml(texto)
        try:
            os.makedirs(os.path.dirname(_REGLAS_FILE), exist_ok=True)
            with open(_REGLAS_FILE, 'w', encoding='utf-8') as f:
                f.write(texto)
        except Exception as _e:
            log.warning("could not save reglas.yaml: %s", _e)
        return jsonify({'ok': True, 'cargadas': n})
    from core.correlacion import _REGLAS_YAML
    return jsonify({'reglas': _REGLAS_YAML})

@app.route('/api/v2/buscar/traducir', methods=['POST'])
def api_v2_buscar_traducir():
    """Translates a unified query to EACH engine's dialect (F8 step 117).
    Body: {campos:{ip,dominio,favicon,cert,puerto,...}, cn:true|false|null}."""
    d = request.json or {}
    campos = {k: v for k, v in (d.get('campos') or {}).items() if v}
    return jsonify({'campos': campos, 'queries': traducir_todos(campos, d.get('cn'))})

@app.route('/api/v2/estado')
def api_v2_estado():
    """System health in JSON (step 105)."""
    return jsonify(_estado_datos())

@app.route('/v2/estado')
def v2_estado():
    """System status page (step 105)."""
    return Response(render_estado(_estado_datos()), mimetype='text/html')

@app.route('/api/v2/recon', methods=['POST'])
def api_v2_recon():
    """Runs all transforms applicable to the seed in parallel (step 102)."""
    d = request.json or {}
    tipo = d.get('tipo', '')
    valor = (d.get('valor', '') or '').strip()
    if not tipo_valido(tipo):
        return _error('invalid entity type', 400)
    con_keys = bool(d.get('con_keys'))
    with _almacen_lock:
        _almacen.crear(tipo, valor)
    ts = [t for t in REGISTRO.aplicables(tipo) if con_keys or not t.requiere_key]
    tareas = [(tipo, valor, t.nombre) for t in ts]
    res = ejecutar_lote(tareas, _almacen, lock=_almacen_lock)
    if _ws_activo:
        with _almacen_lock:
            try:
                _gestor.guardar(_ws_activo, _almacen)
            except Exception as _e:
                log.warning("autosave recon failed: %s", _e)
    return jsonify({'resultados': res, 'total_entidades': len(_almacen), 'workspace': _ws_activo})

_tareas = GestorTareas()

@app.route('/api/v2/recon_async', methods=['POST'])
def api_v2_recon_async():
    """Launches the recon in the background (step 37) and returns a job_id. Progress
    is listened to on /api/v2/tarea/<id>/stream (SSE). Does not block the request."""
    d = request.json or {}
    tipo = d.get('tipo', '')
    valor = (d.get('valor', '') or '').strip()
    if not tipo_valido(tipo):
        return _error('invalid entity type', 400)
    con_keys = bool(d.get('con_keys'))

    def trabajo(emit):
        with _almacen_lock:
            _almacen.crear(tipo, valor)
        ts = [t for t in REGISTRO.aplicables(tipo) if con_keys or not t.requiere_key]
        tareas = [(tipo, valor, t.nombre) for t in ts]
        emit({'tipo': 'inicio', 'total': len(tareas)})

        def prog(nombre, n, hechas, total):
            emit({'tipo': 'progreso', 'transform': nombre, 'nuevas': n,
                  'hechas': hechas, 'total': total, 'entidades': len(_almacen)})
        res = ejecutar_lote(tareas, _almacen, lock=_almacen_lock, on_progreso=prog)
        if _ws_activo:
            with _almacen_lock:
                try:
                    _gestor.guardar(_ws_activo, _almacen)
                except Exception as _e:
                    log.warning("autosave recon_async: %s", _e)
        return {'resultados': res, 'total_entidades': len(_almacen)}

    return jsonify({'job_id': _tareas.crear(trabajo)})

@app.route('/api/v2/tarea/<tid>')
def api_v2_tarea(tid):
    est = _tareas.estado(tid)
    if not est:
        return _error('task not found', 404)
    return jsonify({'id': est['id'], 'estado': est['estado'], 'resultado': est['resultado']})

@app.route('/api/v2/tarea/<tid>/stream')
def api_v2_tarea_stream(tid):
    if not _tareas.estado(tid):
        return _error('task not found', 404)
    def gen():
        for ev in _tareas.stream(tid):
            yield f'data: {json.dumps(ev)}\n\n'
    return Response(stream_with_context(gen()), mimetype='text/event-stream')

@app.route('/api/v2/entidad', methods=['POST'])
def api_v2_entidad():
    """Adds a seed entity to the graph WITHOUT running transforms (Maltego-style:
    you add the node, then right-click -> transform). F6."""
    d = request.json or {}
    tipo = d.get('tipo', '')
    valor = (d.get('valor', '') or '').strip()
    if not tipo_valido(tipo):
        return _error('invalid entity type', 400)
    try:
        ent = Entidad(tipo, valor)
    except ValueError as e:
        return _error(str(e), 400)
    if not ent.valor_bien_formado():
        return _error(f'malformed value for {tipo}', 400)
    ent = _almacen.agregar(ent)
    if _ws_activo:
        try:
            _gestor.guardar(_ws_activo, _almacen)
        except Exception as _e:
            log.warning("autosave failed: %s", _e)
    return jsonify({'ok': True, 'id': ent.id})

def _autosave():
    if _ws_activo:
        try:
            _gestor.guardar(_ws_activo, _almacen)
        except Exception as _e:
            log.warning("autosave failed: %s", _e)

@app.route('/api/v2/entidad/nota', methods=['POST'])
def api_v2_nota():
    """Analyst note on an entity (F6 step 88)."""
    d = request.json or {}
    e = _almacen.obtener(d.get('id', ''))
    if not e:
        return _error('entity not found', 404)
    e.propiedades['nota'] = (d.get('nota', '') or '')[:1000]
    _autosave()
    return jsonify({'ok': True})

@app.route('/api/v2/entidad/tag', methods=['POST'])
def api_v2_tag():
    """Toggle an analyst tag (interesante/descartado/falso-positivo)."""
    d = request.json or {}
    e = _almacen.obtener(d.get('id', ''))
    if not e:
        return _error('entity not found', 404)
    tag = (d.get('tag', '') or '').strip()[:30]
    if not tag:
        return _error('missing tag', 400)
    e.tags.discard(tag) if tag in e.tags else e.tags.add(tag)
    _autosave()
    return jsonify({'ok': True, 'tags': sorted(e.tags)})

@app.route('/api/v2/grafo')
def api_v2_grafo():
    """Typed graph. ?migrar=1 converts the old case['datos'] to the new model."""
    if request.args.get('migrar') == '1':
        return jsonify(migrar_caso(case).to_dict())
    return jsonify(_almacen.to_dict())

@app.route('/api/v2/workspaces', methods=['GET', 'POST', 'DELETE'])
def api_v2_workspaces():
    """Workspace CRUD (F3 step 44). Each one is an isolated SQLite case."""
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
    """Loads a workspace into memory and makes it the active one (F3 step 45)."""
    global _almacen, _ws_activo
    nombre = (request.json or {}).get('nombre', '')
    try:
        _almacen = _gestor.cargar(nombre)
    except KeyError:
        return _error('workspace not found', 404)
    _ws_activo = _slug_caso(nombre)
    _aplicar_perfil_opsec(_ws_activo)                # non-attribution mode (157)
    return jsonify({'ok': True, 'activo': _ws_activo, 'total_entidades': len(_almacen)})

@app.route('/api/v2/workspaces/historial')
def api_v2_ws_historial():
    """Transform history of the active workspace (F3 step 48)."""
    return jsonify({'historial': _gestor.historial(_ws_activo) if _ws_activo else []})

@app.route('/api/v2/workspaces/snapshot', methods=['GET', 'POST'])
def api_v2_ws_snapshot():
    """Create (POST) or list (GET) snapshots of the active workspace (F3 step 49)."""
    if not _ws_activo:
        return _error('no active workspace', 400)
    if request.method == 'POST':
        try:
            sid = _gestor.snapshot(_ws_activo)
        except KeyError:
            return _error('workspace not found', 404)
        return jsonify({'ok': True, 'snapshot': sid})
    return jsonify({'snapshots': _gestor.listar_snapshots(_ws_activo)})

# ── OPSEC: anonymous mode (all traffic over Tor) -- F13 step 153 ─────────────
_OPSEC = {'anonimo': False}

def _set_anonimo(on):
    _OPSEC['anonimo'] = bool(on)
    SESSION.proxies = {'http': TOR_PROXY, 'https': TOR_PROXY} if on else {}

_HUELLA = []

def _registrar_huella(nombre, tipo, valor):
    """Records which transform you ran on which target and whether it was anonymized
    -- your footprint/exposure while investigating (F13 step 160)."""
    _HUELLA.insert(0, {'ts': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                       'transform': nombre, 'objetivo': f'{tipo}:{valor}',
                       'anonimo': _OPSEC['anonimo'] or bool(_PROXIES['pool'])})
    del _HUELLA[500:]

@app.route('/api/v2/opsec/huella')
def api_v2_opsec_huella():
    """Tu huella: qué tocaste y cuánto fue sin anonimizar (exposición). Paso 160."""
    expuestos = sum(1 for h in _HUELLA if not h['anonimo'])
    return jsonify({'total': len(_HUELLA), 'expuestos': expuestos, 'huella': _HUELLA[:100]})

_KEY_ROT = {}

def _key_rotativa(servicio):
    """Key de un servicio, rotando entre varias cuentas si se guardó 'k1|k2|k3'
    (reparte carga entre cuentas del mismo servicio). Paso 159. Retrocompatible:
    una sola key se devuelve tal cual."""
    raw = _boveda.obtener(servicio)
    if not raw or '|' not in raw:
        return raw
    keys = [k.strip() for k in raw.split('|') if k.strip()]
    if not keys:
        return None
    i = _KEY_ROT.get(servicio, 0)
    _KEY_ROT[servicio] = i + 1
    return keys[i % len(keys)]

_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
]
_OPSEC_HIGIENE = {'on': False}

def _higiene_request():
    """Randomiza el User-Agent para no parecer un bot (F13 paso 155)."""
    if _OPSEC_HIGIENE['on']:
        SESSION.headers['User-Agent'] = secrets.choice(_USER_AGENTS)

@app.route('/api/v2/opsec/higiene', methods=['GET', 'POST'])
def api_v2_opsec_higiene():
    if request.method == 'POST':
        _OPSEC_HIGIENE['on'] = bool((request.json or {}).get('on'))
    return jsonify({'higiene': _OPSEC_HIGIENE['on']})

def _evaluar_fuga(anon, ip_session, ip_real):
    """LEAK si el modo anónimo está on pero la IP vista por Obsidian == la IP real
    (o sea, el tráfico NO sale por Tor/proxy). Puro/testeable. Paso 158."""
    return bool(anon and ip_session and ip_real and ip_session == ip_real)

@app.route('/api/v2/opsec/fuga')
def api_v2_opsec_fuga():
    """Detección de fuga de IP/DNS antes de un transform sensible (F13 paso 158).
    (WebRTC solo aplica en navegador — aquí se cubre la fuga de IP del server.)"""
    anon = _OPSEC['anonimo'] or bool(_PROXIES['pool'])
    ip_session = ip_real = None
    try:
        ip_session = SESSION.get('https://api.ipify.org', timeout=8).text.strip()   # con proxy/Tor
    except Exception:
        pass
    try:
        ip_real = requests.get('https://api.ipify.org', timeout=8).text.strip()     # directo, sin proxy
    except Exception:
        pass
    fuga = _evaluar_fuga(anon, ip_session, ip_real)
    return jsonify({'anonimo': anon, 'ip_via_obsidian': ip_session, 'ip_real': ip_real, 'fuga': fuga,
                    'nota': '⚠ LEAK: your real IP is exposed despite anonymous mode' if fuga
                    else ('ok -- traffic anonymized' if anon else 'anonymous mode off')})

_OPSEC_JITTER = {'min': 0.0, 'max': 0.0}

def _jitter():
    """Espera un tiempo aleatorio entre requests para parecer tráfico normal (F13 paso 156)."""
    lo, hi = _OPSEC_JITTER['min'], _OPSEC_JITTER['max']
    if hi <= 0:
        return 0.0
    d = lo + (hi - lo) * (secrets.randbelow(1000) / 1000.0)
    time.sleep(d)
    return d

@app.route('/api/v2/opsec/jitter', methods=['GET', 'POST'])
def api_v2_opsec_jitter():
    if request.method == 'POST':
        d = request.json or {}
        _OPSEC_JITTER['min'] = max(0.0, float(d.get('min', 0)))
        _OPSEC_JITTER['max'] = max(0.0, float(d.get('max', 0)))
    return jsonify(dict(_OPSEC_JITTER))

_PROXIES = {'pool': [], 'i': 0}

def _rotar_proxy():
    """Pone en el SESSION el siguiente proxy del pool (round-robin). Paso 154."""
    pool = _PROXIES['pool']
    if not pool:
        return None
    p = pool[_PROXIES['i'] % len(pool)]
    _PROXIES['i'] += 1
    SESSION.proxies = {'http': p, 'https': p}
    return p

@app.route('/api/v2/opsec/proxies', methods=['GET', 'POST', 'DELETE'])
def api_v2_opsec_proxies():
    """Pool de proxies que rota por transform (F13 paso 154)."""
    if request.method == 'POST':
        _PROXIES['pool'] = [p for p in ((request.json or {}).get('pool') or []) if p]
        _PROXIES['i'] = 0
        return jsonify({'pool_size': len(_PROXIES['pool'])})
    if request.method == 'DELETE':
        _PROXIES['pool'] = []
        SESSION.proxies = {}
        return jsonify({'pool_size': 0})
    return jsonify({'pool_size': len(_PROXIES['pool']), 'actual': SESSION.proxies.get('https')})

@app.route('/api/v2/opsec/anonimo', methods=['GET', 'POST'])
def api_v2_opsec_anonimo():
    """Enruta TODO el tráfico de Obsidian por Tor para no exponer tu IP (F13 paso 153)."""
    if request.method == 'POST':
        on = bool((request.json or {}).get('on'))
        if on and not _tor_disponible():
            return _error('Tor unavailable (start the tor service)', 503)
        _set_anonimo(on)
    return jsonify({'anonimo': _OPSEC['anonimo'], 'tor': _tor_disponible()})

# ── Modo no-atribución: perfil OPSEC por workspace (F13 paso 157) ────────────
_OPSEC_PROFILES = os.path.join(HOME, '.obsidian', 'opsec_profiles.json')

def _leer_perfiles():
    try:
        with open(_OPSEC_PROFILES, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _aplicar_perfil_opsec(ws):
    """Aísla el caso con su propia identidad de red: aplica el perfil OPSEC del
    workspace (persona, proxies, anónimo, higiene, jitter)."""
    p = _leer_perfiles().get(ws, {})
    _OPSEC_HIGIENE['on'] = bool(p.get('higiene'))
    _OPSEC_JITTER['min'] = float(p.get('jitter_min', 0) or 0)
    _OPSEC_JITTER['max'] = float(p.get('jitter_max', 0) or 0)
    _PROXIES['pool'] = list(p.get('proxies', []) or [])
    _PROXIES['i'] = 0
    _set_anonimo(bool(p.get('anonimo')) and _tor_disponible())
    _OPSEC['persona'] = p.get('persona')
    return p

@app.route('/api/v2/opsec/perfil', methods=['GET', 'POST'])
def api_v2_opsec_perfil():
    """Perfil OPSEC (identidad de red) asociado a un workspace (F13 paso 157)."""
    if request.method == 'POST':
        d = request.json or {}
        ws = _slug_caso(d.get('workspace', '') or '')
        if not ws:
            return _error('missing workspace', 400)
        perfiles = _leer_perfiles()
        perfiles[ws] = d.get('perfil', {}) or {}
        try:
            os.makedirs(os.path.dirname(_OPSEC_PROFILES), exist_ok=True)
            with open(_OPSEC_PROFILES, 'w', encoding='utf-8') as f:
                json.dump(perfiles, f, indent=2, ensure_ascii=False)
        except Exception as e:
            return _error(f'could not save: {e}', 500)
        if ws == _ws_activo:
            _aplicar_perfil_opsec(ws)
        return jsonify({'ok': True})
    return jsonify({'perfil': _leer_perfiles().get(_ws_activo, {}), 'activo': _ws_activo,
                    'estado': {'anonimo': _OPSEC['anonimo'], 'higiene': _OPSEC_HIGIENE['on'],
                               'proxies': len(_PROXIES['pool']), 'persona': _OPSEC.get('persona')}})

_personas = GestorPersonas(os.path.join(HOME, '.obsidian', 'personas.json'))

@app.route('/api/v2/personas', methods=['GET', 'POST', 'DELETE'])
def api_v2_personas():
    """Bóveda de sock puppets: identidades de investigación no atribuibles (F13 paso 152)."""
    if request.method == 'GET':
        nombre = request.args.get('nombre')
        if nombre:
            return jsonify({'persona': _personas.obtener(nombre)})
        return jsonify({'personas': _personas.listar()})
    d = request.json or {}
    nombre = (d.get('nombre', '') or '').strip()
    if not nombre:
        return _error('missing persona name', 400)
    if request.method == 'POST':
        _personas.crear(nombre, d.get('datos', {}))
        return jsonify({'ok': True, 'personas': _personas.listar()})
    _personas.borrar(nombre)   # DELETE
    return jsonify({'ok': True, 'personas': _personas.listar()})

@app.route('/api/v2/keys', methods=['GET', 'POST', 'DELETE'])
def api_v2_keys():
    """Bóveda de API keys cifrada (F3 paso 51). GET lista solo NOMBRES de
    servicio (nunca valores). POST guarda; DELETE borra."""
    if request.method == 'GET':
        return jsonify({'servicios': _boveda.servicios()})
    d = request.json or {}
    servicio = (d.get('servicio', '') or '').strip().lower()
    if not servicio:
        return _error('missing service', 400)
    if request.method == 'POST':
        valor = d.get('valor', '')
        if not valor:
            return _error('missing key value', 400)
        _boveda.guardar(servicio, valor)
        return jsonify({'ok': True, 'servicios': _boveda.servicios()})
    _boveda.borrar(servicio)   # DELETE
    return jsonify({'ok': True, 'servicios': _boveda.servicios()})

# Servicio -> (transform, tipo, valor de prueba conocido con datos)
_TEST_SERVICIO = {
    'shodan': ('shodan', 'ip', '8.8.8.8'), 'censys': ('censys', 'ip', '8.8.8.8'),
    'zoomeye': ('zoomeye', 'ip', '8.8.8.8'), 'fofa': ('fofa', 'ip', '8.8.8.8'),
    'quake': ('quake', 'ip', '8.8.8.8'), 'hunter': ('hunter', 'ip', '8.8.8.8'),
    'netlas': ('netlas', 'ip', '8.8.8.8'), 'criminalip': ('criminalip', 'ip', '8.8.8.8'),
    'binaryedge': ('binaryedge', 'ip', '8.8.8.8'),
    'virustotal': ('passivedns', 'dominio', 'google.com'),
    'abuseipdb': ('abuseipdb', 'ip', '8.8.8.8'),
    'github': ('github_usuario', 'usuario', 'torvalds'),
    'viewdns': ('reverse_whois', 'dominio', 'google.com'),
    'hibp': ('email_breaches', 'email', 'test@example.com'),
}

@app.route('/api/v2/keys/probar', methods=['POST'])
def api_v2_keys_probar():
    """Verifica una key REAL: corre su transform sobre un objetivo conocido y dice
    si el parser produjo datos (así se confirma cada buscador contra su API real)."""
    servicio = ((request.json or {}).get('servicio', '') or '').strip().lower()
    mapeo = _TEST_SERVICIO.get(servicio)
    if not mapeo:
        return _error('service has no defined test', 400)
    nombre, tipo, valor = mapeo
    tiene = bool(_boveda.obtener(servicio))
    alm = Almacen()
    try:
        n = len(ejecutar_por_nombre(nombre, alm.crear(tipo, valor), alm))
    except Exception as e:
        return jsonify({'servicio': servicio, 'ok': False, 'nota': f'error: {e}'})
    if n > 0:
        return jsonify({'servicio': servicio, 'ok': True, 'entidades': n,
                        'nota': f'✓ worked -- {n} real entity(ies)'})
    if not tiene:
        return jsonify({'servicio': servicio, 'ok': False, 'nota': 'no key configured'})
    return jsonify({'servicio': servicio, 'ok': False, 'entidades': 0,
                    'nota': 'key present but 0 results (invalid, out of quota, or different schema?)'})

_TIPOS_ACTIVO = ('dominio', 'subdominio', 'ip', 'puerto', 'tech', 'url', 'cve', 'bucket', 'org')

@app.route('/api/v2/inventario')
def api_v2_inventario():
    """Inventario de activos internet-facing del objetivo, en un solo lugar (F12 paso 144)."""
    inv = {}
    for t in _TIPOS_ACTIVO:
        ents = _almacen.de_tipo(t)
        if ents:
            inv[t] = [{'valor': e.valor, 'tags': sorted(e.tags),
                       'props': {k: e.propiedades[k] for k in list(e.propiedades)[:4]}}
                      for e in sorted(ents, key=lambda x: x.valor)]
    return jsonify({'objetivo': _objetivo_del_almacen(),
                    'total_activos': sum(len(v) for v in inv.values()),
                    'inventario': inv})

@app.route('/api/v2/diff_historico')
def api_v2_diff_historico():
    """Cómo cambió la superficie del objetivo vs un snapshot anterior (F12 paso 151).
    Sin ?snapshot devuelve la lista de snapshots disponibles."""
    if not _ws_activo:
        return _error('no active workspace', 400)
    sid = request.args.get('snapshot')
    if not sid:
        return jsonify({'snapshots': _gestor.listar_snapshots(_ws_activo)})
    try:
        viejo = _gestor.cargar_snapshot(_ws_activo, sid)
    except KeyError:
        return _error('snapshot not found', 404)
    ids_v = {e.id: e for e in viejo.entidades}
    ids_n = {e.id: e for e in _almacen.entidades}
    agregados = [{'tipo': e.tipo, 'valor': e.valor} for i, e in ids_n.items() if i not in ids_v]
    removidos = [{'tipo': e.tipo, 'valor': e.valor} for i, e in ids_v.items() if i not in ids_n]
    return jsonify({'snapshot': sid, 'agregados': agregados, 'removidos': removidos,
                    'total_antes': len(viejo), 'total_ahora': len(_almacen)})

@app.route('/api/v2/exposicion')
def api_v2_exposicion():
    """Score de exposición del objetivo: tamaño de la superficie + riesgo (F12 paso 149)."""
    conteos = {t: len(_almacen.de_tipo(t)) for t in _TIPOS_ACTIVO}
    h = correlacionar(_almacen)
    riesgo = score_riesgo(h)
    return jsonify({'exposicion': score_exposicion(conteos, riesgo), 'riesgo': riesgo,
                    'superficie': conteos, 'hallazgos': len(h)})

@app.route('/api/v2/hallazgos')
def api_v2_hallazgos():
    """Corre el motor de correlación sobre el caso activo (F4 pasos 62, 64)."""
    h = correlacionar(_almacen)
    return jsonify({'hallazgos': [x.to_dict() for x in h], 'score': score_riesgo(h)})

def _objetivo_del_almacen():
    """Mejor candidato a 'objetivo' del caso para el encabezado del reporte.
    Prefiere la SEMILLA (entidad sin procedencia = agregada a mano, no derivada
    por un transform), así el reporte dice el objetivo real y no un dato hijo."""
    ents = _almacen.entidades
    if not ents:
        return None
    obj = _almacen.de_tipo('objetivo')
    if obj:
        return sorted(obj, key=lambda e: e.valor)[0].valor
    orden = {'dominio': 0, 'ip': 1, 'email': 2, 'usuario': 3, 'url': 4, 'wallet': 5}
    semillas = [e for e in ents if not e.procedencia]     # sin procedencia = semilla
    cand = [e for e in (semillas or ents) if e.tipo in orden] or (semillas or ents)
    return sorted(cand, key=lambda e: (orden.get(e.tipo, 9), e.valor))[0].valor

@app.route('/api/v2/reporte')
@app.route('/v2/reporte')
def api_v2_reporte():
    """Reporte HTML autocontenido del caso activo (F7 paso 93): resumen de riesgo,
    hallazgos, inventario de entidades y grafo embebido. ?grafo=0 lo omite (más liviano)."""
    h = correlacionar(_almacen)
    vis_js = None
    if request.args.get('grafo', '1') != '0':
        ruta_vis = os.path.join(STATIC_DIR, _VIS)
        if os.path.exists(ruta_vis):
            with open(ruta_vis, encoding='utf-8') as f:
                vis_js = f.read()
    html_doc = generar_reporte(
        _almacen, hallazgos=h, score=score_riesgo(h),
        meta={'workspace': _ws_activo, 'objetivo': _objetivo_del_almacen()},
        vis_js=vis_js)
    return Response(html_doc, mimetype='text/html')

def _nombre_export():
    base = _slug_caso(_ws_activo) if _ws_activo else 'caso'
    return f'obsidian-{base}-{datetime.datetime.now():%Y%m%d}'

@app.route('/api/v2/export/json')
def api_v2_export_json():
    """Caso completo en JSON, re-importable (F7 paso 94)."""
    h = correlacionar(_almacen)
    data = exportar_json(_almacen, h, score_riesgo(h),
                         {'workspace': _ws_activo, 'objetivo': _objetivo_del_almacen()})
    return Response(data, mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename="{_nombre_export()}.json"'})

@app.route('/api/v2/export/csv')
def api_v2_export_csv():
    """Entidades en CSV plano, saneado contra inyección de fórmulas (F7 paso 94)."""
    data = exportar_csv(_almacen)
    return Response(data, mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename="{_nombre_export()}.csv"'})

# ── Monitoreo continuo (F7 paso 95) ──────────────────────────────────────────
_monitor = None
_monitor_tareas = []

def _monitor_snapshot():
    with _almacen_lock:
        return _snap_estado(_almacen)

def _monitor_refrescar():
    for t in _monitor_tareas:
        try:
            _correr_transform_interno(t['tipo'], t['valor'], t['transform'])
        except Exception as e:
            log.debug("monitor: transform %s falló: %s", t.get('transform'), e)

def _ntfy_topic():
    """Topic de ntfy: env OBSIDIAN_NTFY o la bóveda (clave 'ntfy_topic')."""
    t = os.environ.get('OBSIDIAN_NTFY')
    if t:
        return t
    try:
        return _boveda.obtener('ntfy_topic')
    except Exception:
        return None

def _monitor_alerta(cambios):
    """Hook de alerta del monitor (paso 95): avisa al celular por ntfy (paso 96)."""
    log.info("MONITOR: %s", cambios.resumen())
    topic = _ntfy_topic()
    if topic:
        enviar_ntfy(topic, cambios.resumen(), titulo='OBSIDIAN · cambio detectado',
                    prioridad='high', tags='satellite,warning')

def _tareas_monitor_default():
    """Re-corre, sobre la semilla, los transforms que ya construyeron el grafo."""
    seed_valor = _objetivo_del_almacen()
    if not seed_valor:
        return []
    seed = next((e for e in _almacen.entidades if e.valor == seed_valor), None)
    if not seed:
        return []
    usados = set()
    for e in _almacen.entidades:
        usados |= set(e.origenes)
    aplicables = {t.nombre for t in REGISTRO.aplicables(seed.tipo)}
    return [{'tipo': seed.tipo, 'valor': seed.valor, 'transform': n}
            for n in sorted(usados & aplicables)]

@app.route('/api/v2/monitor', methods=['GET'])
def api_v2_monitor():
    """Estado del monitor + historial de alertas."""
    return jsonify({
        'activo': bool(_monitor and _monitor.activo),
        'intervalo': _monitor.intervalo if _monitor else None,
        'ultimo_ciclo': _monitor.ultimo_ciclo if _monitor else None,
        'tareas': _monitor_tareas,
        'ntfy': bool(_ntfy_topic()),
        'alertas': _monitor.alertas if _monitor else []})

@app.route('/api/v2/monitor/ntfy', methods=['POST'])
def api_v2_monitor_ntfy():
    """Configura el topic de ntfy (bóveda) y manda una notificación de prueba."""
    d = request.json or {}
    topic = (d.get('topic', '') or '').strip()
    if not topic:
        return _error('empty topic', 400)
    try:
        _boveda.guardar('ntfy_topic', topic)
    except Exception as e:
        return _error(f'could not save: {e}', 500)
    ok = enviar_ntfy(topic, 'Notificaciones de OBSIDIAN activadas ✓',
                     titulo='OBSIDIAN', prioridad='default')
    return jsonify({'ok': True, 'prueba_enviada': ok})

@app.route('/api/v2/monitor/start', methods=['POST'])
def api_v2_monitor_start():
    global _monitor, _monitor_tareas
    d = request.json or {}
    intervalo = max(30, int(d.get('intervalo', 300)))     # mínimo 30s (no martillar)
    _monitor_tareas = d.get('tareas') or _tareas_monitor_default()
    if not _monitor_tareas:
        return _error('nothing to monitor: add a target and run transforms first', 400)
    if _monitor and _monitor.activo:
        _monitor.detener()
    _monitor = Monitor(_monitor_snapshot, _monitor_refrescar,
                       on_alerta=_monitor_alerta, intervalo=intervalo)
    _monitor.iniciar()
    return jsonify({'activo': True, 'intervalo': intervalo, 'tareas': _monitor_tareas})

@app.route('/api/v2/monitor/stop', methods=['POST'])
def api_v2_monitor_stop():
    if _monitor:
        _monitor.detener()
    return jsonify({'activo': False})

_PROMPTS_IA = {
    'escenario': ('OSINT collected on "{objetivo}". Generate an ETHICAL pentesting scenario:\n'
                  '1. ENTRY VECTORS (with evidence from the data)\n'
                  '2. Probable KILL CHAIN step by step\n'
                  '3. Relevant MITRE ATT&CK TECHNIQUES (with IDs)\n'
                  '4. TOP 3 most critical vulnerabilities\n'
                  '5. COUNTERMEASURES per vector\n\nData:\n{datos}'),
    'superficie': ('Attack surface map of "{objetivo}":\n'
                   '1. EXPOSED ASSETS (IPs, domains, services, technologies)\n'
                   '2. LEAKED DATA found\n3. TECHNOLOGIES with known CVEs\n'
                   '4. WEAK CONFIGURATIONS\n5. RISK SCORE 0-10 with justification\n'
                   '6. HARDENING RECOMMENDATIONS\n\nData:\n{datos}'),
    'analizar': ('Analyze the WHOLE OSINT case of "{objetivo}" and correlate: what story the data tells '
                 'together, non-obvious findings, and the next 3 investigation steps.\n\nData:\n{datos}'),
    'resumen': ('Summarize the OSINT case of "{objetivo}" in ONE clear paragraph understandable to a '
                'non-technical person: what was found and what it means.\n\nData:\n{datos}'),
    'siguiente': ('You are an OSINT analyst. Given the case of "{objetivo}", suggest the NEXT 3-5 '
                  'concrete investigation steps (what to run and why), prioritized.\n\nData:\n{datos}'),
    'narrativa': ('Write a readable REPORT (prose narrative) of the case of "{objetivo}" from the data: '
                  'context, findings and conclusion. Professional tone.\n\nData:\n{datos}'),
    'clasificar': ('Rank the findings of the case of "{objetivo}" by real RELEVANCE to an attacker '
                   '(not just severity), and briefly explain the order.\n\nData:\n{datos}'),
    'geoloc': ('Geolocate the target/photo of "{objetivo}" from ALL the textual clues in the case '
               '(EXIF/GPS, OCR, languages, domains, titles): give 3-5 location CANDIDATES '
               '(country/city/area) with the reasoning and what to verify. Note: with no vision, reason '
               'over textual clues.\n\nData:\n{datos}'),
}

_FUENTE_POR_IDIOMA = {'ru': 'Yandex / VK', 'zh': 'Baidu / Weibo', 'ar': 'Google (Arabic)',
                      'ja': 'Yahoo Japan', 'ko': 'Naver', 'es_en': 'Google'}

@app.route('/api/v2/zona_horaria', methods=['POST'])
def api_v2_zona_horaria():
    """Zona horaria y hora local de un país, para la cronolocalización (F15 paso 178)."""
    return jsonify(_ml.zona_horaria((request.json or {}).get('pais', '')))

@app.route('/api/v2/normalizar_telefono', methods=['POST'])
def api_v2_normalizar_telefono():
    """Normaliza un teléfono a +E.164 según el país (F15 paso 177)."""
    d = request.json or {}
    return jsonify({'e164': _ml.normalizar_telefono(d.get('numero', ''), d.get('pais', 'US'))})

@app.route('/api/v2/idioma', methods=['POST'])
def api_v2_idioma():
    """Detecta el idioma del texto y sugiere la fuente/motor correcto (F15 paso 175)."""
    idioma = _ml.detectar_idioma((request.json or {}).get('texto', ''))
    return jsonify({'idioma': idioma, 'fuente_sugerida': _FUENTE_POR_IDIOMA.get(idioma, 'Google')})

@app.route('/api/v2/extraer_texto', methods=['POST'])
def api_v2_extraer_texto():
    """Pega texto → entidades tipadas al grafo (F14 paso 161, regex determinista)."""
    texto = (request.json or {}).get('texto', '')
    agregadas = []
    with _almacen_lock:
        for tipo, valor in extraer_entidades(texto):
            try:
                e = _almacen.crear(tipo, valor)
                agregadas.append({'tipo': e.tipo, 'valor': e.valor})
            except Exception:
                pass
        if _ws_activo:
            try:
                _gestor.guardar(_ws_activo, _almacen)
            except Exception as _e:
                log.warning("autosave extraer_texto: %s", _e)
    return jsonify({'agregadas': agregadas, 'total': len(agregadas)})

@app.route('/api/v2/chat', methods=['POST'])
def api_v2_chat():
    """Chat about the case: ask the AI using the graph data (F14 step 170)."""
    if not ia.disponible():
        return _error('AI (Ollama) unavailable', 503)
    pregunta = ((request.json or {}).get('pregunta', '') or '').strip()
    if not pregunta:
        return _error('empty question', 400)
    contexto = json.dumps(_almacen.to_dict(), default=str)[:3500]
    prompt = (f'You are an analyst with access to this OSINT case. Answer the question using ONLY this '
              f'data; if the answer is not in it, say so clearly.\n\nData:\n{contexto}\n\n'
              f'Question: {pregunta}')
    try:
        resp = ia.consultar(prompt, max_tokens=500, temp=0.3)
    except Exception as e:
        return _error(f'AI failed: {e}', 500)
    return jsonify({'pregunta': pregunta, 'respuesta': resp})

@app.route('/api/v2/deteccion_ia', methods=['POST'])
def api_v2_deteccion_ia():
    """A hint (NOT proof) of AI-generated text (F14 step 169). For images, use the
    'ela' transform (126). No reliable keyless method exists -- it is indicative only."""
    if not ia.disponible():
        return _error('AI (Ollama) unavailable', 503)
    texto = ((request.json or {}).get('texto', '') or '')[:3000]
    if not texto.strip():
        return _error('empty text', 400)
    try:
        resp = ia.consultar('Does this text look AI-generated? Give concrete SIGNALS (uniformity, '
                            'generic phrasing, lack of specific detail) and a tentative verdict. '
                            f'Do not invent certainty.\n\n{texto}', max_tokens=400, temp=0.3)
    except Exception as e:
        return _error(f'AI failed: {e}', 500)
    return jsonify({'evaluacion': resp,
                    'aviso': 'A HINT, not proof. There is no reliable keyless AI/deepfake detection; '
                             'for images use the ela transform (Error Level Analysis).'})

@app.route('/api/v2/consulta', methods=['POST'])
def api_v2_consulta():
    """Natural-language query -> transform plan (F14 step 165)."""
    if not ia.disponible():
        return _error('AI (Ollama) unavailable', 503)
    pregunta = ((request.json or {}).get('pregunta', '') or '').strip()
    if not pregunta:
        return _error('empty question', 400)
    disponibles = sorted({t.nombre for tp in TIPOS for t in REGISTRO.aplicables(tp)})
    prompt = (f'You are OBSIDIAN, an OSINT engine. Available transforms: {", ".join(disponibles)}.\n'
              f'The user asks: "{pregunta}". Return a concrete PLAN: which transforms to run, '
              f'on which entity and in what order. Be specific.')
    try:
        resp = ia.consultar(prompt, max_tokens=600, temp=0.3)
    except Exception as e:
        return _error(f'AI failed: {e}', 500)
    return jsonify({'pregunta': pregunta, 'plan': resp})

@app.route('/api/v2/traducir', methods=['POST'])
def api_v2_traducir():
    """Translates foreign text (Chinese/Russian/Arabic...) to English with Ollama (F14 step 162)."""
    if not ia.disponible():
        return _error('AI (Ollama) unavailable', 503)
    texto = ((request.json or {}).get('texto', '') or '')[:4000]
    if not texto.strip():
        return _error('empty text', 400)
    try:
        resp = ia.consultar(f'Translate to English. Return ONLY the translation, no notes '
                            f'or quotes:\n\n{texto}', max_tokens=800, temp=0.2)
    except Exception as e:
        return _error(f'AI failed: {e}', 500)
    return jsonify({'traduccion': resp})

@app.route('/api/v2/ia/<modo>', methods=['POST'])
def api_v2_ia_modo(modo):
    """Case-level AI (step 34 backfill): MITRE scenario / surface / analyze."""
    if modo not in _PROMPTS_IA:
        return _error('invalid mode', 404)
    if not ia.disponible():
        return _error('AI (Ollama) unavailable', 503)
    contexto = json.dumps(_almacen.to_dict(), default=str)[:3500]
    prompt = _PROMPTS_IA[modo].format(objetivo=_objetivo_del_almacen() or 'el objetivo', datos=contexto)
    try:
        resp = ia.consultar(prompt, max_tokens=700, temp=0.4)
    except Exception as e:
        return _error(f'AI failed: {e}', 500)
    return jsonify({'modo': modo, 'resultado': resp})

@app.route('/api/v2/hallazgos/ia', methods=['POST'])
def api_v2_hallazgos_ia():
    """AI-assisted correlation (F4 step 65): Ollama summarizes the risk and
    suggests the next step from the case findings."""
    h = correlacionar(_almacen)
    if not h:
        return jsonify({'resumen': 'No findings to analyze yet. Run more transforms.'})
    conteo = {}
    for e in _almacen.entidades:
        conteo[e.tipo] = conteo.get(e.tipo, 0) + 1
    ents = ', '.join(f'{n} {t}' for t, n in conteo.items())
    lista = '\n'.join(f'- [{x.severidad}] {x.mensaje}' for x in h)
    prompt = (
        f"You are a cybersecurity analyst. In an OSINT investigation on a target "
        f"(entities: {ents}) these findings were detected:\n\n{lista}\n\n"
        f"Risk score: {score_riesgo(h)}/100.\n\n"
        f"In 3-4 sentences: summarize the main risk and suggest the next concrete "
        f"investigation step. Direct, no filler.")
    try:
        texto = ia.consultar(prompt, max_tokens=300)
        return jsonify({'resumen': texto or 'The AI returned no text.'})
    except Exception as e:
        log.warning("AI correlation failed: %s", e)
        return _error('Ollama unavailable (is it running on :11434?)', 503)

@app.route('/api/v2/hallazgos/verificar', methods=['POST'])
def api_v2_verificar():
    """SECOND SHIELD: the AI reviews each finding with the real EVIDENCE, explains
    why it is (or is not) dangerous and flags likely false positives. It SUGGESTS,
    it does not delete -- the human confirms (LLM-as-verifier)."""
    h = correlacionar(_almacen)
    if not h:
        return jsonify({'revisiones': []})
    idmap = {e.id: e for e in _almacen.entidades}
    revisiones = []
    for hall in h[:6]:   # cap so it does not run forever
        ev = []
        for eid in hall.entidades:
            e = idmap.get(eid)
            if e:
                ev.append(f"{e.tipo} {e.valor} | props: {e.propiedades} | tags: {sorted(e.tags)} | fuentes: {sorted(e.origenes)}")
        prompt = (
            "You are a security analyst reviewing an AUTOMATIC alert. Be VERY skeptical "
            "of single-source signals: they can be false positives (CDNs like Cloudflare, "
            "TOR nodes, shared hosting are not malicious on their own).\n\n"
            f"ALERT [{hall.severidad}]: {hall.mensaje}\n"
            "REAL EVIDENCE collected:\n" + ("\n".join(ev) or "(no extra evidence)") + "\n\n"
            "In 2-3 sentences: real risk or likely false positive? WHY (based on the "
            "evidence)? What should the user verify?")
        try:
            razon = ia.consultar(prompt, max_tokens=220, temp=0.3)
        except Exception as e:
            log.warning("verify AI failed: %s", e)
            razon = 'AI unavailable (is Ollama on :11434?)'
        revisiones.append({'hallazgo': hall.mensaje, 'severidad': hall.severidad, 'razon': razon})
    return jsonify({'revisiones': revisiones})

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
            return jsonify({'error': 'Invalid IP: disallowed characters'}), 400
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

# Rate limits por defecto: no más de N ejecuciones concurrentes de cada transform
# que pega a una API de terceros (paso 40). Configurable con OBSIDIAN_LIMITE_API.
from core.transforms import set_limite as _set_limite
_LIMITE_API = int(os.environ.get('OBSIDIAN_LIMITE_API', '2'))
for _rl_nombre in ('crtsh', 'ct_certspotter', 'shodan', 'censys', 'zoomeye', 'fofa',
                   'quake', 'hunter', 'netlas', 'criminalip', 'binaryedge', 'passivedns',
                   'github_sec', 'reverse_whois', 'abuseipdb', 'greynoise'):
    _set_limite(_rl_nombre, _LIMITE_API)

if __name__ == '__main__':
    _cargar_reglas_usuario()
    if os.environ.get('OBSIDIAN_ANONIMO') and _tor_disponible():
        _set_anonimo(True)
    host = os.environ.get('OBSIDIAN_HOST', '127.0.0.1')
    ts = _tailscale_ip()
    lineas = [f"   Este equipo: http://localhost:{PORT}"]
    if host in ('0.0.0.0', '::'):
        lineas.append(f"   LAN:         http://{_get_local_ip()}:{PORT}  (⚠ expuesto a toda la red local)")
    else:
        lineas.append(f"   LAN:         apagada (bind local). Para exponer: OBSIDIAN_HOST=0.0.0.0")
    if ts:
        lineas.append(f"   Tailscale:   http://{ts}:{PORT}  (remoto seguro ✓)")
    else:
        lineas.append(f"   Tailscale:   sin detectar — recomendado para acceso remoto sin abrir la LAN")
    print("\n⬛ OBSIDIAN Web — iniciando...\n" + "\n".join(lineas) + "\n")
    app.run(host=host, port=PORT, debug=False, threaded=True)
