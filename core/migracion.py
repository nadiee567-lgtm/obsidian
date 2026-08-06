"""Migration from the old format to the typed model -- F1 step 24.

Converts the flat `case['datos']` (per-module dict: {tipo, objetivo, resultados})
into a Store of typed entities/relations. Replicates the mapping _build_grafo
already did, so existing cases aren't lost when moving to the new model.

Defensive: a malformed module is skipped, it does not take down the whole migration."""
import re

from core.modelo import Store

_RE_IP = re.compile(r'\d+\.\d+\.\d+\.\d+')


def migrate_case(case: dict) -> Store:
    """case (dict with 'objetivo' and 'datos') -> typed Store."""
    alm = Store()
    objetivo = case.get('objetivo')
    raiz = alm.create('objetivo', objetivo, origenes={'caso'}) if objetivo else None

    for clave, valor in (case.get('datos') or {}).items():
        if not isinstance(valor, dict):
            continue
        tipo = valor.get('tipo', '')
        res = valor.get('resultados', {}) or {}
        try:
            _MIGRADORES.get(tipo, lambda *a: None)(alm, raiz, valor, res, clave)
        except Exception:
            continue   # malformed module: skipped
    return alm


def _rel(alm, a, b, etiqueta):
    if a is not None and b is not None:
        alm.relate(a, b, etiqueta)


def _mig_dominio(alm, raiz, valor, res, origen):
    dom = valor.get('objetivo', '')
    if not dom:
        return
    d = alm.create('dominio', dom, origenes={origen})
    _rel(alm, raiz, d, 'dominio')
    for ip in _RE_IP.findall(str(res.get('dns', {}).get('A', ''))):
        _rel(alm, d, alm.create('ip', ip, origenes={origen}), 'A')
    for sub in res.get('subdominios', [])[:50]:
        _rel(alm, d, alm.create('subdominio', sub, origenes={origen}), 'subdominio')
    for email in res.get('emails', [])[:30]:
        _rel(alm, d, alm.create('email', email, origenes={origen}), 'email')
    for h, v in (res.get('tecnologias', {}) or {}).items():
        if v:
            _rel(alm, d, alm.create('tech', str(v), origenes={origen}), h.lower())


def _mig_ip(alm, raiz, valor, res, origen):
    ip = valor.get('objetivo', '')
    if not ip:
        return
    i = alm.create('ip', ip, origenes={origen})
    _rel(alm, raiz, i, 'ip')
    geo = res.get('geo', {}) or {}
    if geo.get('country'):
        _rel(alm, i, alm.create('pais', geo['country'], origenes={origen}), 'location')
    if geo.get('org'):
        _rel(alm, i, alm.create('org', geo['org'], origenes={origen}), 'org')
    if res.get('ptr'):
        _rel(alm, i, alm.create('dominio', res['ptr'], origenes={origen}), 'PTR')


def _mig_usuario(alm, raiz, valor, res, origen):
    user = valor.get('objetivo', '')
    if not user:
        return
    u = alm.create('usuario', user, origenes={origen})
    _rel(alm, raiz, u, 'usuario')
    for p in (res.get('plataformas', []) or []) + (res.get('maigret', []) or []):
        plat = p.get('plataforma')
        if plat:
            e = alm.create('plataforma', plat, origenes={origen},
                          propiedades={'url': p.get('url', '')})
            _rel(alm, u, e, 'profile')
    gh = res.get('github', {}) or {}
    if gh.get('email') and gh['email'] != 'oculto':
        _rel(alm, u, alm.create('email', gh['email'], origenes={origen}), 'email')
    for repo in res.get('github_repos', [])[:10]:
        if repo.get('nombre'):
            _rel(alm, u, alm.create('repo', repo['nombre'], origenes={origen}), 'repo')


def _mig_email(alm, raiz, valor, res, origen):
    email = valor.get('objetivo', '')
    if not email:
        return
    props = {}
    sec = res.get('email_sec', {}) or {}
    if sec.get('spoofable'):
        props['spoofable'] = True
    breaches = res.get('hibp_breaches', []) or []
    if breaches:
        props['hibp_breaches'] = breaches
    e = alm.create('email', email, origenes={origen}, propiedades=props)
    if sec.get('spoofable'):
        e.tag('spoofable')
    if breaches:
        e.tag('filtrado')
    _rel(alm, raiz, e, 'email')


def _mig_buckets(alm, raiz, valor, res, origen):
    for b in res.get('buckets', []) or []:
        if not b.get('bucket'):
            continue
        e = alm.create('bucket', b['bucket'], origenes={origen},
                      propiedades={'url': b.get('url', ''), 'publico': b.get('publico', False)})
        if b.get('publico'):
            e.tag('publico')
        _rel(alm, raiz, e, 'bucket')


def _mig_takeover(alm, raiz, valor, res, origen):
    for v in res.get('vulnerables', []) or []:
        if not v.get('subdominio'):
            continue
        e = alm.create('subdominio', v['subdominio'], origenes={origen},
                      propiedades={'servicio': v.get('servicio'), 'status': v.get('status')})
        e.tag('takeover', 'vulnerable')
        _rel(alm, raiz, e, 'takeover')


def _mig_typo(alm, raiz, valor, res, origen):
    for d in res.get('registrados', []) or []:
        if not d.get('dominio'):
            continue
        e = alm.create('dominio', d['dominio'], origenes={origen},
                      propiedades={'ip': d.get('ip')})
        e.tag('typosquat')
        _rel(alm, raiz, e, 'typosquat')


def _mig_github_secrets(alm, raiz, valor, res, origen):
    for h in res.get('hallazgos', []) or []:
        if not h.get('valor'):
            continue
        e = alm.create('credencial', h['valor'], origenes={origen},
                      propiedades={'tipo_secreto': h.get('tipo'), 'repo': h.get('repo'),
                                   'commit': h.get('commit')})
        e.tag('expuesto')
        _rel(alm, raiz, e, 'exposed secret')


def _mig_passivedns(alm, raiz, valor, res, origen):
    dom = valor.get('objetivo', '')
    d = alm.create('dominio', dom, origenes={origen}) if dom else raiz
    for h in res.get('historial', [])[:30]:
        if h.get('ip'):
            _rel(alm, d, alm.create('ip', h['ip'], origenes={origen}),
                 f"resolved {h.get('fecha', '?')}")


def _mig_favicon(alm, raiz, valor, res, origen):
    for m in res.get('relacionados', [])[:30]:
        if m.get('ip'):
            e = alm.create('ip', m['ip'], origenes={origen},
                          propiedades={'org': m.get('org')})
            e.tag('favicon-compartido')
            _rel(alm, raiz, e, 'shared favicon')


_MIGRADORES = {
    'dominio': _mig_dominio,
    'ip': _mig_ip,
    'usuario': _mig_usuario,
    'email': _mig_email,
    'buckets': _mig_buckets,
    'subdomain_takeover': _mig_takeover,
    'typosquatting': _mig_typo,
    'github_secrets': _mig_github_secrets,
    'passivedns': _mig_passivedns,
    'favicon': _mig_favicon,
}
