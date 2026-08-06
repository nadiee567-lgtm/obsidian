"""Migration from the old format to the typed model -- F1 step 24.

Converts the flat `case['data']` (per-module dict: {type, target, results})
into a Store of typed entities/relations. Replicates the mapping _build_graph
already did, so existing cases aren't lost when moving to the new model.

Defensive: a malformed module is skipped, it does not take down the whole migration."""
import re

from core.modelo import Store

_RE_IP = re.compile(r'\d+\.\d+\.\d+\.\d+')


def migrate_case(case: dict) -> Store:
    """case (dict with 'target' and 'data') -> typed Store."""
    alm = Store()
    target = case.get('target')
    raiz = alm.create('target', target, sources={'caso'}) if target else None

    for key, value in (case.get('data') or {}).items():
        if not isinstance(value, dict):
            continue
        type = value.get('type', '')
        res = value.get('results', {}) or {}
        try:
            _MIGRADORES.get(type, lambda *a: None)(alm, raiz, value, res, key)
        except Exception:
            continue   # malformed module: skipped
    return alm


def _rel(alm, a, b, label):
    if a is not None and b is not None:
        alm.relate(a, b, label)


def _mig_domain(alm, raiz, value, res, source):
    dom = value.get('target', '')
    if not dom:
        return
    d = alm.create('domain', dom, sources={source})
    _rel(alm, raiz, d, 'domain')
    for ip in _RE_IP.findall(str(res.get('dns', {}).get('A', ''))):
        _rel(alm, d, alm.create('ip', ip, sources={source}), 'A')
    for sub in res.get('subdominios', [])[:50]:
        _rel(alm, d, alm.create('subdomain', sub, sources={source}), 'subdomain')
    for email in res.get('emails', [])[:30]:
        _rel(alm, d, alm.create('email', email, sources={source}), 'email')
    for h, v in (res.get('tecnologias', {}) or {}).items():
        if v:
            _rel(alm, d, alm.create('tech', str(v), sources={source}), h.lower())


def _mig_ip(alm, raiz, value, res, source):
    ip = value.get('target', '')
    if not ip:
        return
    i = alm.create('ip', ip, sources={source})
    _rel(alm, raiz, i, 'ip')
    geo = res.get('geo', {}) or {}
    if geo.get('country'):
        _rel(alm, i, alm.create('country', geo['country'], sources={source}), 'location')
    if geo.get('org'):
        _rel(alm, i, alm.create('org', geo['org'], sources={source}), 'org')
    if res.get('ptr'):
        _rel(alm, i, alm.create('domain', res['ptr'], sources={source}), 'PTR')


def _mig_user(alm, raiz, value, res, source):
    user = value.get('target', '')
    if not user:
        return
    u = alm.create('user', user, sources={source})
    _rel(alm, raiz, u, 'user')
    for p in (res.get('plataformas', []) or []) + (res.get('maigret', []) or []):
        plat = p.get('platform')
        if plat:
            e = alm.create('platform', plat, sources={source},
                          properties={'url': p.get('url', '')})
            _rel(alm, u, e, 'profile')
    gh = res.get('github', {}) or {}
    if gh.get('email') and gh['email'] != 'oculto':
        _rel(alm, u, alm.create('email', gh['email'], sources={source}), 'email')
    for repo in res.get('github_repos', [])[:10]:
        if repo.get('name'):
            _rel(alm, u, alm.create('repo', repo['name'], sources={source}), 'repo')


def _mig_email(alm, raiz, value, res, source):
    email = value.get('target', '')
    if not email:
        return
    props = {}
    sec = res.get('email_sec', {}) or {}
    if sec.get('spoofable'):
        props['spoofable'] = True
    breaches = res.get('hibp_breaches', []) or []
    if breaches:
        props['hibp_breaches'] = breaches
    e = alm.create('email', email, sources={source}, properties=props)
    if sec.get('spoofable'):
        e.tag('spoofable')
    if breaches:
        e.tag('leaked')
    _rel(alm, raiz, e, 'email')


def _mig_buckets(alm, raiz, value, res, source):
    for b in res.get('buckets', []) or []:
        if not b.get('bucket'):
            continue
        e = alm.create('bucket', b['bucket'], sources={source},
                      properties={'url': b.get('url', ''), 'public': b.get('public', False)})
        if b.get('public'):
            e.tag('public')
        _rel(alm, raiz, e, 'bucket')


def _mig_takeover(alm, raiz, value, res, source):
    for v in res.get('vulnerables', []) or []:
        if not v.get('subdomain'):
            continue
        e = alm.create('subdomain', v['subdomain'], sources={source},
                      properties={'service': v.get('service'), 'status': v.get('status')})
        e.tag('takeover', 'vulnerable')
        _rel(alm, raiz, e, 'takeover')


def _mig_typo(alm, raiz, value, res, source):
    for d in res.get('registrados', []) or []:
        if not d.get('domain'):
            continue
        e = alm.create('domain', d['domain'], sources={source},
                      properties={'ip': d.get('ip')})
        e.tag('typosquat')
        _rel(alm, raiz, e, 'typosquat')


def _mig_github_secrets(alm, raiz, value, res, source):
    for h in res.get('hallazgos', []) or []:
        if not h.get('value'):
            continue
        e = alm.create('credential', h['value'], sources={source},
                      properties={'tipo_secreto': h.get('type'), 'repo': h.get('repo'),
                                   'commit': h.get('commit')})
        e.tag('exposed')
        _rel(alm, raiz, e, 'exposed secret')


def _mig_passivedns(alm, raiz, value, res, source):
    dom = value.get('target', '')
    d = alm.create('domain', dom, sources={source}) if dom else raiz
    for h in res.get('history', [])[:30]:
        if h.get('ip'):
            _rel(alm, d, alm.create('ip', h['ip'], sources={source}),
                 f"resolved {h.get('date', '?')}")


def _mig_favicon(alm, raiz, value, res, source):
    for m in res.get('relacionados', [])[:30]:
        if m.get('ip'):
            e = alm.create('ip', m['ip'], sources={source},
                          properties={'org': m.get('org')})
            e.tag('shared-favicon')
            _rel(alm, raiz, e, 'shared favicon')


_MIGRADORES = {
    'domain': _mig_domain,
    'ip': _mig_ip,
    'user': _mig_user,
    'email': _mig_email,
    'buckets': _mig_buckets,
    'subdomain_takeover': _mig_takeover,
    'typosquatting': _mig_typo,
    'github_secrets': _mig_github_secrets,
    'passivedns': _mig_passivedns,
    'favicon': _mig_favicon,
}
