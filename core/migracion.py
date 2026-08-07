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
    store = Store()
    target = case.get('target')
    raiz = store.create('target', target, sources={'caso'}) if target else None

    for key, value in (case.get('data') or {}).items():
        if not isinstance(value, dict):
            continue
        type = value.get('type', '')
        res = value.get('results', {}) or {}
        try:
            _MIGRADORES.get(type, lambda *a: None)(store, raiz, value, res, key)
        except Exception:
            continue   # malformed module: skipped
    return store


def _rel(store, a, b, label):
    if a is not None and b is not None:
        store.relate(a, b, label)


def _mig_domain(store, raiz, value, res, source):
    dom = value.get('target', '')
    if not dom:
        return
    d = store.create('domain', dom, sources={source})
    _rel(store, raiz, d, 'domain')
    for ip in _RE_IP.findall(str(res.get('dns', {}).get('A', ''))):
        _rel(store, d, store.create('ip', ip, sources={source}), 'A')
    for sub in res.get('subdominios', [])[:50]:
        _rel(store, d, store.create('subdomain', sub, sources={source}), 'subdomain')
    for email in res.get('emails', [])[:30]:
        _rel(store, d, store.create('email', email, sources={source}), 'email')
    for h, v in (res.get('tecnologias', {}) or {}).items():
        if v:
            _rel(store, d, store.create('tech', str(v), sources={source}), h.lower())


def _mig_ip(store, raiz, value, res, source):
    ip = value.get('target', '')
    if not ip:
        return
    i = store.create('ip', ip, sources={source})
    _rel(store, raiz, i, 'ip')
    geo = res.get('geo', {}) or {}
    if geo.get('country'):
        _rel(store, i, store.create('country', geo['country'], sources={source}), 'location')
    if geo.get('org'):
        _rel(store, i, store.create('org', geo['org'], sources={source}), 'org')
    if res.get('ptr'):
        _rel(store, i, store.create('domain', res['ptr'], sources={source}), 'PTR')


def _mig_user(store, raiz, value, res, source):
    user = value.get('target', '')
    if not user:
        return
    u = store.create('user', user, sources={source})
    _rel(store, raiz, u, 'user')
    for p in (res.get('plataformas', []) or []) + (res.get('maigret', []) or []):
        plat = p.get('platform')
        if plat:
            e = store.create('platform', plat, sources={source},
                          properties={'url': p.get('url', '')})
            _rel(store, u, e, 'profile')
    gh = res.get('github', {}) or {}
    if gh.get('email') and gh['email'] != 'oculto':
        _rel(store, u, store.create('email', gh['email'], sources={source}), 'email')
    for repo in res.get('github_repos', [])[:10]:
        if repo.get('name'):
            _rel(store, u, store.create('repo', repo['name'], sources={source}), 'repo')


def _mig_email(store, raiz, value, res, source):
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
    e = store.create('email', email, sources={source}, properties=props)
    if sec.get('spoofable'):
        e.tag('spoofable')
    if breaches:
        e.tag('leaked')
    _rel(store, raiz, e, 'email')


def _mig_buckets(store, raiz, value, res, source):
    for b in res.get('buckets', []) or []:
        if not b.get('bucket'):
            continue
        e = store.create('bucket', b['bucket'], sources={source},
                      properties={'url': b.get('url', ''), 'public': b.get('public', False)})
        if b.get('public'):
            e.tag('public')
        _rel(store, raiz, e, 'bucket')


def _mig_takeover(store, raiz, value, res, source):
    for v in res.get('vulnerables', []) or []:
        if not v.get('subdomain'):
            continue
        e = store.create('subdomain', v['subdomain'], sources={source},
                      properties={'service': v.get('service'), 'status': v.get('status')})
        e.tag('takeover', 'vulnerable')
        _rel(store, raiz, e, 'takeover')


def _mig_typo(store, raiz, value, res, source):
    for d in res.get('registered', []) or []:
        if not d.get('domain'):
            continue
        e = store.create('domain', d['domain'], sources={source},
                      properties={'ip': d.get('ip')})
        e.tag('typosquat')
        _rel(store, raiz, e, 'typosquat')


def _mig_github_secrets(store, raiz, value, res, source):
    for h in res.get('findings', []) or []:
        if not h.get('value'):
            continue
        e = store.create('credential', h['value'], sources={source},
                      properties={'secret_type': h.get('type'), 'repo': h.get('repo'),
                                   'commit': h.get('commit')})
        e.tag('exposed')
        _rel(store, raiz, e, 'exposed secret')


def _mig_passivedns(store, raiz, value, res, source):
    dom = value.get('target', '')
    d = store.create('domain', dom, sources={source}) if dom else raiz
    for h in res.get('history', [])[:30]:
        if h.get('ip'):
            _rel(store, d, store.create('ip', h['ip'], sources={source}),
                 f"resolved {h.get('date', '?')}")


def _mig_favicon(store, raiz, value, res, source):
    for m in res.get('relacionados', [])[:30]:
        if m.get('ip'):
            e = store.create('ip', m['ip'], sources={source},
                          properties={'org': m.get('org')})
            e.tag('shared-favicon')
            _rel(store, raiz, e, 'shared favicon')


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
