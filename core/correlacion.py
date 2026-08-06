"""OBSIDIAN correlation engine -- F4, steps 53-54, 57-62, 64.

Runs rules over the store and finds patterns no single transform sees (an exposed
sensitive port, an expired cert, an email in breaches...). Each rule produces
Hallazgos with severity; the engine sorts them and computes a score.

Design: rules as Python functions registered with @rule (robust and testable,
SpiderFoot-style). The user YAML rule loader is separate (step 63).
PURE module: takes a Store, no Flask, no network."""
from __future__ import annotations
import datetime
from dataclasses import dataclass, field, asdict

SEVERIDADES = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
_PESO = {'critical': 40, 'high': 20, 'medium': 8, 'low': 3}


@dataclass
class Finding:
    """A detected risk pattern (step 54)."""
    rule: str
    severity: str          # critical | high | medium | low (severity value ids)
    message: str
    entities: list = field(default_factory=list)   # ids involucrados

    def to_dict(self):
        return asdict(self)


_REGLAS = []


def rule(fn):
    """Registers a rule function: receives the Store and yields Hallazgos."""
    _REGLAS.append(fn)
    return fn


_SUPRIMIR = {'discarded', 'false-positive'}

# ── User YAML rules (step 63) ────────────────────────────────────────────────
# The user defines their own rules in YAML without touching Python. They are
# evaluated alongside the built-in ones. Format:
#   - name: ftp-anon
#     severity: high            # critical|high|medium|low
#     message: "Anonymous FTP on {value}"
#     when:
#       type: port               # entity type (optional)
#       tag: ftp-anon            # required tag (optional)
#       value_contains: ":21"    # substring in the value (optional)
#       property: {name: service, value: ftp}   # prop == value (optional)
_REGLAS_YAML = []


def _yaml_matches(ent, when) -> bool:
    if 'tag' in when and when['tag'] not in ent.tags:
        return False
    if 'value_contains' in when and str(when['value_contains']) not in ent.value:
        return False
    prop = when.get('property')
    if isinstance(prop, dict):
        if str(ent.properties.get(prop.get('name'))) != str(prop.get('value')):
            return False
    return True


def load_yaml_rules(texto: str) -> int:
    """Parses YAML rules (text) and activates them. Returns how many loaded.
    Ignores invalid entries (does not break correlation)."""
    import yaml
    try:
        data = yaml.safe_load(texto) or []
    except Exception:
        return 0
    specs = []
    for s in (data if isinstance(data, list) else []):
        if isinstance(s, dict) and s.get('name'):
            if s.get('severity', 'medium') not in SEVERIDADES:
                s['severity'] = 'medium'
            specs.append(s)
    _REGLAS_YAML[:] = specs           # mutate in place: external references see it
    return len(specs)


def _evaluate_yaml(almacen) -> list:
    out = []
    for spec in _REGLAS_YAML:
        when = spec.get('when', {}) or {}
        type = when.get('type')
        ents = almacen.of_type(type) if type else almacen.entities
        for e in ents:
            if _yaml_matches(e, when):
                msg = str(spec.get('message', spec['name'])).replace('{value}', e.value)
                out.append(Finding(spec['name'], spec.get('severity', 'medium'), msg, [e.id]))
    return out


def correlate(almacen) -> list:
    """Runs all rules (built-in + user YAML) and returns the findings ordered by
    severity. Honors analyst feedback: if ALL entities of a finding are tagged
    'discarded'/'false-positive', the finding is suppressed (feedback loop --
    learns from human corrections)."""
    out = []
    for fn in _REGLAS:
        try:
            out.extend(fn(almacen) or [])
        except Exception:
            pass   # a broken rule does not take down correlation
    try:
        out.extend(_evaluate_yaml(almacen))
    except Exception:
        pass
    idx = {e.id: e for e in almacen.entities}
    def suprimido(h):
        ids = [eid for eid in h.entities if eid in idx]
        return bool(ids) and all(_SUPRIMIR & idx[eid].tags for eid in ids)
    out = [h for h in out if not suprimido(h)]
    out.sort(key=lambda h: -SEVERIDADES.get(h.severity, 0))
    return out


def risk_score(hallazgos) -> int:
    """Score 0-100 aggregating severities (step 64)."""
    return min(100, sum(_PESO.get(h.severity, 0) for h in hallazgos))


def exposure_score(conteos: dict, riesgo: int) -> int:
    """Exposure score 0-100 (step 149): combines the SIZE of the surface (how many
    internet-facing assets) with the RISK (findings). More surface + more risk =
    more exposed."""
    superficie = min(50, conteos.get('subdomain', 0) * 1 + conteos.get('ip', 0) * 2
                     + conteos.get('port', 0) * 2 + conteos.get('bucket', 0) * 5
                     + conteos.get('url', 0))
    return min(100, superficie + riesgo // 2)


# ════════════════════════════════════════════════════════════════════════════
# Built-in rules (they fire on data the transforms already produce)
# ════════════════════════════════════════════════════════════════════════════

_PUERTOS_SENSIBLES = {
    '21': 'FTP', '23': 'Telnet', '445': 'SMB', '1433': 'MSSQL', '3306': 'MySQL',
    '3389': 'RDP', '5432': 'PostgreSQL', '5900': 'VNC', '6379': 'Redis', '27017': 'MongoDB',
}

@rule
def r_puerto_sensible(alm):
    """Administrative/database port exposed to the internet (step 58)."""
    for p in alm.of_type('port'):
        num = p.value.split(':')[-1]
        if num in _PUERTOS_SENSIBLES:
            yield Finding('sensitive-port', 'high',
                           f'Port {num} ({_PUERTOS_SENSIBLES[num]}) exposed: {p.value}', [p.id])

@rule
def r_cert_vencido(alm):
    """Expired TLS certificate on a domain (step 61)."""
    ahora = datetime.datetime.now()
    for d in alm.of_type('domain'):
        exp = d.properties.get('cert_expira')
        if not exp:
            continue
        try:
            date = datetime.datetime.strptime(exp.replace(' GMT', ''), '%b %d %H:%M:%S %Y')
        except ValueError:
            continue
        if date < ahora:
            yield Finding('cert-expired', 'medium',
                           f'Expired TLS certificate on {d.value} ({exp})', [d.id])

@rule
def r_ip_maliciosa(alm):
    """IP classified malicious by real threat intel (GreyNoise). Step 57."""
    for ip in alm.of_type('ip'):
        if 'malicious' in ip.tags:
            yield Finding('ip-malicious', 'critical',
                           f'IP {ip.value} classified as malicious (GreyNoise)', [ip.id])

@rule
def r_ip_listada(alm):
    """IP present in a threat feed. A SIGNAL with source, to verify -- not a
    verdict (feeds have false positives)."""
    for ip in alm.of_type('ip'):
        if 'threat-listed' in ip.tags:
            fuente = ip.properties.get('amenaza_fuente', 'threat feed')
            yield Finding('ip-listed', 'high',
                           f'IP {ip.value} listed in {fuente} -- verify (possible false positive)', [ip.id])

@rule
def r_email_filtrado(alm):
    """Email that appeared in data breaches (part of 56)."""
    for e in alm.of_type('email'):
        if 'leaked' in e.tags:
            yield Finding('email-leaked', 'high',
                           f'{e.value} appeared in data breaches', [e.id])

@rule
def r_stealer(alm):
    """Email coming from an infostealer-infected machine = compromised credentials."""
    for e in alm.of_type('email'):
        if 'stealer-infected' in e.tags:
            yield Finding('stealer-infected', 'critical',
                           f'{e.value} came from an infostealer machine: compromised credentials', [e.id])

@rule
def r_email_spoofable(alm):
    """Email domain without SPF -> spoofing possible."""
    for e in alm.of_type('email'):
        if 'spoofable' in e.tags:
            yield Finding('email-spoofable', 'medium',
                           f'The domain of {e.value} has no SPF: spoofing possible', [e.id])

@rule
def r_takeover(alm):
    """Subdomain marked as vulnerable to takeover (step 55)."""
    for s in alm.of_type('subdomain'):
        if 'takeover' in s.tags:
            yield Finding('subdomain-takeover', 'high',
                           f'Subdomain vulnerable to takeover: {s.value}', [s.id])

@rule
def r_shadow_it(alm):
    """Shadow IT / forgotten assets (step 150): public buckets (exposed storage)
    and broken subdomains (HTTP 5xx = forgotten/badly maintained)."""
    for b in alm.of_type('bucket'):
        if 'public' in b.tags:
            yield Finding('shadow-it', 'high',
                           f'Public bucket -- exposed storage: {b.value}', [b.id])
    for s in alm.of_type('subdomain'):
        st = s.properties.get('http_status')
        if isinstance(st, int) and st >= 500:
            yield Finding('shadow-it', 'medium',
                           f'Broken/forgotten subdomain (HTTP {st}): {s.value}', [s.id])

@rule
def r_infra_compartida(alm):
    """Assets sharing a favicon or cert = probably the same organization (step 147).
    Groups domains/subdomains/ips by shared attribute."""
    from collections import defaultdict
    for campo, label in (('favicon_hash', 'favicon'), ('cert_cn', 'cert')):
        grupos = defaultdict(list)
        for type in ('domain', 'subdomain', 'ip'):
            for e in alm.of_type(type):
                v = e.properties.get(campo)
                if v:
                    grupos[str(v)].append(e)
        for v, ents in grupos.items():
            if len(ents) >= 2:
                yield Finding('shared-infra', 'low',
                               f'{len(ents)} assets share {label} ({v[:40]}) -- same '
                               f'infrastructure: ' + ', '.join(e.value for e in ents[:4]),
                               [e.id for e in ents])

@rule
def r_wallet_ransomware(alm):
    """Wallet linked to ransomware (step 141)."""
    for w in alm.of_type('wallet'):
        if 'ransomware' in w.tags:
            yield Finding('wallet-ransomware', 'critical',
                           f'Wallet linked to ransomware: {w.value}', [w.id])

@rule
def r_leak_login(alm):
    """Leaked credential + exposed login panel = probable access path (step 136).
    Explicitly pairs each 'leaked' email with each 'login-panel' in the case,
    naming both -- the concrete attack vector."""
    filtrados = [e for e in alm.of_type('email') if 'leaked' in e.tags]
    if not filtrados:
        return
    paneles = [e for type in ('domain', 'subdomain')
               for e in alm.of_type(type) if 'login-panel' in e.tags]
    for panel in paneles:
        for cred in filtrados[:3]:
            yield Finding('leak-login', 'critical',
                           f'Leaked credential ({cred.value}) + exposed panel ({panel.value}) '
                           f'= possible account access', [cred.id, panel.id])

@rule
def r_pivote_plataformas(alm):
    """A user present on many platforms = strong pivot to cross identity (step 59).
    Counts the platforms linked to each user."""
    usuarios = {e.id: e for e in alm.of_type('user')}
    ids_plat = {e.id for e in alm.of_type('platform')}
    conteo = {}
    for r in alm.relations:
        if r.source in usuarios and r.target in ids_plat:
            conteo[r.source] = conteo.get(r.source, 0) + 1
    for uid, n in conteo.items():
        if n >= 5:
            yield Finding('platform-pivot', 'low',
                           f'{usuarios[uid].value} present on {n} platforms -- strong pivot to cross identity',
                           [uid])

@rule
def r_login_expuesto(alm):
    """Accessible login/admin panel (step 56). High on its own; CRITICAL if there are
    also leaked credentials in the case -- login + credential = probable access."""
    hay_cred = (any('leaked' in e.tags or 'stealer-infected' in e.tags
                    for e in alm.of_type('email'))
                or bool(alm.of_type('credential')))
    for type in ('domain', 'subdomain'):
        for e in alm.of_type(type):
            if 'login-panel' in e.tags:
                sev = 'critical' if hay_cred else 'high'
                extra = ' + there are leaked credentials in the case' if hay_cred else ''
                yield Finding('login-exposed', sev,
                               f'Login/admin panel exposed: {e.value}{extra}', [e.id])

@rule
def r_secreto_github(alm):
    """Hardcoded credential/secret found in a GitHub commit (step 60)."""
    for c in alm.of_type('credential'):
        if 'github-secret' in c.tags:
            type = c.properties.get('tipo_secreto', 'secret')
            repo = c.properties.get('repo', '?')
            yield Finding('github-secret', 'critical',
                           f'{type} exposed in a commit of {repo}', [c.id])

@rule
def r_nuclei_vuln(alm):
    """Host with high+ severity nuclei findings."""
    for type in ('domain', 'subdomain'):
        for e in alm.of_type(type):
            if 'vulnerable' in e.tags:
                n = len(e.properties.get('nuclei', []))
                yield Finding('vuln-nuclei', 'high',
                               f'{e.value}: {n} nuclei finding(s) (high+ severity)', [e.id])
