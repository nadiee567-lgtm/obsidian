"""OBSIDIAN correlation engine -- F4, steps 53-54, 57-62, 64.

Runs rules over the store and finds patterns no single transform sees (an exposed
sensitive port, an expired cert, an email in breaches...). Each rule produces
Hallazgos with severity; the engine sorts them and computes a score.

Design: rules as Python functions registered with @regla (robust and testable,
SpiderFoot-style). The user YAML rule loader is separate (step 63).
PURE module: takes a Store, no Flask, no network."""
from __future__ import annotations
import datetime
from dataclasses import dataclass, field, asdict

SEVERIDADES = {'critico': 4, 'alto': 3, 'medio': 2, 'bajo': 1}
_PESO = {'critico': 40, 'alto': 20, 'medio': 8, 'bajo': 3}


@dataclass
class Hallazgo:
    """A detected risk pattern (step 54)."""
    regla: str
    severidad: str          # critico | alto | medio | bajo (severity value ids)
    mensaje: str
    entidades: list = field(default_factory=list)   # ids involucrados

    def to_dict(self):
        return asdict(self)


_REGLAS = []


def regla(fn):
    """Registers a rule function: receives the Store and yields Hallazgos."""
    _REGLAS.append(fn)
    return fn


_SUPRIMIR = {'descartado', 'falso-positivo'}

# ── User YAML rules (step 63) ────────────────────────────────────────────────
# The user defines their own rules in YAML without touching Python. They are
# evaluated alongside the built-in ones. Format:
#   - nombre: ftp-anonimo
#     severidad: alto            # critico|alto|medio|bajo
#     mensaje: "Anonymous FTP on {valor}"
#     cuando:
#       tipo: puerto             # entity type (optional)
#       tag: ftp-anon            # required tag (optional)
#       valor_contiene: ":21"    # substring in the value (optional)
#       propiedad: {nombre: servicio, valor: ftp}   # prop == value (optional)
_REGLAS_YAML = []


def _coincide_yaml(ent, cuando) -> bool:
    if 'tag' in cuando and cuando['tag'] not in ent.tags:
        return False
    if 'valor_contiene' in cuando and str(cuando['valor_contiene']) not in ent.valor:
        return False
    prop = cuando.get('propiedad')
    if isinstance(prop, dict):
        if str(ent.propiedades.get(prop.get('nombre'))) != str(prop.get('valor')):
            return False
    return True


def cargar_reglas_yaml(texto: str) -> int:
    """Parses YAML rules (text) and activates them. Returns how many loaded.
    Ignores invalid entries (does not break correlation)."""
    import yaml
    try:
        data = yaml.safe_load(texto) or []
    except Exception:
        return 0
    specs = []
    for s in (data if isinstance(data, list) else []):
        if isinstance(s, dict) and s.get('nombre'):
            if s.get('severidad', 'medio') not in SEVERIDADES:
                s['severidad'] = 'medio'
            specs.append(s)
    _REGLAS_YAML[:] = specs           # mutate in place: external references see it
    return len(specs)


def _evaluar_yaml(almacen) -> list:
    out = []
    for spec in _REGLAS_YAML:
        cuando = spec.get('cuando', {}) or {}
        tipo = cuando.get('tipo')
        ents = almacen.de_tipo(tipo) if tipo else almacen.entidades
        for e in ents:
            if _coincide_yaml(e, cuando):
                msg = str(spec.get('mensaje', spec['nombre'])).replace('{valor}', e.valor)
                out.append(Hallazgo(spec['nombre'], spec.get('severidad', 'medio'), msg, [e.id]))
    return out


def correlacionar(almacen) -> list:
    """Runs all rules (built-in + user YAML) and returns the findings ordered by
    severity. Honors analyst feedback: if ALL entities of a finding are tagged
    'descartado'/'falso-positivo', the finding is suppressed (feedback loop --
    learns from human corrections)."""
    out = []
    for fn in _REGLAS:
        try:
            out.extend(fn(almacen) or [])
        except Exception:
            pass   # a broken rule does not take down correlation
    try:
        out.extend(_evaluar_yaml(almacen))
    except Exception:
        pass
    idx = {e.id: e for e in almacen.entidades}
    def suprimido(h):
        ids = [eid for eid in h.entidades if eid in idx]
        return bool(ids) and all(_SUPRIMIR & idx[eid].tags for eid in ids)
    out = [h for h in out if not suprimido(h)]
    out.sort(key=lambda h: -SEVERIDADES.get(h.severidad, 0))
    return out


def score_riesgo(hallazgos) -> int:
    """Score 0-100 aggregating severities (step 64)."""
    return min(100, sum(_PESO.get(h.severidad, 0) for h in hallazgos))


def score_exposicion(conteos: dict, riesgo: int) -> int:
    """Exposure score 0-100 (step 149): combines the SIZE of the surface (how many
    internet-facing assets) with the RISK (findings). More surface + more risk =
    more exposed."""
    superficie = min(50, conteos.get('subdominio', 0) * 1 + conteos.get('ip', 0) * 2
                     + conteos.get('puerto', 0) * 2 + conteos.get('bucket', 0) * 5
                     + conteos.get('url', 0))
    return min(100, superficie + riesgo // 2)


# ════════════════════════════════════════════════════════════════════════════
# Built-in rules (they fire on data the transforms already produce)
# ════════════════════════════════════════════════════════════════════════════

_PUERTOS_SENSIBLES = {
    '21': 'FTP', '23': 'Telnet', '445': 'SMB', '1433': 'MSSQL', '3306': 'MySQL',
    '3389': 'RDP', '5432': 'PostgreSQL', '5900': 'VNC', '6379': 'Redis', '27017': 'MongoDB',
}

@regla
def r_puerto_sensible(alm):
    """Administrative/database port exposed to the internet (step 58)."""
    for p in alm.de_tipo('puerto'):
        num = p.valor.split(':')[-1]
        if num in _PUERTOS_SENSIBLES:
            yield Hallazgo('puerto-sensible', 'alto',
                           f'Port {num} ({_PUERTOS_SENSIBLES[num]}) exposed: {p.valor}', [p.id])

@regla
def r_cert_vencido(alm):
    """Expired TLS certificate on a domain (step 61)."""
    ahora = datetime.datetime.now()
    for d in alm.de_tipo('dominio'):
        exp = d.propiedades.get('cert_expira')
        if not exp:
            continue
        try:
            fecha = datetime.datetime.strptime(exp.replace(' GMT', ''), '%b %d %H:%M:%S %Y')
        except ValueError:
            continue
        if fecha < ahora:
            yield Hallazgo('cert-vencido', 'medio',
                           f'Expired TLS certificate on {d.valor} ({exp})', [d.id])

@regla
def r_ip_maliciosa(alm):
    """IP classified malicious by real threat intel (GreyNoise). Step 57."""
    for ip in alm.de_tipo('ip'):
        if 'malicioso' in ip.tags:
            yield Hallazgo('ip-maliciosa', 'critico',
                           f'IP {ip.valor} classified as malicious (GreyNoise)', [ip.id])

@regla
def r_ip_listada(alm):
    """IP present in a threat feed. A SIGNAL with source, to verify -- not a
    verdict (feeds have false positives)."""
    for ip in alm.de_tipo('ip'):
        if 'listado-amenaza' in ip.tags:
            fuente = ip.propiedades.get('amenaza_fuente', 'threat feed')
            yield Hallazgo('ip-listada', 'alto',
                           f'IP {ip.valor} listed in {fuente} -- verify (possible false positive)', [ip.id])

@regla
def r_email_filtrado(alm):
    """Email that appeared in data breaches (part of 56)."""
    for e in alm.de_tipo('email'):
        if 'filtrado' in e.tags:
            yield Hallazgo('email-filtrado', 'alto',
                           f'{e.valor} appeared in data breaches', [e.id])

@regla
def r_stealer(alm):
    """Email coming from an infostealer-infected machine = compromised credentials."""
    for e in alm.de_tipo('email'):
        if 'stealer-infectado' in e.tags:
            yield Hallazgo('stealer-infectado', 'critico',
                           f'{e.valor} came from an infostealer machine: compromised credentials', [e.id])

@regla
def r_email_spoofable(alm):
    """Email domain without SPF -> spoofing possible."""
    for e in alm.de_tipo('email'):
        if 'spoofable' in e.tags:
            yield Hallazgo('email-spoofable', 'medio',
                           f'The domain of {e.valor} has no SPF: spoofing possible', [e.id])

@regla
def r_takeover(alm):
    """Subdomain marked as vulnerable to takeover (step 55)."""
    for s in alm.de_tipo('subdominio'):
        if 'takeover' in s.tags:
            yield Hallazgo('subdominio-takeover', 'alto',
                           f'Subdomain vulnerable to takeover: {s.valor}', [s.id])

@regla
def r_shadow_it(alm):
    """Shadow IT / forgotten assets (step 150): public buckets (exposed storage)
    and broken subdomains (HTTP 5xx = forgotten/badly maintained)."""
    for b in alm.de_tipo('bucket'):
        if 'publico' in b.tags:
            yield Hallazgo('shadow-it', 'alto',
                           f'Public bucket -- exposed storage: {b.valor}', [b.id])
    for s in alm.de_tipo('subdominio'):
        st = s.propiedades.get('http_status')
        if isinstance(st, int) and st >= 500:
            yield Hallazgo('shadow-it', 'medio',
                           f'Broken/forgotten subdomain (HTTP {st}): {s.valor}', [s.id])

@regla
def r_infra_compartida(alm):
    """Assets sharing a favicon or cert = probably the same organization (step 147).
    Groups domains/subdomains/ips by shared attribute."""
    from collections import defaultdict
    for campo, etiqueta in (('favicon_hash', 'favicon'), ('cert_cn', 'cert')):
        grupos = defaultdict(list)
        for tipo in ('dominio', 'subdominio', 'ip'):
            for e in alm.de_tipo(tipo):
                v = e.propiedades.get(campo)
                if v:
                    grupos[str(v)].append(e)
        for v, ents in grupos.items():
            if len(ents) >= 2:
                yield Hallazgo('infra-compartida', 'bajo',
                               f'{len(ents)} assets share {etiqueta} ({v[:40]}) -- same '
                               f'infrastructure: ' + ', '.join(e.valor for e in ents[:4]),
                               [e.id for e in ents])

@regla
def r_wallet_ransomware(alm):
    """Wallet linked to ransomware (step 141)."""
    for w in alm.de_tipo('wallet'):
        if 'ransomware' in w.tags:
            yield Hallazgo('wallet-ransomware', 'critico',
                           f'Wallet linked to ransomware: {w.valor}', [w.id])

@regla
def r_leak_login(alm):
    """Leaked credential + exposed login panel = probable access path (step 136).
    Explicitly pairs each 'filtrado' email with each 'panel-login' in the case,
    naming both -- the concrete attack vector."""
    filtrados = [e for e in alm.de_tipo('email') if 'filtrado' in e.tags]
    if not filtrados:
        return
    paneles = [e for tipo in ('dominio', 'subdominio')
               for e in alm.de_tipo(tipo) if 'panel-login' in e.tags]
    for panel in paneles:
        for cred in filtrados[:3]:
            yield Hallazgo('leak-login', 'critico',
                           f'Leaked credential ({cred.valor}) + exposed panel ({panel.valor}) '
                           f'= possible account access', [cred.id, panel.id])

@regla
def r_pivote_plataformas(alm):
    """A user present on many platforms = strong pivot to cross identity (step 59).
    Counts the platforms linked to each user."""
    usuarios = {e.id: e for e in alm.de_tipo('usuario')}
    ids_plat = {e.id for e in alm.de_tipo('plataforma')}
    conteo = {}
    for r in alm.relaciones:
        if r.origen in usuarios and r.destino in ids_plat:
            conteo[r.origen] = conteo.get(r.origen, 0) + 1
    for uid, n in conteo.items():
        if n >= 5:
            yield Hallazgo('pivote-plataformas', 'bajo',
                           f'{usuarios[uid].valor} present on {n} platforms -- strong pivot to cross identity',
                           [uid])

@regla
def r_login_expuesto(alm):
    """Accessible login/admin panel (step 56). High on its own; CRITICAL if there are
    also leaked credentials in the case -- login + credential = probable access."""
    hay_cred = (any('filtrado' in e.tags or 'stealer-infectado' in e.tags
                    for e in alm.de_tipo('email'))
                or bool(alm.de_tipo('credencial')))
    for tipo in ('dominio', 'subdominio'):
        for e in alm.de_tipo(tipo):
            if 'panel-login' in e.tags:
                sev = 'critico' if hay_cred else 'alto'
                extra = ' + there are leaked credentials in the case' if hay_cred else ''
                yield Hallazgo('login-expuesto', sev,
                               f'Login/admin panel exposed: {e.valor}{extra}', [e.id])

@regla
def r_secreto_github(alm):
    """Hardcoded credential/secret found in a GitHub commit (step 60)."""
    for c in alm.de_tipo('credencial'):
        if 'secreto-github' in c.tags:
            tipo = c.propiedades.get('tipo_secreto', 'secret')
            repo = c.propiedades.get('repo', '?')
            yield Hallazgo('secreto-github', 'critico',
                           f'{tipo} exposed in a commit of {repo}', [c.id])

@regla
def r_nuclei_vuln(alm):
    """Host with high+ severity nuclei findings."""
    for tipo in ('dominio', 'subdominio'):
        for e in alm.de_tipo(tipo):
            if 'vulnerable' in e.tags:
                n = len(e.propiedades.get('nuclei', []))
                yield Hallazgo('vuln-nuclei', 'alto',
                               f'{e.valor}: {n} nuclei finding(s) (high+ severity)', [e.id])
