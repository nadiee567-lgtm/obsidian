"""Motor de correlación de OBSIDIAN — F4, pasos 53-54, 57-62, 64.

Corre reglas sobre el almacén y encuentra patrones que ningún transform ve solo
(un puerto sensible expuesto, un cert vencido, un email en brechas...). Cada
regla produce Hallazgos con severidad; el motor los ordena y calcula un score.

Diseño: reglas como funciones Python registradas con @regla (robusto y testeable,
estilo SpiderFoot). El cargador de reglas YAML de usuario es aparte (paso 63).
Módulo PURO: recibe un Almacen, no toca Flask ni red."""
from __future__ import annotations
import datetime
from dataclasses import dataclass, field, asdict

SEVERIDADES = {'critico': 4, 'alto': 3, 'medio': 2, 'bajo': 1}
_PESO = {'critico': 40, 'alto': 20, 'medio': 8, 'bajo': 3}


@dataclass
class Hallazgo:
    """Un patrón de riesgo detectado (paso 54)."""
    regla: str
    severidad: str          # critico | alto | medio | bajo
    mensaje: str
    entidades: list = field(default_factory=list)   # ids involucrados

    def to_dict(self):
        return asdict(self)


_REGLAS = []


def regla(fn):
    """Registra una función-regla: recibe el Almacen y produce Hallazgos."""
    _REGLAS.append(fn)
    return fn


_SUPRIMIR = {'descartado', 'falso-positivo'}

def correlacionar(almacen) -> list:
    """Corre todas las reglas y devuelve los hallazgos ordenados por severidad.
    Respeta el feedback del analista: si TODAS las entidades de un hallazgo están
    marcadas 'descartado'/'falso-positivo', el hallazgo se suprime (ciclo de
    feedback — la herramienta aprende de las correcciones humanas)."""
    out = []
    for fn in _REGLAS:
        try:
            out.extend(fn(almacen) or [])
        except Exception:
            pass   # una regla rota no tumba la correlación
    idx = {e.id: e for e in almacen.entidades}
    def suprimido(h):
        ids = [eid for eid in h.entidades if eid in idx]
        return bool(ids) and all(_SUPRIMIR & idx[eid].tags for eid in ids)
    out = [h for h in out if not suprimido(h)]
    out.sort(key=lambda h: -SEVERIDADES.get(h.severidad, 0))
    return out


def score_riesgo(hallazgos) -> int:
    """Score 0-100 agregando severidades (paso 64)."""
    return min(100, sum(_PESO.get(h.severidad, 0) for h in hallazgos))


# ════════════════════════════════════════════════════════════════════════════
# Reglas de fábrica (disparan con los datos que ya producen los transforms)
# ════════════════════════════════════════════════════════════════════════════

_PUERTOS_SENSIBLES = {
    '21': 'FTP', '23': 'Telnet', '445': 'SMB', '1433': 'MSSQL', '3306': 'MySQL',
    '3389': 'RDP', '5432': 'PostgreSQL', '5900': 'VNC', '6379': 'Redis', '27017': 'MongoDB',
}

@regla
def r_puerto_sensible(alm):
    """Puerto administrativo/de base de datos expuesto a internet (paso 58)."""
    for p in alm.de_tipo('puerto'):
        num = p.valor.split(':')[-1]
        if num in _PUERTOS_SENSIBLES:
            yield Hallazgo('puerto-sensible', 'alto',
                           f'Puerto {num} ({_PUERTOS_SENSIBLES[num]}) expuesto: {p.valor}', [p.id])

@regla
def r_cert_vencido(alm):
    """Certificado TLS vencido en un dominio (paso 61)."""
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
                           f'Certificado TLS vencido en {d.valor} ({exp})', [d.id])

@regla
def r_ip_maliciosa(alm):
    """IP con clasificación maliciosa de threat intel real (GreyNoise). Paso 57."""
    for ip in alm.de_tipo('ip'):
        if 'malicioso' in ip.tags:
            yield Hallazgo('ip-maliciosa', 'critico',
                           f'IP {ip.valor} clasificada como maliciosa (GreyNoise)', [ip.id])

@regla
def r_ip_listada(alm):
    """IP presente en un feed de amenazas. SEÑAL con fuente, para verificar —
    no un veredicto (los feeds tienen falsos positivos)."""
    for ip in alm.de_tipo('ip'):
        if 'listado-amenaza' in ip.tags:
            fuente = ip.propiedades.get('amenaza_fuente', 'feed de amenazas')
            yield Hallazgo('ip-listada', 'alto',
                           f'IP {ip.valor} listada en {fuente} — verificar (posible falso positivo)', [ip.id])

@regla
def r_email_filtrado(alm):
    """Email que apareció en brechas de datos (parte del 56)."""
    for e in alm.de_tipo('email'):
        if 'filtrado' in e.tags:
            yield Hallazgo('email-filtrado', 'alto',
                           f'{e.valor} apareció en brechas de datos', [e.id])

@regla
def r_stealer(alm):
    """Email salido de una máquina con infostealer = credenciales comprometidas."""
    for e in alm.de_tipo('email'):
        if 'stealer-infectado' in e.tags:
            yield Hallazgo('stealer-infectado', 'critico',
                           f'{e.valor} salió de una máquina con infostealer: credenciales comprometidas', [e.id])

@regla
def r_email_spoofable(alm):
    """Dominio de email sin SPF → spoofing posible."""
    for e in alm.de_tipo('email'):
        if 'spoofable' in e.tags:
            yield Hallazgo('email-spoofable', 'medio',
                           f'El dominio de {e.valor} no tiene SPF: spoofing posible', [e.id])

@regla
def r_takeover(alm):
    """Subdominio marcado como vulnerable a takeover (paso 55)."""
    for s in alm.de_tipo('subdominio'):
        if 'takeover' in s.tags:
            yield Hallazgo('subdominio-takeover', 'alto',
                           f'Subdominio vulnerable a takeover: {s.valor}', [s.id])

@regla
def r_secreto_github(alm):
    """Credencial/secreto hardcodeado hallado en un commit de GitHub (paso 60)."""
    for c in alm.de_tipo('credencial'):
        if 'secreto-github' in c.tags:
            tipo = c.propiedades.get('tipo_secreto', 'secreto')
            repo = c.propiedades.get('repo', '?')
            yield Hallazgo('secreto-github', 'critico',
                           f'{tipo} expuesto en un commit de {repo}', [c.id])

@regla
def r_nuclei_vuln(alm):
    """Host con hallazgos de nuclei de severidad alta+."""
    for tipo in ('dominio', 'subdominio'):
        for e in alm.de_tipo(tipo):
            if 'vulnerable' in e.tags:
                n = len(e.propiedades.get('nuclei', []))
                yield Hallazgo('vuln-nuclei', 'alto',
                               f'{e.valor}: {n} hallazgo(s) de nuclei (severidad alta+)', [e.id])
