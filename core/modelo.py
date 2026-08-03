"""Modelo de datos tipado de OBSIDIAN — F1, el corazón del framework.

Todo dato recolectado es una Entidad tipada con id determinístico: la misma IP
hallada por dos fuentes distintas colapsa en UN solo nodo (dedup por id). Las
Relaciones tipadas conectan entidades. El Almacén indexa todo y deduplica.

Pasos del roadmap: 13 (catálogo de tipos), 14 (Entidad), 15 (Relación),
16 (almacén), 17 (dedup/merge), 21 (serialización), 22 (normalizadores).

Módulo PURO: no depende de Flask, ni de `case`, ni de red. Testeable solo.
"""
from __future__ import annotations
import hashlib
import ipaddress
import datetime
from dataclasses import dataclass, field, asdict


# ── Paso 13: catálogo de tipos de entidad ────────────────────────────────────
# Única fuente de verdad de qué tipos existen y cómo se ven (el grafo leerá de
# aquí en F6). etiqueta = nombre legible; color = paleta ya usada en el grafo.
TIPOS = {
    'objetivo':   {'etiqueta': 'Objetivo',    'color': '#d99a4e'},
    'dominio':    {'etiqueta': 'Dominio',     'color': '#5b9bd5'},
    'subdominio': {'etiqueta': 'Subdominio',  'color': '#7fb8d9'},
    'ip':         {'etiqueta': 'IP',          'color': '#d9564b'},
    'email':      {'etiqueta': 'Email',       'color': '#6fae7c'},
    'usuario':    {'etiqueta': 'Usuario',     'color': '#cc9a3c'},
    'telefono':   {'etiqueta': 'Teléfono',    'color': '#c99a6b'},
    'persona':    {'etiqueta': 'Persona',     'color': '#e0af68'},
    'org':        {'etiqueta': 'Organización','color': '#b07a9e'},
    'url':        {'etiqueta': 'URL',         'color': '#5fa8a0'},
    'puerto':     {'etiqueta': 'Puerto',      'color': '#8b8b98'},
    'hash':       {'etiqueta': 'Hash',        'color': '#9a7ecc'},
    'archivo':    {'etiqueta': 'Archivo',     'color': '#7a85b0'},
    'cve':        {'etiqueta': 'CVE',         'color': '#d9564b'},
    'bucket':     {'etiqueta': 'Bucket',      'color': '#d9564b'},
    'credencial': {'etiqueta': 'Credencial',  'color': '#f7768e'},
    'asn':        {'etiqueta': 'ASN',         'color': '#7a85b0'},
    'pais':       {'etiqueta': 'País',        'color': '#7a85b0'},
    'tech':       {'etiqueta': 'Tecnología',  'color': '#5fa8a0'},
    'imagen':     {'etiqueta': 'Imagen',      'color': '#73daca'},
    'wallet':     {'etiqueta': 'Wallet',      'color': '#e0af68'},
    'plataforma': {'etiqueta': 'Plataforma',  'color': '#c17a52'},
    'repo':       {'etiqueta': 'Repositorio', 'color': '#d99a4e'},
}


def tipo_valido(tipo: str) -> bool:
    return tipo in TIPOS


# ── Paso 22: normalizadores por tipo (para dedup estable) ────────────────────
def normalizar(tipo: str, valor: str) -> str:
    """Forma canónica de un valor, para que dos escrituras del mismo dato den el
    mismo id. Ej: 'WWW.Example.COM.' y 'example.com' → 'example.com'."""
    v = (valor or '').strip()
    if tipo in ('dominio', 'subdominio'):
        v = v.lower().rstrip('.')
        if v.startswith('www.'):
            v = v[4:]
    elif tipo == 'ip':
        try:
            v = str(ipaddress.ip_address(v))   # comprime IPv6, valida
        except ValueError:
            pass
    elif tipo == 'email':
        v = v.lower()
    elif tipo == 'url':
        v = v.rstrip('/')
    return v


def _ahora() -> str:
    return datetime.datetime.now().isoformat(timespec='seconds')


# ── Paso 14: la Entidad ──────────────────────────────────────────────────────
@dataclass
class Entidad:
    """Unidad atómica de dato. El id se deriva de (tipo, valor normalizado), así
    que dos entidades del mismo dato son la MISMA entidad aunque las cree otra
    fuente. `origenes` acumula qué transforms la produjeron (trazabilidad)."""
    tipo: str
    valor: str
    propiedades: dict = field(default_factory=dict)
    origenes: set = field(default_factory=set)     # nombres de transforms/fuentes
    confianza: float = 1.0                          # 0..1
    creada: str = field(default_factory=_ahora)
    id: str = field(default='', init=False)

    def __post_init__(self):
        if not tipo_valido(self.tipo):
            raise ValueError(f"tipo de entidad desconocido: {self.tipo!r}")
        self.valor = normalizar(self.tipo, self.valor)
        if not self.valor:
            raise ValueError("valor de entidad vacío")
        if isinstance(self.origenes, (list, tuple)):
            self.origenes = set(self.origenes)
        self.id = self._calcular_id()

    def _calcular_id(self) -> str:
        base = f"{self.tipo}:{self.valor}".encode('utf-8')
        return hashlib.sha1(base).hexdigest()[:16]

    def fusionar(self, otra: 'Entidad') -> None:
        """Absorbe otra entidad del mismo id (paso 17): une orígenes y
        propiedades, sube la confianza, conserva la fecha más antigua."""
        if otra.id != self.id:
            raise ValueError("no se puede fusionar entidades de distinto id")
        self.origenes |= otra.origenes
        for k, v in otra.propiedades.items():
            if v not in (None, '', [], {}):
                self.propiedades[k] = v
        self.confianza = max(self.confianza, otra.confianza)
        self.creada = min(self.creada, otra.creada)

    # ── Paso 21: serialización ──
    def to_dict(self) -> dict:
        d = asdict(self)
        d['origenes'] = sorted(self.origenes)   # set no es JSON-serializable
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'Entidad':
        e = cls(tipo=d['tipo'], valor=d['valor'],
                propiedades=dict(d.get('propiedades', {})),
                origenes=set(d.get('origenes', [])),
                confianza=d.get('confianza', 1.0))
        e.creada = d.get('creada', e.creada)
        return e


# ── Paso 15: la Relación ─────────────────────────────────────────────────────
@dataclass
class Relacion:
    """Arista tipada y dirigida entre dos entidades (por id). id determinístico
    de (origen, destino, etiqueta) → no se duplica la misma relación."""
    origen: str        # id de entidad
    destino: str       # id de entidad
    etiqueta: str = ''
    id: str = field(default='', init=False)

    def __post_init__(self):
        base = f"{self.origen}>{self.destino}:{self.etiqueta}".encode('utf-8')
        self.id = hashlib.sha1(base).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'Relacion':
        return cls(origen=d['origen'], destino=d['destino'], etiqueta=d.get('etiqueta', ''))


# ── Paso 16 + 17: el Almacén con dedup automático ────────────────────────────
class Almacen:
    """Guarda entidades y relaciones de un caso. Deduplica por id al agregar."""

    def __init__(self):
        self._entidades: dict[str, Entidad] = {}
        self._relaciones: dict[str, Relacion] = {}
        self._por_tipo: dict[str, set] = {}     # tipo -> {id, ...}

    # -- entidades --
    def agregar(self, ent: Entidad) -> Entidad:
        """Agrega o fusiona. Devuelve la entidad viva en el almacén (paso 17)."""
        existente = self._entidades.get(ent.id)
        if existente:
            existente.fusionar(ent)
            return existente
        self._entidades[ent.id] = ent
        self._por_tipo.setdefault(ent.tipo, set()).add(ent.id)
        return ent

    def crear(self, tipo, valor, **kw) -> Entidad:
        """Atajo: construye una Entidad y la agrega (deduplicando)."""
        return self.agregar(Entidad(tipo=tipo, valor=valor, **kw))

    def obtener(self, id_: str) -> Entidad | None:
        return self._entidades.get(id_)

    def buscar(self, tipo, valor) -> Entidad | None:
        """Busca por (tipo, valor) sin agregar — respeta la normalización."""
        eid = hashlib.sha1(f"{tipo}:{normalizar(tipo, valor)}".encode()).hexdigest()[:16]
        return self._entidades.get(eid)

    def de_tipo(self, tipo) -> list:
        return [self._entidades[i] for i in self._por_tipo.get(tipo, ())]

    # -- relaciones --
    def relacionar(self, origen, destino, etiqueta='') -> Relacion:
        """Conecta dos entidades (por id o por objeto Entidad). Deduplica."""
        oid = origen.id if isinstance(origen, Entidad) else origen
        did = destino.id if isinstance(destino, Entidad) else destino
        rel = Relacion(origen=oid, destino=did, etiqueta=etiqueta)
        self._relaciones.setdefault(rel.id, rel)
        return self._relaciones[rel.id]

    # -- vistas --
    @property
    def entidades(self) -> list:
        return list(self._entidades.values())

    @property
    def relaciones(self) -> list:
        return list(self._relaciones.values())

    def __len__(self) -> int:
        return len(self._entidades)

    # ── Paso 21: serialización del caso completo ──
    def to_dict(self) -> dict:
        return {
            'entidades': [e.to_dict() for e in self._entidades.values()],
            'relaciones': [r.to_dict() for r in self._relaciones.values()],
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'Almacen':
        alm = cls()
        for ed in d.get('entidades', []):
            alm.agregar(Entidad.from_dict(ed))
        for rd in d.get('relaciones', []):
            r = Relacion.from_dict(rd)
            alm._relaciones[r.id] = r
        return alm
