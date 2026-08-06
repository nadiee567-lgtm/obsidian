"""OBSIDIAN typed data model — F1, the heart of the framework.

Every collected datum is a typed Entity with a deterministic id: the same IP
found by two different sources collapses into ONE node (dedup by id). Typed
Relations connect entities. The Store indexes everything and deduplicates.

Roadmap steps: 13 (type catalog), 14 (Entity), 15 (Relation), 16 (store),
17 (dedup/merge), 21 (serialization), 22 (normalizers).

PURE module: does not depend on Flask, on `case`, or on the network. Testable alone.
"""
from __future__ import annotations
import hashlib
import ipaddress
import datetime
from dataclasses import dataclass, field, asdict

from core.validacion import _validar   # step 25: a single source of truth

# Entity type -> core.validacion validation type (the ones with a strict shape).
# The rest (persona, org, hash...) are not validated by shape.
_TIPO_VALIDACION = {
    'ip': 'ip', 'dominio': 'dominio', 'subdominio': 'dominio',
    'email': 'email', 'usuario': 'usuario',
}


# ── Step 13: entity type catalog ─────────────────────────────────────────────
# Single source of truth for which types exist and how they look (the graph will
# read from here in F6). etiqueta = readable name; color = palette used in the graph.
TIPOS = {
    'objetivo':   {'etiqueta': 'Target',       'color': '#d99a4e'},
    'dominio':    {'etiqueta': 'Domain',       'color': '#5b9bd5'},
    'subdominio': {'etiqueta': 'Subdomain',    'color': '#7fb8d9'},
    'ip':         {'etiqueta': 'IP',           'color': '#d9564b'},
    'email':      {'etiqueta': 'Email',        'color': '#6fae7c'},
    'usuario':    {'etiqueta': 'Username',     'color': '#cc9a3c'},
    'telefono':   {'etiqueta': 'Phone',        'color': '#c99a6b'},
    'persona':    {'etiqueta': 'Person',       'color': '#e0af68'},
    'org':        {'etiqueta': 'Organization', 'color': '#b07a9e'},
    'url':        {'etiqueta': 'URL',          'color': '#5fa8a0'},
    'puerto':     {'etiqueta': 'Port',         'color': '#8b8b98'},
    'hash':       {'etiqueta': 'Hash',         'color': '#9a7ecc'},
    'archivo':    {'etiqueta': 'File',         'color': '#7a85b0'},
    'cve':        {'etiqueta': 'CVE',          'color': '#d9564b'},
    'bucket':     {'etiqueta': 'Bucket',       'color': '#d9564b'},
    'credencial': {'etiqueta': 'Credential',   'color': '#f7768e'},
    'asn':        {'etiqueta': 'ASN',          'color': '#7a85b0'},
    'pais':       {'etiqueta': 'Country',      'color': '#7a85b0'},
    'tech':       {'etiqueta': 'Technology',   'color': '#5fa8a0'},
    'imagen':     {'etiqueta': 'Image',        'color': '#73daca'},
    'wallet':     {'etiqueta': 'Wallet',       'color': '#e0af68'},
    'plataforma': {'etiqueta': 'Platform',     'color': '#c17a52'},
    'repo':       {'etiqueta': 'Repository',   'color': '#d99a4e'},
}


def valid_type(tipo: str) -> bool:
    return tipo in TIPOS


# ── Step 22: per-type normalizers (for stable dedup) ─────────────────────────
def normalize(tipo: str, valor: str) -> str:
    """Canonical form of a value, so two writes of the same datum yield the same
    id. E.g.: 'WWW.Example.COM.' and 'example.com' -> 'example.com'."""
    v = (valor or '').strip()
    if tipo in ('dominio', 'subdominio'):
        v = v.lower().rstrip('.')
        if v.startswith('www.'):
            v = v[4:]
    elif tipo == 'ip':
        try:
            v = str(ipaddress.ip_address(v))   # compresses IPv6, validates
        except ValueError:
            pass
    elif tipo == 'email':
        v = v.lower()
    elif tipo == 'url':
        v = v.rstrip('/')
    return v


def _ahora() -> str:
    return datetime.datetime.now().isoformat(timespec='seconds')


# ── Step 14: the Entity ──────────────────────────────────────────────────────
@dataclass
class Entity:
    """Atomic unit of data. The id derives from (type, normalized value), so two
    entities of the same datum are the SAME entity even if another source creates
    it. `origenes` accumulates which transforms produced it (traceability)."""
    tipo: str
    valor: str
    propiedades: dict = field(default_factory=dict)
    origenes: set = field(default_factory=set)     # transform/source names
    procedencia: list = field(default_factory=list)  # step 18: [{transform, input}]
    tags: set = field(default_factory=set)          # step 23: interesting/suspicious/...
    confianza: float = 1.0                          # 0..1
    creada: str = field(default_factory=_ahora)
    id: str = field(default='', init=False)

    def __post_init__(self):
        if not valid_type(self.tipo):
            raise ValueError(f"unknown entity type: {self.tipo!r}")
        self.valor = normalize(self.tipo, self.valor)
        if not self.valor:
            raise ValueError("empty entity value")
        if isinstance(self.origenes, (list, tuple)):
            self.origenes = set(self.origenes)
        if isinstance(self.tags, (list, tuple)):
            self.tags = set(self.tags)
        self.id = self._compute_id()

    # ── Step 23: analyst tags ──
    def tag(self, *tags) -> None:
        self.tags.update(tags)

    def untag(self, tag) -> None:
        self.tags.discard(tag)

    # ── Step 18: detailed traceability ──
    def note_provenance(self, transform, input_id=None) -> None:
        """Records which transform (and on which input entity) created it."""
        self.origenes.add(transform)
        entrada = {'transform': transform, 'input': input_id}
        if entrada not in self.procedencia:
            self.procedencia.append(entrada)

    def _compute_id(self) -> str:
        base = f"{self.tipo}:{self.valor}".encode('utf-8')
        return hashlib.sha1(base).hexdigest()[:16]

    def well_formed(self) -> bool:
        """True if the value is well-formed for its type, using the SAME security
        validators (step 25). Types without a strict shape (persona, org, hash...)
        return True. Not enforced at construction: it's an optional check so
        transforms can filter junk before adding."""
        tv = _TIPO_VALIDACION.get(self.tipo)
        return True if tv is None else _validar(self.valor, tv)

    def merge(self, otra: 'Entity') -> None:
        """Absorbs another entity of the same id (step 17): merges origins and
        properties, raises confidence, keeps the oldest date."""
        if otra.id != self.id:
            raise ValueError("cannot merge entities of different id")
        self.origenes |= otra.origenes
        self.tags |= otra.tags
        for p in otra.procedencia:
            if p not in self.procedencia:
                self.procedencia.append(p)
        for k, v in otra.propiedades.items():
            if v not in (None, '', [], {}):
                self.propiedades[k] = v
        self.confianza = max(self.confianza, otra.confianza)
        self.creada = min(self.creada, otra.creada)

    # ── Step 21: serialization ──
    def to_dict(self) -> dict:
        d = asdict(self)
        d['origenes'] = sorted(self.origenes)   # a set is not JSON-serializable
        d['tags'] = sorted(self.tags)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'Entity':
        e = cls(tipo=d['tipo'], valor=d['valor'],
                propiedades=dict(d.get('propiedades', {})),
                origenes=set(d.get('origenes', [])),
                procedencia=list(d.get('procedencia', [])),
                tags=set(d.get('tags', [])),
                confianza=d.get('confianza', 1.0))
        e.creada = d.get('creada', e.creada)
        return e


# ── Step 15: the Relation ────────────────────────────────────────────────────
@dataclass
class Relation:
    """Typed, directed edge between two entities (by id). Deterministic id from
    (source, target, label) -> the same relation is never duplicated."""
    origen: str        # entity id
    destino: str       # entity id
    etiqueta: str = ''
    id: str = field(default='', init=False)

    def __post_init__(self):
        base = f"{self.origen}>{self.destino}:{self.etiqueta}".encode('utf-8')
        self.id = hashlib.sha1(base).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'Relation':
        return cls(origen=d['origen'], destino=d['destino'], etiqueta=d.get('etiqueta', ''))


# ── Steps 16 + 17: the Store with automatic dedup ────────────────────────────
class Store:
    """Holds a case's entities and relations. Deduplicates by id on add. If given
    a Bus, publishes events on create/merge/relate (step 19)."""

    def __init__(self, bus=None):
        self._entidades: dict[str, Entity] = {}
        self._relaciones: dict[str, Relation] = {}
        self._por_tipo: dict[str, set] = {}     # type -> {id, ...}
        self._bus = bus

    def _publish(self, evento, *args):
        if self._bus is not None:
            self._bus.publish(evento, *args)

    # -- entities --
    def add(self, ent: Entity) -> Entity:
        """Adds or merges. Returns the live entity in the store (step 17)."""
        existente = self._entidades.get(ent.id)
        if existente:
            existente.merge(ent)
            self._publish('entidad_actualizada', existente)
            return existente
        self._entidades[ent.id] = ent
        self._por_tipo.setdefault(ent.tipo, set()).add(ent.id)
        self._publish('entidad_nueva', ent)
        return ent

    def create(self, tipo, valor, **kw) -> Entity:
        """Shortcut: builds an Entity and adds it (deduplicating)."""
        return self.add(Entity(tipo=tipo, valor=valor, **kw))

    def obtener(self, id_: str) -> Entity | None:
        return self._entidades.get(id_)

    def buscar(self, tipo, valor) -> Entity | None:
        """Looks up by (type, value) without adding -- respects normalization."""
        eid = hashlib.sha1(f"{tipo}:{normalize(tipo, valor)}".encode()).hexdigest()[:16]
        return self._entidades.get(eid)

    def of_type(self, tipo) -> list:
        return [self._entidades[i] for i in self._por_tipo.get(tipo, ())]

    # -- relations --
    def relate(self, origen, destino, etiqueta='') -> Relation:
        """Connects two entities (by id or Entity object). Deduplicates."""
        oid = origen.id if isinstance(origen, Entity) else origen
        did = destino.id if isinstance(destino, Entity) else destino
        rel = Relation(origen=oid, destino=did, etiqueta=etiqueta)
        if rel.id not in self._relaciones:
            self._relaciones[rel.id] = rel
            self._publish('relacion_nueva', rel)
        return self._relaciones[rel.id]

    # -- views --
    @property
    def entidades(self) -> list:
        return list(self._entidades.values())

    @property
    def relaciones(self) -> list:
        return list(self._relaciones.values())

    def __len__(self) -> int:
        return len(self._entidades)

    # ── Step 21: full-case serialization ──
    def to_dict(self) -> dict:
        return {
            'entidades': [e.to_dict() for e in self._entidades.values()],
            'relaciones': [r.to_dict() for r in self._relaciones.values()],
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'Store':
        alm = cls()
        for ed in d.get('entidades', []):
            alm.add(Entity.from_dict(ed))
        for rd in d.get('relaciones', []):
            r = Relation.from_dict(rd)
            alm._relaciones[r.id] = r
        return alm
