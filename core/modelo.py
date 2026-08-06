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

from core.validacion import _validate   # step 25: a single source of truth

# Entity type -> core.validacion validation type (the ones with a strict shape).
# The rest (persona, org, hash...) are not validated by shape.
_TIPO_VALIDACION = {
    'ip': 'ip', 'domain': 'domain', 'subdomain': 'domain',
    'email': 'email', 'user': 'user',
}


# ── Step 13: entity type catalog ─────────────────────────────────────────────
# Single source of truth for which types exist and how they look (the graph will
# read from here in F6). label = readable name; color = palette used in the graph.
TIPOS = {
    'target':   {'label': 'Target',       'color': '#d99a4e'},
    'domain':    {'label': 'Domain',       'color': '#5b9bd5'},
    'subdomain': {'label': 'Subdomain',    'color': '#7fb8d9'},
    'ip':         {'label': 'IP',           'color': '#d9564b'},
    'email':      {'label': 'Email',        'color': '#6fae7c'},
    'user':    {'label': 'Username',     'color': '#cc9a3c'},
    'phone':   {'label': 'Phone',        'color': '#c99a6b'},
    'person':    {'label': 'Person',       'color': '#e0af68'},
    'org':        {'label': 'Organization', 'color': '#b07a9e'},
    'url':        {'label': 'URL',          'color': '#5fa8a0'},
    'port':     {'label': 'Port',         'color': '#8b8b98'},
    'hash':       {'label': 'Hash',         'color': '#9a7ecc'},
    'file':    {'label': 'File',         'color': '#7a85b0'},
    'cve':        {'label': 'CVE',          'color': '#d9564b'},
    'bucket':     {'label': 'Bucket',       'color': '#d9564b'},
    'credential': {'label': 'Credential',   'color': '#f7768e'},
    'asn':        {'label': 'ASN',          'color': '#7a85b0'},
    'country':       {'label': 'Country',      'color': '#7a85b0'},
    'tech':       {'label': 'Technology',   'color': '#5fa8a0'},
    'image':     {'label': 'Image',        'color': '#73daca'},
    'wallet':     {'label': 'Wallet',       'color': '#e0af68'},
    'platform': {'label': 'Platform',     'color': '#c17a52'},
    'repo':       {'label': 'Repository',   'color': '#d99a4e'},
}


def valid_type(type: str) -> bool:
    return type in TIPOS


# ── Step 22: per-type normalizers (for stable dedup) ─────────────────────────
def normalize(type: str, value: str) -> str:
    """Canonical form of a value, so two writes of the same datum yield the same
    id. E.g.: 'WWW.Example.COM.' and 'example.com' -> 'example.com'."""
    v = (value or '').strip()
    if type in ('domain', 'subdomain'):
        v = v.lower().rstrip('.')
        if v.startswith('www.'):
            v = v[4:]
    elif type == 'ip':
        try:
            v = str(ipaddress.ip_address(v))   # compresses IPv6, validates
        except ValueError:
            pass
    elif type == 'email':
        v = v.lower()
    elif type == 'url':
        v = v.rstrip('/')
    return v


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec='seconds')


# ── Step 14: the Entity ──────────────────────────────────────────────────────
@dataclass
class Entity:
    """Atomic unit of data. The id derives from (type, normalized value), so two
    entities of the same datum are the SAME entity even if another source creates
    it. `sources` accumulates which transforms produced it (traceability)."""
    type: str
    value: str
    properties: dict = field(default_factory=dict)
    sources: set = field(default_factory=set)     # transform/source names
    provenance: list = field(default_factory=list)  # step 18: [{transform, input}]
    tags: set = field(default_factory=set)          # step 23: interesting/suspicious/...
    confidence: float = 1.0                          # 0..1
    created: str = field(default_factory=_now)
    id: str = field(default='', init=False)

    def __post_init__(self):
        if not valid_type(self.type):
            raise ValueError(f"unknown entity type: {self.type!r}")
        self.value = normalize(self.type, self.value)
        if not self.value:
            raise ValueError("empty entity value")
        if isinstance(self.sources, (list, tuple)):
            self.sources = set(self.sources)
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
        self.sources.add(transform)
        input = {'transform': transform, 'input': input_id}
        if input not in self.provenance:
            self.provenance.append(input)

    def _compute_id(self) -> str:
        base = f"{self.type}:{self.value}".encode('utf-8')
        return hashlib.sha1(base).hexdigest()[:16]

    def well_formed(self) -> bool:
        """True if the value is well-formed for its type, using the SAME security
        validators (step 25). Types without a strict shape (persona, org, hash...)
        return True. Not enforced at construction: it's an optional check so
        transforms can filter junk before adding."""
        tv = _TIPO_VALIDACION.get(self.type)
        return True if tv is None else _validate(self.value, tv)

    def merge(self, other: 'Entity') -> None:
        """Absorbs another entity of the same id (step 17): merges origins and
        properties, raises confidence, keeps the oldest date."""
        if other.id != self.id:
            raise ValueError("cannot merge entities of different id")
        self.sources |= other.sources
        self.tags |= other.tags
        for p in other.provenance:
            if p not in self.provenance:
                self.provenance.append(p)
        for k, v in other.properties.items():
            if v not in (None, '', [], {}):
                self.properties[k] = v
        self.confidence = max(self.confidence, other.confidence)
        self.created = min(self.created, other.created)

    # ── Step 21: serialization ──
    def to_dict(self) -> dict:
        d = asdict(self)
        d['sources'] = sorted(self.sources)   # a set is not JSON-serializable
        d['tags'] = sorted(self.tags)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'Entity':
        e = cls(type=d['type'], value=d['value'],
                properties=dict(d.get('properties', {})),
                sources=set(d.get('sources', [])),
                provenance=list(d.get('provenance', [])),
                tags=set(d.get('tags', [])),
                confidence=d.get('confidence', 1.0))
        e.created = d.get('created', e.created)
        return e


# ── Step 15: the Relation ────────────────────────────────────────────────────
@dataclass
class Relation:
    """Typed, directed edge between two entities (by id). Deterministic id from
    (source, target, label) -> the same relation is never duplicated."""
    source: str        # entity id
    target: str       # entity id
    label: str = ''
    id: str = field(default='', init=False)

    def __post_init__(self):
        base = f"{self.source}>{self.target}:{self.label}".encode('utf-8')
        self.id = hashlib.sha1(base).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'Relation':
        return cls(source=d['source'], target=d['target'], label=d.get('label', ''))


# ── Steps 16 + 17: the Store with automatic dedup ────────────────────────────
class Store:
    """Holds a case's entities and relations. Deduplicates by id on add. If given
    a Bus, publishes events on create/merge/relate (step 19)."""

    def __init__(self, bus=None):
        self._entities: dict[str, Entity] = {}
        self._relations: dict[str, Relation] = {}
        self._by_type: dict[str, set] = {}     # type -> {id, ...}
        self._bus = bus

    def _publish(self, event, *args):
        if self._bus is not None:
            self._bus.publish(event, *args)

    # -- entities --
    def add(self, entity: Entity) -> Entity:
        """Adds or merges. Returns the live entity in the store (step 17)."""
        existing = self._entities.get(entity.id)
        if existing:
            existing.merge(entity)
            self._publish('entity_updated', existing)
            return existing
        self._entities[entity.id] = entity
        self._by_type.setdefault(entity.type, set()).add(entity.id)
        self._publish('entity_new', entity)
        return entity

    def create(self, type, value, **kw) -> Entity:
        """Shortcut: builds an Entity and adds it (deduplicating)."""
        return self.add(Entity(type=type, value=value, **kw))

    def get(self, id_: str) -> Entity | None:
        return self._entities.get(id_)

    def find(self, type, value) -> Entity | None:
        """Looks up by (type, value) without adding -- respects normalization."""
        eid = hashlib.sha1(f"{type}:{normalize(type, value)}".encode()).hexdigest()[:16]
        return self._entities.get(eid)

    def of_type(self, type) -> list:
        return [self._entities[i] for i in self._by_type.get(type, ())]

    # -- relations --
    def relate(self, source, target, label='') -> Relation:
        """Connects two entities (by id or Entity object). Deduplicates."""
        oid = source.id if isinstance(source, Entity) else source
        did = target.id if isinstance(target, Entity) else target
        rel = Relation(source=oid, target=did, label=label)
        if rel.id not in self._relations:
            self._relations[rel.id] = rel
            self._publish('relation_new', rel)
        return self._relations[rel.id]

    # -- views --
    @property
    def entities(self) -> list:
        return list(self._entities.values())

    @property
    def relations(self) -> list:
        return list(self._relations.values())

    def __len__(self) -> int:
        return len(self._entities)

    # ── Step 21: full-case serialization ──
    def to_dict(self) -> dict:
        return {
            'entities': [e.to_dict() for e in self._entities.values()],
            'relations': [r.to_dict() for r in self._relations.values()],
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'Store':
        store = cls()
        for ed in d.get('entities', []):
            store.add(Entity.from_dict(ed))
        for rd in d.get('relations', []):
            r = Relation.from_dict(rd)
            store._relations[r.id] = r
        return store
