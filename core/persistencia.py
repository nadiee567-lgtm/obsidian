"""Typed-model persistence in SQLite -- F1 step 20.

Saves a Store (entities + relations) into SQLite tables, one row per entity --
queryable, unlike a JSON blob. Foundation of workspaces (F3), where each case
will have its own DB.

PURE module with respect to Flask: takes the DB path, does not depend on the server."""
import sqlite3
import json
import datetime

from core.modelo import Entity, Store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    properties TEXT,
    sources TEXT,
    tags TEXT,
    provenance TEXT,
    confidence REAL,
    created TEXT
);
CREATE TABLE IF NOT EXISTS relations (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    label TEXT
);
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    transform TEXT,
    input TEXT,
    outputs INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ent_type  ON entities(type);
CREATE INDEX IF NOT EXISTS idx_ent_value ON entities(value);
CREATE INDEX IF NOT EXISTS idx_rel_source ON relations(source);
"""

# ── Migration: Spanish schema (pre-English) -> English (F1/Phase B3) ─────────
# Old cases created before the English rename have tables `entidades`/`relaciones`/
# `history` with Spanish columns. Rename them in place (data preserved) so any
# existing .db keeps loading. Idempotent: skips whatever is already English.
_TABLE_RENAME = {'entidades': 'entities', 'relaciones': 'relations', 'history': 'history'}
_COLUMN_RENAME = {
    'entities': {'tipo': 'type', 'valor': 'value', 'propiedades': 'properties',
                 'origenes': 'sources', 'procedencia': 'provenance',
                 'confianza': 'confidence', 'creada': 'created'},
    'relations': {'origen': 'source', 'destino': 'target', 'etiqueta': 'label'},
    'history': {'input': 'input', 'outputs': 'outputs'},
}


def _migrar_esquema(con) -> None:
    """Renames legacy Spanish tables/columns to English, in place (SQLite >= 3.25)."""
    tablas = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    # 1) rename tables (only if the old exists and the new does not)
    for viejo, nuevo in _TABLE_RENAME.items():
        if viejo in tablas and nuevo not in tablas:
            con.execute(f"ALTER TABLE {viejo} RENAME TO {nuevo}")
            tablas.discard(viejo)
            tablas.add(nuevo)
    # 2) rename columns within each (now-English) table
    for tabla, cols in _COLUMN_RENAME.items():
        if tabla not in tablas:
            continue
        actuales = {r[1] for r in con.execute(f"PRAGMA table_info({tabla})")}
        for viejo, nuevo in cols.items():
            if viejo in actuales and nuevo not in actuales:
                con.execute(f"ALTER TABLE {tabla} RENAME COLUMN {viejo} TO {nuevo}")


# Spanish entity-type VALUES stored in old cases -> English (Phase B3, step 2).
# Changing a type value changes the entity id (id = sha1("type:value")), so the
# ids must be recomputed and every relation endpoint remapped. Idempotent.
_TYPE_VALUE_RENAME = {
    'dominio': 'domain', 'subdominio': 'subdomain', 'usuario': 'user',
    'telefono': 'phone', 'plataforma': 'platform', 'credencial': 'credential',
    'archivo': 'file', 'imagen': 'image', 'puerto': 'port', 'pais': 'country',
    'persona': 'person', 'objetivo': 'target',
}


def _sha1_id(base: str) -> str:
    import hashlib
    return hashlib.sha1(base.encode('utf-8')).hexdigest()[:16]


def _migrar_valores_tipo(con) -> None:
    """Rewrites legacy Spanish type values to English, recomputing entity ids and
    remapping relation endpoints. Runs at raw-SQL level, before the model (which
    would reject the old type values) ever sees the rows. No-op if already English."""
    try:
        tipos = {r[0] for r in con.execute("SELECT DISTINCT type FROM entities")}
    except sqlite3.OperationalError:
        return                                   # fresh DB, no entities table yet
    if not (tipos & set(_TYPE_VALUE_RENAME)):
        return                                   # nothing legacy -> done
    rows = con.execute(
        "SELECT id,type,value,properties,sources,tags,provenance,confidence,created FROM entities"
    ).fetchall()
    idmap = {}                                   # old entity id -> new entity id
    nuevas = []
    for (eid, type_, value, props, srcs, tags, prov, conf, created) in rows:
        ntype = _TYPE_VALUE_RENAME.get(type_, type_)
        nid = _sha1_id(f"{ntype}:{value}")
        idmap[eid] = nid
        nuevas.append((nid, ntype, value, props, srcs, tags, prov, conf, created))
    rels = con.execute("SELECT id,source,target,label FROM relations").fetchall()
    nrels = []
    for (_rid, src, tgt, label) in rels:
        ns, nt = idmap.get(src, src), idmap.get(tgt, tgt)
        nrels.append((_sha1_id(f"{ns}>{nt}:{label or ''}"), ns, nt, label))
    with con:
        con.execute("DELETE FROM entities")
        con.executemany(
            "INSERT OR REPLACE INTO entities "
            "(id,type,value,properties,sources,tags,provenance,confidence,created) "
            "VALUES (?,?,?,?,?,?,?,?,?)", nuevas)
        con.execute("DELETE FROM relations")
        con.executemany(
            "INSERT OR REPLACE INTO relations (id,source,target,label) VALUES (?,?,?,?)", nrels)


def _conectar(db_path):
    con = sqlite3.connect(db_path)
    _migrar_esquema(con)          # 1) legacy Spanish tables/columns -> English
    con.executescript(_SCHEMA)    # 2) create tables if this is a fresh DB
    _migrar_valores_tipo(con)     # 3) legacy Spanish type VALUES -> English (+ reindex ids)
    return con


def save_store(almacen: Store, db_path: str) -> None:
    """Dumps the full store to the DB (upsert by id)."""
    con = _conectar(db_path)
    with con:
        for e in almacen.entities:
            con.execute(
                "INSERT OR REPLACE INTO entities "
                "(id,type,value,properties,sources,tags,provenance,confidence,created) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (e.id, e.type, e.value,
                 json.dumps(e.properties, default=str),
                 json.dumps(sorted(e.sources)),
                 json.dumps(sorted(e.tags)),
                 json.dumps(e.provenance, default=str),
                 e.confidence, e.created),
            )
        for r in almacen.relations:
            con.execute(
                "INSERT OR REPLACE INTO relations (id,source,target,label) VALUES (?,?,?,?)",
                (r.id, r.source, r.target, r.label),
            )
    con.close()


def load_store(db_path: str) -> Store:
    """Rebuilds a Store from the DB. SILENT load (no bus): does not fire events,
    because loading from disk is not 'discovering' new data."""
    con = _conectar(db_path)
    alm = Store()   # no bus -> add() does not publish
    for row in con.execute(
        "SELECT type,value,properties,sources,tags,provenance,confidence,created FROM entities"
    ):
        type_, value, props, orig, tags, proc, conf, created = row
        e = Entity(
            type=type_, value=value,
            properties=json.loads(props or '{}'),
            sources=set(json.loads(orig or '[]')),
            provenance=json.loads(proc or '[]'),
            tags=set(json.loads(tags or '[]')),
            confidence=conf if conf is not None else 1.0,
        )
        e.created = created or e.created
        alm.add(e)
    for row in con.execute("SELECT source,target,label FROM relations"):
        alm.relate(row[0], row[1], row[2] or '')
    con.close()
    return alm


# ── Per-case history / audit (F3 step 48) ────────────────────────────────────
def record_event(db_path: str, transform: str, input_: str, outputs: int) -> None:
    """Records that a transform ran (what, when, how many results)."""
    con = _conectar(db_path)
    with con:
        con.execute(
            "INSERT INTO history (ts,transform,input,outputs) VALUES (?,?,?,?)",
            (datetime.datetime.now().isoformat(timespec='seconds'), transform, input_, outputs),
        )
    con.close()


def read_history(db_path: str, limite: int = 100) -> list:
    """Case history, most recent first."""
    con = _conectar(db_path)
    con.row_factory = sqlite3.Row
    filas = con.execute(
        "SELECT ts,transform,input,outputs FROM history ORDER BY id DESC LIMIT ?",
        (limite,),
    ).fetchall()
    con.close()
    return [dict(f) for f in filas]
