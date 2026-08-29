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

_TABLE_RENAME = {'entidades': 'entities', 'relaciones': 'relations', 'history': 'history'}
_COLUMN_RENAME = {
    'entities': {'tipo': 'type', 'valor': 'value', 'propiedades': 'properties',
                 'origenes': 'sources', 'procedencia': 'provenance',
                 'confianza': 'confidence', 'creada': 'created'},
    'relations': {'origen': 'source', 'destino': 'target', 'etiqueta': 'label'},
    'history': {'input': 'input', 'outputs': 'outputs'},
}


def _migrate_schema(con) -> None:
    """Renames legacy Spanish tables/columns to English, in place (SQLite >= 3.25)."""
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for old, new in _TABLE_RENAME.items():
        if old in tables and new not in tables:
            con.execute(f"ALTER TABLE {old} RENAME TO {new}")
            tables.discard(old)
            tables.add(new)
    for table, cols in _COLUMN_RENAME.items():
        if table not in tables:
            continue
        current = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
        for old, new in cols.items():
            if old in current and new not in current:
                con.execute(f"ALTER TABLE {table} RENAME COLUMN {old} TO {new}")


_TYPE_VALUE_RENAME = {
    'domain': 'domain', 'subdominio': 'subdomain', 'username': 'user',
    'telefono': 'phone', 'plataforma': 'platform', 'credencial': 'credential',
    'archivo': 'file', 'imagen': 'image', 'puerto': 'port', 'pais': 'country',
    'persona': 'person', 'target': 'target',
}


def _sha1_id(base: str) -> str:
    import hashlib
    return hashlib.sha1(base.encode('utf-8')).hexdigest()[:16]


def _migrate_type_values(con) -> None:
    """Rewrites legacy Spanish type values to English, recomputing entity ids and
    remapping relation endpoints. Runs at raw-SQL level, before the model (which
    would reject the old type values) ever sees the rows. No-op if already English."""
    try:
        tipos = {r[0] for r in con.execute("SELECT DISTINCT type FROM entities")}
    except sqlite3.OperationalError:
        return
    if not (tipos & set(_TYPE_VALUE_RENAME)):
        return
    rows = con.execute(
        "SELECT id,type,value,properties,sources,tags,provenance,confidence,created FROM entities"
    ).fetchall()
    idmap = {}
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


def _connect(db_path):
    con = sqlite3.connect(db_path)
    _migrate_schema(con)
    con.executescript(_SCHEMA)
    _migrate_type_values(con)
    return con


def save_store(store: Store, db_path: str) -> None:
    """Dumps the full store to the DB (upsert by id)."""
    con = _connect(db_path)
    with con:
        for e in store.entities:
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
        for r in store.relations:
            con.execute(
                "INSERT OR REPLACE INTO relations (id,source,target,label) VALUES (?,?,?,?)",
                (r.id, r.source, r.target, r.label),
            )
    con.close()


def load_store(db_path: str) -> Store:
    """Rebuilds a Store from the DB. SILENT load (no bus): does not fire events,
    because loading from disk is not 'discovering' new data."""
    con = _connect(db_path)
    store = Store()
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
        store.add(e)
    for row in con.execute("SELECT source,target,label FROM relations"):
        store.relate(row[0], row[1], row[2] or '')
    con.close()
    return store


def record_event(db_path: str, transform: str, input_: str, outputs: int) -> None:
    """Records that a transform ran (what, when, how many results)."""
    con = _connect(db_path)
    with con:
        con.execute(
            "INSERT INTO history (ts,transform,input,outputs) VALUES (?,?,?,?)",
            (datetime.datetime.now().isoformat(timespec='seconds'), transform, input_, outputs),
        )
    con.close()


def read_history(db_path: str, limite: int = 100) -> list:
    """Case history, most recent first."""
    con = _connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT ts,transform,input,outputs FROM history ORDER BY id DESC LIMIT ?",
        (limite,),
    ).fetchall()
    con.close()
    return [dict(f) for f in rows]
