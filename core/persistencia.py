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
CREATE TABLE IF NOT EXISTS entidades (
    id TEXT PRIMARY KEY,
    tipo TEXT NOT NULL,
    valor TEXT NOT NULL,
    propiedades TEXT,
    origenes TEXT,
    tags TEXT,
    procedencia TEXT,
    confianza REAL,
    creada TEXT
);
CREATE TABLE IF NOT EXISTS relaciones (
    id TEXT PRIMARY KEY,
    origen TEXT NOT NULL,
    destino TEXT NOT NULL,
    etiqueta TEXT
);
CREATE TABLE IF NOT EXISTS historial (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    transform TEXT,
    entrada TEXT,
    salidas INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ent_tipo  ON entidades(tipo);
CREATE INDEX IF NOT EXISTS idx_ent_valor ON entidades(valor);
CREATE INDEX IF NOT EXISTS idx_rel_origen ON relaciones(origen);
"""


def _conectar(db_path):
    con = sqlite3.connect(db_path)
    con.executescript(_SCHEMA)
    return con


def save_store(almacen: Store, db_path: str) -> None:
    """Dumps the full store to the DB (upsert by id)."""
    con = _conectar(db_path)
    with con:
        for e in almacen.entidades:
            con.execute(
                "INSERT OR REPLACE INTO entidades "
                "(id,tipo,valor,propiedades,origenes,tags,procedencia,confianza,creada) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (e.id, e.tipo, e.valor,
                 json.dumps(e.propiedades, default=str),
                 json.dumps(sorted(e.origenes)),
                 json.dumps(sorted(e.tags)),
                 json.dumps(e.procedencia, default=str),
                 e.confianza, e.creada),
            )
        for r in almacen.relaciones:
            con.execute(
                "INSERT OR REPLACE INTO relaciones (id,origen,destino,etiqueta) VALUES (?,?,?,?)",
                (r.id, r.origen, r.destino, r.etiqueta),
            )
    con.close()


def load_store(db_path: str) -> Store:
    """Rebuilds a Store from the DB. SILENT load (no bus): does not fire events,
    because loading from disk is not 'discovering' new data."""
    con = _conectar(db_path)
    alm = Store()   # no bus -> add() does not publish
    for row in con.execute(
        "SELECT tipo,valor,propiedades,origenes,tags,procedencia,confianza,creada FROM entidades"
    ):
        tipo, valor, props, orig, tags, proc, conf, creada = row
        e = Entity(
            tipo=tipo, valor=valor,
            propiedades=json.loads(props or '{}'),
            origenes=set(json.loads(orig or '[]')),
            procedencia=json.loads(proc or '[]'),
            tags=set(json.loads(tags or '[]')),
            confianza=conf if conf is not None else 1.0,
        )
        e.creada = creada or e.creada
        alm.add(e)
    for row in con.execute("SELECT origen,destino,etiqueta FROM relaciones"):
        alm.relate(row[0], row[1], row[2] or '')
    con.close()
    return alm


# ── Per-case history / audit (F3 step 48) ────────────────────────────────────
def record_event(db_path: str, transform: str, entrada: str, salidas: int) -> None:
    """Records that a transform ran (what, when, how many results)."""
    con = _conectar(db_path)
    with con:
        con.execute(
            "INSERT INTO historial (ts,transform,entrada,salidas) VALUES (?,?,?,?)",
            (datetime.datetime.now().isoformat(timespec='seconds'), transform, entrada, salidas),
        )
    con.close()


def read_history(db_path: str, limite: int = 100) -> list:
    """Case history, most recent first."""
    con = _conectar(db_path)
    con.row_factory = sqlite3.Row
    filas = con.execute(
        "SELECT ts,transform,entrada,salidas FROM historial ORDER BY id DESC LIMIT ?",
        (limite,),
    ).fetchall()
    con.close()
    return [dict(f) for f in filas]
