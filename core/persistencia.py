"""Persistencia del modelo tipado en SQLite — F1 paso 20.

Guarda un Almacen (entidades + relaciones) en tablas SQLite, una fila por
entidad — consultable, a diferencia de un blob JSON. Base de los workspaces
(F3), donde cada caso tendrá su propia DB.

Módulo PURO respecto a Flask: recibe la ruta de la DB, no depende del server."""
import sqlite3
import json
import datetime

from core.modelo import Entidad, Almacen

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


def guardar_almacen(almacen: Almacen, db_path: str) -> None:
    """Vuelca el almacén completo a la DB (upsert por id)."""
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


def cargar_almacen(db_path: str) -> Almacen:
    """Reconstruye un Almacen desde la DB. Carga SILENCIOSA (sin bus): no dispara
    eventos, porque cargar de disco no es 'descubrir' datos nuevos."""
    con = _conectar(db_path)
    alm = Almacen()   # sin bus -> agregar() no publica
    for row in con.execute(
        "SELECT tipo,valor,propiedades,origenes,tags,procedencia,confianza,creada FROM entidades"
    ):
        tipo, valor, props, orig, tags, proc, conf, creada = row
        e = Entidad(
            tipo=tipo, valor=valor,
            propiedades=json.loads(props or '{}'),
            origenes=set(json.loads(orig or '[]')),
            procedencia=json.loads(proc or '[]'),
            tags=set(json.loads(tags or '[]')),
            confianza=conf if conf is not None else 1.0,
        )
        e.creada = creada or e.creada
        alm.agregar(e)
    for row in con.execute("SELECT origen,destino,etiqueta FROM relaciones"):
        alm.relacionar(row[0], row[1], row[2] or '')
    con.close()
    return alm


# ── Historial / auditoría por caso (F3 paso 48) ──────────────────────────────
def registrar_evento(db_path: str, transform: str, entrada: str, salidas: int) -> None:
    """Anota que se corrió un transform (qué, cuándo, cuántos resultados)."""
    con = _conectar(db_path)
    with con:
        con.execute(
            "INSERT INTO historial (ts,transform,entrada,salidas) VALUES (?,?,?,?)",
            (datetime.datetime.now().isoformat(timespec='seconds'), transform, entrada, salidas),
        )
    con.close()


def leer_historial(db_path: str, limite: int = 100) -> list:
    """Historial del caso, más reciente primero."""
    con = _conectar(db_path)
    con.row_factory = sqlite3.Row
    filas = con.execute(
        "SELECT ts,transform,entrada,salidas FROM historial ORDER BY id DESC LIMIT ?",
        (limite,),
    ).fetchall()
    con.close()
    return [dict(f) for f in filas]
