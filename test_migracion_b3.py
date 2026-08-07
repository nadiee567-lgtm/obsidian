"""Test for the Phase B3 data migration (Spanish schema+type values -> English)."""
import sqlite3
from core.persistencia import load_store, save_store


def _crear_db_vieja(path):
    """Builds a DB with the OLD Spanish schema + Spanish type values + a relation."""
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE entidades (id TEXT PRIMARY KEY, tipo TEXT, valor TEXT,
            propiedades TEXT, origenes TEXT, tags TEXT, procedencia TEXT,
            confianza REAL, creada TEXT);
        CREATE TABLE relaciones (id TEXT PRIMARY KEY, origen TEXT, destino TEXT, etiqueta TEXT);
        CREATE TABLE history (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
            transform TEXT, input TEXT, outputs INTEGER);
    """)
    # old ids computed the old way: sha1("domain:x.com") etc. -- but the migration
    # recomputes from type:value, so the stored id value here is irrelevant.
    con.execute("INSERT INTO entidades VALUES ('OLD1','domain','x.com','{}','[]','[]','[]',1.0,'t')")
    con.execute("INSERT INTO entidades VALUES ('OLD2','ip','1.2.3.4','{}','[]','[]','[]',1.0,'t')")
    con.execute("INSERT INTO relaciones VALUES ('R1','OLD1','OLD2','resuelve')")
    con.commit(); con.close()


def test_migracion_completa(tmp_path):
    db = str(tmp_path / 'old.db')
    _crear_db_vieja(db)
    store = load_store(db)                      # triggers schema + type-value migration
    # entities survived, types are English now
    tipos = {e.type for e in store.entities}
    assert tipos == {'domain', 'ip'}
    dom = store.find('domain', 'x.com')
    assert dom is not None and dom.value == 'x.com'
    # the relation still connects the same two entities (endpoints remapped)
    assert len(store.relations) == 1
    r = store.relations[0]
    ids = {e.id for e in store.entities}
    assert r.source in ids and r.target in ids and r.label == 'resuelve'
    # round-trip through the new schema
    save_store(store, db)
    alm2 = load_store(db)
    assert {e.type for e in alm2.entities} == {'domain', 'ip'}
    assert len(alm2.relations) == 1


def test_migracion_idempotente(tmp_path):
    db = str(tmp_path / 'old.db')
    _crear_db_vieja(db)
    load_store(db)
    a = load_store(db)                        # second open: already English, no-op
    assert {e.type for e in a.entities} == {'domain', 'ip'}
    assert len(a.entities) == 2
