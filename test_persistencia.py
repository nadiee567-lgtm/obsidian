"""Tests de persistencia SQLite del modelo (F1 step 20).

Correr:  ../.venv/bin/python -m pytest test_persistencia.py -q
"""
from core.modelo import Store
from core.persistencia import save_store, load_store


def _store_example():
    store = Store()
    d = store.create('domain', 'example.com', sources={'whois'},
                  properties={'registrar': 'GoDaddy'})
    d.tag('interesting')
    i = store.create('ip', '93.184.216.34', sources={'dns'})
    i.note_provenance('transform_dns', input_id=d.id)
    store.relate(d, i, 'resuelve_a')
    return store


def test_save_load_roundtrip(tmp_path):
    db = str(tmp_path / 'caso.db')
    original = _store_example()
    save_store(original, db)

    cargado = load_store(db)
    assert len(cargado) == 2
    assert len(cargado.relations) == 1

    d = cargado.find('domain', 'example.com')
    assert d.sources == {'whois'}
    assert d.properties == {'registrar': 'GoDaddy'}
    assert d.tags == {'interesting'}

    i = cargado.find('ip', '93.184.216.34')
    assert {'transform': 'transform_dns', 'input': d.id} in i.provenance


def test_save_is_idempotent(tmp_path):
    db = str(tmp_path / 'caso.db')
    store = _store_example()
    save_store(store, db)
    save_store(store, db)   # segunda vez: upsert, no duplica
    cargado = load_store(db)
    assert len(cargado) == 2
    assert len(cargado.relations) == 1


def test_ids_estables_tras_recarga(tmp_path):
    db = str(tmp_path / 'caso.db')
    store = _store_example()
    ids_antes = {e.id for e in store.entities}
    save_store(store, db)
    cargado = load_store(db)
    ids_despues = {e.id for e in cargado.entities}
    assert ids_antes == ids_despues, "los ids deben sobrevivir el guardado/carga"
