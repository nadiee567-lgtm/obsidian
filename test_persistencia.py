"""Tests de persistencia SQLite del modelo (F1 paso 20).

Correr:  ../.venv/bin/python -m pytest test_persistencia.py -q
"""
from core.modelo import Store
from core.persistencia import save_store, load_store


def _almacen_ejemplo():
    alm = Store()
    d = alm.create('dominio', 'example.com', sources={'whois'},
                  properties={'registrar': 'GoDaddy'})
    d.tag('interesante')
    i = alm.create('ip', '93.184.216.34', sources={'dns'})
    i.note_provenance('transform_dns', input_id=d.id)
    alm.relate(d, i, 'resuelve_a')
    return alm


def test_guardar_y_cargar_roundtrip(tmp_path):
    db = str(tmp_path / 'caso.db')
    original = _almacen_ejemplo()
    save_store(original, db)

    cargado = load_store(db)
    assert len(cargado) == 2
    assert len(cargado.relations) == 1

    d = cargado.buscar('dominio', 'example.com')
    assert d.sources == {'whois'}
    assert d.properties == {'registrar': 'GoDaddy'}
    assert d.tags == {'interesante'}

    i = cargado.buscar('ip', '93.184.216.34')
    assert {'transform': 'transform_dns', 'input': d.id} in i.provenance


def test_guardar_es_idempotente(tmp_path):
    db = str(tmp_path / 'caso.db')
    alm = _almacen_ejemplo()
    save_store(alm, db)
    save_store(alm, db)   # segunda vez: upsert, no duplica
    cargado = load_store(db)
    assert len(cargado) == 2
    assert len(cargado.relations) == 1


def test_ids_estables_tras_recarga(tmp_path):
    db = str(tmp_path / 'caso.db')
    alm = _almacen_ejemplo()
    ids_antes = {e.id for e in alm.entities}
    save_store(alm, db)
    cargado = load_store(db)
    ids_despues = {e.id for e in cargado.entities}
    assert ids_antes == ids_despues, "los ids deben sobrevivir el guardado/carga"
