"""Tests de persistencia SQLite del modelo (F1 paso 20).

Correr:  ../.venv/bin/python -m pytest test_persistencia.py -q
"""
from core.modelo import Store
from core.persistencia import guardar_almacen, cargar_almacen


def _almacen_ejemplo():
    alm = Store()
    d = alm.crear('dominio', 'example.com', origenes={'whois'},
                  propiedades={'registrar': 'GoDaddy'})
    d.etiquetar('interesante')
    i = alm.crear('ip', '93.184.216.34', origenes={'dns'})
    i.anotar_procedencia('transform_dns', input_id=d.id)
    alm.relacionar(d, i, 'resuelve_a')
    return alm


def test_guardar_y_cargar_roundtrip(tmp_path):
    db = str(tmp_path / 'caso.db')
    original = _almacen_ejemplo()
    guardar_almacen(original, db)

    cargado = cargar_almacen(db)
    assert len(cargado) == 2
    assert len(cargado.relaciones) == 1

    d = cargado.buscar('dominio', 'example.com')
    assert d.origenes == {'whois'}
    assert d.propiedades == {'registrar': 'GoDaddy'}
    assert d.tags == {'interesante'}

    i = cargado.buscar('ip', '93.184.216.34')
    assert {'transform': 'transform_dns', 'input': d.id} in i.procedencia


def test_guardar_es_idempotente(tmp_path):
    db = str(tmp_path / 'caso.db')
    alm = _almacen_ejemplo()
    guardar_almacen(alm, db)
    guardar_almacen(alm, db)   # segunda vez: upsert, no duplica
    cargado = cargar_almacen(db)
    assert len(cargado) == 2
    assert len(cargado.relaciones) == 1


def test_ids_estables_tras_recarga(tmp_path):
    db = str(tmp_path / 'caso.db')
    alm = _almacen_ejemplo()
    ids_antes = {e.id for e in alm.entidades}
    guardar_almacen(alm, db)
    cargado = cargar_almacen(db)
    ids_despues = {e.id for e in cargado.entidades}
    assert ids_antes == ids_despues, "los ids deben sobrevivir el guardado/carga"
