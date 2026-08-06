"""Tests for the JSON/CSV exporters (F7 step 94).

Run:  ../.venv/bin/python -m pytest test_exportar.py -q
"""
import csv
import io
import json

from core.modelo import Store
from core.correlacion import Finding
from core.exportar import exportar_json, exportar_csv


def _demo():
    alm = Store()
    d = alm.create('dominio', 'objetivo.com', propiedades={'org': 'ACME'})
    ip = alm.create('ip', '93.184.216.34')
    ip.tag('listado-amenaza')
    alm.relate(d.id, ip.id, 'resuelve')
    return alm, d, ip


def test_json_reimportable():
    alm, d, ip = _demo()
    h = [Finding('ip-listada', 'alto', 'x', [ip.id])]
    txt = exportar_json(alm, h, score=20, meta={'workspace': 'c1'})
    obj = json.loads(txt)
    assert obj['meta']['workspace'] == 'c1'
    assert obj['score'] == 20
    assert len(obj['hallazgos']) == 1
    # the full case can be reconstructed
    alm2 = Store.from_dict(obj)
    assert len(alm2) == len(alm) == 2
    assert {e.valor for e in alm2.entidades} == {'objetivo.com', '93.184.216.34'}
    assert len(alm2.relaciones) == 1


def test_csv_tiene_cabecera_y_filas():
    alm, _, _ = _demo()
    filas = list(csv.reader(io.StringIO(exportar_csv(alm))))
    assert filas[0] == ['type', 'value', 'tags', 'sources', 'confidence', 'properties']
    assert len(filas) == 1 + 2                       # header + 2 entities
    valores = {f[1] for f in filas[1:]}
    assert valores == {'objetivo.com', '93.184.216.34'}


def test_csv_neutraliza_inyeccion_de_formulas():
    """A tag starting with a formula (=+-@) must not stay executable in the cell."""
    alm = Store()
    e = alm.create('email', 'a@b.com')
    e.tag('=HYPERLINK(evil)')
    filas = list(csv.reader(io.StringIO(exportar_csv(alm))))
    tags = filas[1][2]
    assert not tags.startswith('=')       # neutralized
    assert tags.startswith("'")


def test_csv_valor_peligroso_al_inicio():
    alm = Store()
    alm.create('usuario', '=cmd')          # usuario allows arbitrary text
    filas = list(csv.reader(io.StringIO(exportar_csv(alm))))
    assert filas[1][1] == "'=cmd"         # sanitized


def test_csv_ninguna_celda_empieza_con_formula():
    """Invariant: NO data cell starts with a formula character."""
    alm = Store()
    alm.create('usuario', '+evil')
    alm.create('usuario', '-2+3')
    u = alm.create('email', 'x@y.com'); u.tag('@cmd')
    filas = list(csv.reader(io.StringIO(exportar_csv(alm))))
    for fila in filas[1:]:
        for celda in fila:
            assert not (celda and celda[0] in ('=', '+', '-', '@')), f'dangerous cell: {celda!r}'
