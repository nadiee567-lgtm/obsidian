"""Tests for the JSON/CSV exporters (F7 step 94).

Run:  ../.venv/bin/python -m pytest test_exportar.py -q
"""
import csv
import io
import json

from core.modelo import Store
from core.correlacion import Finding
from core.exportar import export_json, export_csv


def _demo():
    store = Store()
    d = store.create('domain', 'target.com', properties={'org': 'ACME'})
    ip = store.create('ip', '93.184.216.34')
    ip.tag('threat-listed')
    store.relate(d.id, ip.id, 'resuelve')
    return store, d, ip


def test_json_reimportable():
    store, d, ip = _demo()
    h = [Finding('ip-listed', 'high', 'x', [ip.id])]
    txt = export_json(store, h, score=20, meta={'workspace': 'c1'})
    obj = json.loads(txt)
    assert obj['meta']['workspace'] == 'c1'
    assert obj['score'] == 20
    assert len(obj['findings']) == 1
    # the full case can be reconstructed
    alm2 = Store.from_dict(obj)
    assert len(alm2) == len(store) == 2
    assert {e.value for e in alm2.entities} == {'target.com', '93.184.216.34'}
    assert len(alm2.relations) == 1


def test_csv_tiene_cabecera_filas():
    store, _, _ = _demo()
    rows = list(csv.reader(io.StringIO(export_csv(store))))
    assert rows[0] == ['type', 'value', 'tags', 'sources', 'confidence', 'properties']
    assert len(rows) == 1 + 2                       # header + 2 entities
    valores = {f[1] for f in rows[1:]}
    assert valores == {'target.com', '93.184.216.34'}


def test_csv_neutraliza_inyeccion_formulas():
    """A tag starting with a formula (=+-@) must not stay executable in the cell."""
    store = Store()
    e = store.create('email', 'a@b.com')
    e.tag('=HYPERLINK(evil)')
    rows = list(csv.reader(io.StringIO(export_csv(store))))
    tags = rows[1][2]
    assert not tags.startswith('=')       # neutralized
    assert tags.startswith("'")


def test_csv_value_dangerous_at_start():
    store = Store()
    store.create('user', '=cmd')          # username allows arbitrary text
    rows = list(csv.reader(io.StringIO(export_csv(store))))
    assert rows[1][1] == "'=cmd"         # sanitized


def test_csv_ninguna_celda_empieza_with_formula():
    """Invariant: NO data cell starts with a formula character."""
    store = Store()
    store.create('user', '+evil')
    store.create('user', '-2+3')
    u = store.create('email', 'x@y.com'); u.tag('@cmd')
    rows = list(csv.reader(io.StringIO(export_csv(store))))
    for fila in rows[1:]:
        for celda in fila:
            assert not (celda and celda[0] in ('=', '+', '-', '@')), f'dangerous cell: {celda!r}'
