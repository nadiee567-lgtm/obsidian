"""Tests de los exportadores JSON/CSV (F7 paso 94).

Correr:  ../.venv/bin/python -m pytest test_exportar.py -q
"""
import csv
import io
import json

from core.modelo import Almacen
from core.correlacion import Hallazgo
from core.exportar import exportar_json, exportar_csv


def _demo():
    alm = Almacen()
    d = alm.crear('dominio', 'objetivo.com', propiedades={'org': 'ACME'})
    ip = alm.crear('ip', '93.184.216.34')
    ip.etiquetar('listado-amenaza')
    alm.relacionar(d.id, ip.id, 'resuelve')
    return alm, d, ip


def test_json_reimportable():
    alm, d, ip = _demo()
    h = [Hallazgo('ip-listada', 'alto', 'x', [ip.id])]
    txt = exportar_json(alm, h, score=20, meta={'workspace': 'c1'})
    obj = json.loads(txt)
    assert obj['meta']['workspace'] == 'c1'
    assert obj['score'] == 20
    assert len(obj['hallazgos']) == 1
    # se puede reconstruir el caso completo
    alm2 = Almacen.from_dict(obj)
    assert len(alm2) == len(alm) == 2
    assert {e.valor for e in alm2.entidades} == {'objetivo.com', '93.184.216.34'}
    assert len(alm2.relaciones) == 1


def test_csv_tiene_cabecera_y_filas():
    alm, _, _ = _demo()
    filas = list(csv.reader(io.StringIO(exportar_csv(alm))))
    assert filas[0] == ['tipo', 'valor', 'tags', 'fuentes', 'confianza', 'propiedades']
    assert len(filas) == 1 + 2                       # cabecera + 2 entidades
    valores = {f[1] for f in filas[1:]}
    assert valores == {'objetivo.com', '93.184.216.34'}


def test_csv_neutraliza_inyeccion_de_formulas():
    """Un tag que empieza con fórmula (=+-@) no debe quedar ejecutable en la celda."""
    alm = Almacen()
    e = alm.crear('email', 'a@b.com')
    e.etiquetar('=HYPERLINK(evil)')
    filas = list(csv.reader(io.StringIO(exportar_csv(alm))))
    tags = filas[1][2]
    assert not tags.startswith('=')       # neutralizada
    assert tags.startswith("'")


def test_csv_valor_peligroso_al_inicio():
    alm = Almacen()
    alm.crear('usuario', '=cmd')          # usuario permite texto arbitrario
    filas = list(csv.reader(io.StringIO(exportar_csv(alm))))
    assert filas[1][1] == "'=cmd"         # saneado


def test_csv_ninguna_celda_empieza_con_formula():
    """Invariante: NINGUNA celda de datos arranca con un carácter de fórmula."""
    alm = Almacen()
    alm.crear('usuario', '+evil')
    alm.crear('usuario', '-2+3')
    u = alm.crear('email', 'x@y.com'); u.etiquetar('@cmd')
    filas = list(csv.reader(io.StringIO(exportar_csv(alm))))
    for fila in filas[1:]:
        for celda in fila:
            assert not (celda and celda[0] in ('=', '+', '-', '@')), f'celda peligrosa: {celda!r}'
