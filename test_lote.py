"""Tests del ejecutor de transforms en paralelo (F7 paso 102).

Correr:  ../.venv/bin/python -m pytest test_lote.py -q
"""
import threading

from core.modelo import Almacen
from core.transforms import transform, ejecutar_lote


@transform(entrada='dominio', salidas=('ip',), nombre='_test_lote_a')
def _fake_a(entidad, ctx):
    ctx.emitir('ip', '10.0.0.1')
    ctx.emitir('ip', '10.0.0.2')


@transform(entrada='dominio', salidas=('subdominio',), nombre='_test_lote_b')
def _fake_b(entidad, ctx):
    ctx.emitir('subdominio', 'x.' + entidad.valor)


def test_lote_fusiona_resultados():
    alm = Almacen()
    res = ejecutar_lote([('dominio', 'ejemplo.com', '_test_lote_a'),
                         ('dominio', 'ejemplo.com', '_test_lote_b')], alm)
    assert dict(res) == {'_test_lote_a': 2, '_test_lote_b': 1}
    # semilla compartida (dedup) + 2 ip + 1 subdominio = 4
    assert len(alm) == 4
    assert {e.tipo for e in alm.entidades} == {'dominio', 'ip', 'subdominio'}
    # las relaciones semilla→salida también se fusionaron
    assert len(alm.relaciones) == 3


def test_lote_con_lock():
    alm = Almacen()
    ejecutar_lote([('dominio', 'a.com', '_test_lote_a')], alm, lock=threading.RLock())
    assert len(alm.de_tipo('ip')) == 2


def test_lote_vacio():
    assert ejecutar_lote([], Almacen()) == []


def test_lote_transform_inexistente_no_rompe():
    alm = Almacen()
    res = ejecutar_lote([('dominio', 'a.com', 'no_existe_zzz')], alm)
    assert res == [('no_existe_zzz', 0)]
    assert len(alm) == 1          # solo la semilla


def test_lote_no_pierde_datos_en_paralelo():
    """Muchas tareas concurrentes: ninguna salida se pierde en la fusión."""
    alm = Almacen()
    tareas = [('dominio', f'sitio{i}.com', '_test_lote_a') for i in range(20)]
    ejecutar_lote(tareas, alm, max_workers=8)
    # 20 semillas distintas + 2 ips compartidas (10.0.0.1/2) = 22
    assert len(alm.de_tipo('dominio')) == 20
    assert len(alm.de_tipo('ip')) == 2
