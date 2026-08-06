"""Tests for the parallel transform executor (F7 step 102).

Run:  ../.venv/bin/python -m pytest test_lote.py -q
"""
import threading

from core.modelo import Store
from core.transforms import transform, run_batch


@transform(input='domain', outputs=('ip',), name='_test_lote_a')
def _fake_a(entidad, ctx):
    ctx.emit('ip', '10.0.0.1')
    ctx.emit('ip', '10.0.0.2')


@transform(input='domain', outputs=('subdomain',), name='_test_lote_b')
def _fake_b(entidad, ctx):
    ctx.emit('subdomain', 'x.' + entidad.value)


def test_lote_fusiona_resultados():
    alm = Store()
    res = run_batch([('domain', 'ejemplo.com', '_test_lote_a'),
                         ('domain', 'ejemplo.com', '_test_lote_b')], alm)
    assert dict(res) == {'_test_lote_a': 2, '_test_lote_b': 1}
    # shared seed (dedup) + 2 ip + 1 subdomain = 4
    assert len(alm) == 4
    assert {e.type for e in alm.entities} == {'domain', 'ip', 'subdomain'}
    # the seed→output relations were merged too
    assert len(alm.relations) == 3


def test_lote_con_lock():
    alm = Store()
    run_batch([('domain', 'a.com', '_test_lote_a')], alm, lock=threading.RLock())
    assert len(alm.of_type('ip')) == 2


def test_lote_vacio():
    assert run_batch([], Store()) == []


def test_lote_transform_inexistente_no_rompe():
    alm = Store()
    res = run_batch([('domain', 'a.com', 'no_existe_zzz')], alm)
    assert res == [('no_existe_zzz', 0)]
    assert len(alm) == 1          # only the seed


def test_lote_no_pierde_datos_en_paralelo():
    """Many concurrent tasks: no output is lost in the merge."""
    alm = Store()
    tareas = [('domain', f'sitio{i}.com', '_test_lote_a') for i in range(20)]
    run_batch(tareas, alm, max_workers=8)
    # 20 distinct seeds + 2 shared ips (10.0.0.1/2) = 22
    assert len(alm.of_type('domain')) == 20
    assert len(alm.of_type('ip')) == 2
