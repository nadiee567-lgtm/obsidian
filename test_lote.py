"""Tests for the parallel transform executor (F7 step 102).

Run:  ../.venv/bin/python -m pytest test_lote.py -q
"""
import threading

from core.modelo import Store
from core.transforms import transform, run_batch


@transform(input='domain', outputs=('ip',), name='_test_lote_a')
def _fake_a(entity, ctx):
    ctx.emit('ip', '10.0.0.1')
    ctx.emit('ip', '10.0.0.2')


@transform(input='domain', outputs=('subdomain',), name='_test_lote_b')
def _fake_b(entity, ctx):
    ctx.emit('subdomain', 'x.' + entity.value)


def test_batch_merges_results():
    store = Store()
    res = run_batch([('domain', 'ejemplo.com', '_test_lote_a'),
                         ('domain', 'ejemplo.com', '_test_lote_b')], store)
    assert dict(res) == {'_test_lote_a': 2, '_test_lote_b': 1}
    # shared seed (dedup) + 2 ip + 1 subdomain = 4
    assert len(store) == 4
    assert {e.type for e in store.entities} == {'domain', 'ip', 'subdomain'}
    # the seed→output relations were merged too
    assert len(store.relations) == 3


def test_batch_with_lock():
    store = Store()
    run_batch([('domain', 'a.com', '_test_lote_a')], store, lock=threading.RLock())
    assert len(store.of_type('ip')) == 2


def test_batch_empty():
    assert run_batch([], Store()) == []


def test_batch_missing_transform_ok():
    store = Store()
    res = run_batch([('domain', 'a.com', 'no_existe_zzz')], store)
    assert res == [('no_existe_zzz', 0)]
    assert len(store) == 1          # only the seed


def test_batch_no_data_loss_parallel():
    """Many concurrent tasks: no output is lost in the merge."""
    store = Store()
    tasks = [('domain', f'sitio{i}.com', '_test_lote_a') for i in range(20)]
    run_batch(tasks, store, max_workers=8)
    # 20 distinct seeds + 2 shared ips (10.0.0.1/2) = 22
    assert len(store.of_type('domain')) == 20
    assert len(store.of_type('ip')) == 2
