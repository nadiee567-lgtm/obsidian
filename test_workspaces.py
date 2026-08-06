"""Tests for the workspace manager (F3 steps 43-47).

Run:  ../.venv/bin/python -m pytest test_workspaces.py -q
"""
import pytest
from core.workspaces import Manager


def test_crear_y_listar(tmp_path):
    g = Manager(str(tmp_path))
    assert g.listar() == []
    g.crear('caso1')
    g.crear('target-com')
    assert g.listar() == ['caso1', 'target-com']
    assert g.existe('caso1') and not g.existe('inexistente')


def test_no_duplicar(tmp_path):
    g = Manager(str(tmp_path))
    g.crear('caso1')
    with pytest.raises(ValueError):
        g.crear('caso1')


def test_persistencia_aislada(tmp_path):
    """Each workspace stores its own, without mixing with another."""
    g = Manager(str(tmp_path))
    a = g.crear('caso_a')
    a.crear('dominio', 'example.com', origenes={'whois'})
    g.guardar('caso_a', a)

    b = g.crear('caso_b')
    b.crear('ip', '8.8.8.8')
    g.guardar('caso_b', b)

    # reload each one: sees only its own
    ra = g.cargar('caso_a')
    rb = g.cargar('caso_b')
    assert ra.buscar('dominio', 'example.com') is not None
    assert ra.buscar('ip', '8.8.8.8') is None       # isolated
    assert rb.buscar('ip', '8.8.8.8') is not None
    assert rb.buscar('dominio', 'example.com') is None


def test_sobrevive_recarga(tmp_path):
    """State persists (does not live only in memory)."""
    g1 = Manager(str(tmp_path))
    a = g1.crear('caso1')
    a.crear('email', 'a@b.com', tags={'interesante'})
    g1.guardar('caso1', a)
    # new Manager (simulates a server restart)
    g2 = Manager(str(tmp_path))
    r = g2.cargar('caso1')
    e = r.buscar('email', 'a@b.com')
    assert e is not None and 'interesante' in e.tags


def test_borrar_y_renombrar(tmp_path):
    g = Manager(str(tmp_path))
    g.crear('viejo')
    g.renombrar('viejo', 'nuevo')
    assert g.listar() == ['nuevo']
    assert g.borrar('nuevo') is True
    assert g.listar() == []


def test_nombres_maliciosos_rechazados(tmp_path):
    g = Manager(str(tmp_path))
    for malo in ['../../etc/passwd', '..', 'a/b', 'x\\y', '']:
        with pytest.raises(ValueError):
            g.crear(malo)
    # and nothing was created outside the directory
    assert g.listar() == []


def test_historial(tmp_path):
    g = Manager(str(tmp_path))
    g.crear('caso')
    g.registrar('caso', 'dns_a', 'example.com', 3)
    g.registrar('caso', 'rdap', 'example.com', 5)
    h = g.historial('caso')
    assert len(h) == 2
    assert h[0]['transform'] == 'rdap' and h[0]['salidas'] == 5   # most recent first


def test_snapshots(tmp_path):
    g = Manager(str(tmp_path))
    a = g.crear('caso')
    a.crear('ip', '8.8.8.8')
    g.guardar('caso', a)
    sid = g.snapshot('caso')
    assert sid in g.listar_snapshots('caso')

    # change the case, then restore the snapshot -> the old state returns
    a2 = g.cargar('caso')
    a2.crear('ip', '1.1.1.1')
    g.guardar('caso', a2)
    assert len(g.cargar('caso')) == 2
    g.restaurar('caso', sid)
    assert len(g.cargar('caso')) == 1   # reverted to the snapshot (only 8.8.8.8)
