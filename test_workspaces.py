"""Tests del gestor de workspaces (F3 pasos 43-47).

Correr:  ../.venv/bin/python -m pytest test_workspaces.py -q
"""
import pytest
from core.workspaces import Gestor


def test_crear_y_listar(tmp_path):
    g = Gestor(str(tmp_path))
    assert g.listar() == []
    g.crear('caso1')
    g.crear('target-com')
    assert g.listar() == ['caso1', 'target-com']
    assert g.existe('caso1') and not g.existe('inexistente')


def test_no_duplicar(tmp_path):
    g = Gestor(str(tmp_path))
    g.crear('caso1')
    with pytest.raises(ValueError):
        g.crear('caso1')


def test_persistencia_aislada(tmp_path):
    """Cada workspace guarda lo suyo, sin mezclarse con otro."""
    g = Gestor(str(tmp_path))
    a = g.crear('caso_a')
    a.crear('dominio', 'example.com', origenes={'whois'})
    g.guardar('caso_a', a)

    b = g.crear('caso_b')
    b.crear('ip', '8.8.8.8')
    g.guardar('caso_b', b)

    # recargar cada uno: solo ve lo suyo
    ra = g.cargar('caso_a')
    rb = g.cargar('caso_b')
    assert ra.buscar('dominio', 'example.com') is not None
    assert ra.buscar('ip', '8.8.8.8') is None       # aislado
    assert rb.buscar('ip', '8.8.8.8') is not None
    assert rb.buscar('dominio', 'example.com') is None


def test_sobrevive_recarga(tmp_path):
    """El estado persiste (no vive solo en memoria)."""
    g1 = Gestor(str(tmp_path))
    a = g1.crear('caso1')
    a.crear('email', 'a@b.com', tags={'interesante'})
    g1.guardar('caso1', a)
    # nuevo Gestor (simula reinicio del server)
    g2 = Gestor(str(tmp_path))
    r = g2.cargar('caso1')
    e = r.buscar('email', 'a@b.com')
    assert e is not None and 'interesante' in e.tags


def test_borrar_y_renombrar(tmp_path):
    g = Gestor(str(tmp_path))
    g.crear('viejo')
    g.renombrar('viejo', 'nuevo')
    assert g.listar() == ['nuevo']
    assert g.borrar('nuevo') is True
    assert g.listar() == []


def test_nombres_maliciosos_rechazados(tmp_path):
    g = Gestor(str(tmp_path))
    for malo in ['../../etc/passwd', '..', 'a/b', 'x\\y', '']:
        with pytest.raises(ValueError):
            g.crear(malo)
    # y no se creó nada fuera del directorio
    assert g.listar() == []
