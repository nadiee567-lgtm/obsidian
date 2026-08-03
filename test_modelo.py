"""Tests del modelo de datos tipado (F1). Roadmap pasos 13-17, 21-22.

Correr:  ../.venv/bin/python -m pytest test_modelo.py -q
"""
import pytest
from core.modelo import Entidad, Relacion, Almacen, normalizar, TIPOS, tipo_valido


# ── id determinístico + normalización (pasos 14, 22) ─────────────────────────
def test_id_deterministico_mismo_dato():
    a = Entidad('dominio', 'Example.com')
    b = Entidad('dominio', 'www.example.com.')   # www + mayúsculas + punto final
    assert a.id == b.id, "el mismo dominio debe dar el mismo id"

def test_normalizacion():
    assert normalizar('dominio', 'WWW.Example.COM.') == 'example.com'
    assert normalizar('email', 'A@B.COM') == 'a@b.com'
    assert normalizar('ip', '2001:4860:4860:0:0:0:0:8888') == '2001:4860:4860::8888'
    assert normalizar('url', 'http://x.com/') == 'http://x.com'

def test_ids_distintos_por_tipo_y_valor():
    assert Entidad('dominio', 'x.com').id != Entidad('usuario', 'x.com').id
    assert Entidad('ip', '8.8.8.8').id != Entidad('ip', '1.1.1.1').id


# ── validación (paso 14) ─────────────────────────────────────────────────────
def test_tipo_invalido_falla():
    with pytest.raises(ValueError):
        Entidad('inventado', 'x')

def test_valor_vacio_falla():
    with pytest.raises(ValueError):
        Entidad('dominio', '   ')

def test_todos_los_tipos_del_catalogo_sirven():
    for tipo in TIPOS:
        assert tipo_valido(tipo)
        Entidad(tipo, 'valor-de-prueba')   # no debe lanzar


# ── fusión / dedup (paso 17) ─────────────────────────────────────────────────
def test_fusionar_une_origenes_y_props():
    a = Entidad('ip', '8.8.8.8', origenes={'shodan'}, propiedades={'pais': 'US'}, confianza=0.5)
    b = Entidad('ip', '8.8.8.8', origenes={'nmap'}, propiedades={'puerto': 53}, confianza=0.9)
    a.fusionar(b)
    assert a.origenes == {'shodan', 'nmap'}
    assert a.propiedades == {'pais': 'US', 'puerto': 53}
    assert a.confianza == 0.9

def test_fusionar_distinto_id_falla():
    with pytest.raises(ValueError):
        Entidad('ip', '8.8.8.8').fusionar(Entidad('ip', '1.1.1.1'))


# ── almacén: dedup automático (pasos 16, 17) ─────────────────────────────────
def test_almacen_deduplica():
    alm = Almacen()
    alm.crear('dominio', 'example.com', origenes={'whois'})
    alm.crear('dominio', 'WWW.example.com', origenes={'crtsh'})   # mismo dominio
    assert len(alm) == 1, "debe colapsar en una sola entidad"
    ent = alm.buscar('dominio', 'example.com')
    assert ent.origenes == {'whois', 'crtsh'}, "orígenes fusionados"

def test_almacen_de_tipo_y_buscar():
    alm = Almacen()
    alm.crear('ip', '8.8.8.8')
    alm.crear('ip', '1.1.1.1')
    alm.crear('email', 'a@b.com')
    assert len(alm.de_tipo('ip')) == 2
    assert alm.buscar('email', 'A@B.com') is not None   # respeta normalización


# ── relaciones: deterministas y sin duplicar (paso 15) ───────────────────────
def test_relaciones_dedup():
    alm = Almacen()
    d = alm.crear('dominio', 'example.com')
    i = alm.crear('ip', '93.184.216.34')
    alm.relacionar(d, i, 'resuelve_a')
    alm.relacionar(d, i, 'resuelve_a')   # misma relación otra vez
    assert len(alm.relaciones) == 1


# ── serialización round-trip (paso 21) ───────────────────────────────────────
def test_roundtrip_almacen():
    alm = Almacen()
    d = alm.crear('dominio', 'example.com', origenes={'whois'}, propiedades={'reg': 'GoDaddy'})
    i = alm.crear('ip', '93.184.216.34', origenes={'dns'})
    alm.relacionar(d, i, 'resuelve_a')

    d2 = alm.to_dict()
    alm2 = Almacen.from_dict(d2)

    assert len(alm2) == 2
    assert len(alm2.relaciones) == 1
    ent = alm2.buscar('dominio', 'example.com')
    assert ent.origenes == {'whois'}
    assert ent.propiedades == {'reg': 'GoDaddy'}
