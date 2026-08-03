"""Tests del modelo de datos tipado (F1). Roadmap pasos 13-17, 21-22.

Correr:  ../.venv/bin/python -m pytest test_modelo.py -q
"""
import pytest
from core.modelo import Entidad, Relacion, Almacen, normalizar, TIPOS, tipo_valido
from core.eventos import Bus, ENTIDAD_NUEVA, ENTIDAD_ACTUALIZADA, RELACION_NUEVA


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


# ── tags del analista (paso 23) ──────────────────────────────────────────────
def test_tags():
    e = Entidad('ip', '8.8.8.8')
    e.etiquetar('interesante', 'revisar')
    assert e.tags == {'interesante', 'revisar'}
    e.quitar_etiqueta('revisar')
    assert e.tags == {'interesante'}
    # los tags sobreviven la serialización
    assert set(e.to_dict()['tags']) == {'interesante'}
    assert Entidad.from_dict(e.to_dict()).tags == {'interesante'}

def test_tags_se_fusionan():
    a = Entidad('ip', '8.8.8.8', tags={'a'})
    b = Entidad('ip', '8.8.8.8', tags={'b'})
    a.fusionar(b)
    assert a.tags == {'a', 'b'}


# ── procedencia detallada (paso 18) ──────────────────────────────────────────
def test_procedencia():
    e = Entidad('subdominio', 'mail.example.com')
    e.anotar_procedencia('transform_subdominios', input_id='abc123')
    assert 'transform_subdominios' in e.origenes
    assert {'transform': 'transform_subdominios', 'input': 'abc123'} in e.procedencia
    # no duplica la misma procedencia
    e.anotar_procedencia('transform_subdominios', input_id='abc123')
    assert len(e.procedencia) == 1


# ── event bus (paso 19) ──────────────────────────────────────────────────────
def test_bus_publica_entidad_nueva_y_actualizada():
    bus = Bus()
    nuevas, actualizadas = [], []
    bus.suscribir(ENTIDAD_NUEVA, lambda e: nuevas.append(e))
    bus.suscribir(ENTIDAD_ACTUALIZADA, lambda e: actualizadas.append(e))
    alm = Almacen(bus=bus)
    alm.crear('dominio', 'example.com')            # nueva
    alm.crear('dominio', 'www.example.com')        # mismo id -> actualizada
    assert len(nuevas) == 1
    assert len(actualizadas) == 1

def test_bus_publica_relacion_nueva():
    bus = Bus()
    rels = []
    bus.suscribir(RELACION_NUEVA, lambda r: rels.append(r))
    alm = Almacen(bus=bus)
    d = alm.crear('dominio', 'example.com')
    i = alm.crear('ip', '93.184.216.34')
    alm.relacionar(d, i, 'resuelve_a')
    alm.relacionar(d, i, 'resuelve_a')   # dup: no re-publica
    assert len(rels) == 1

def test_bus_aisla_fallos_de_suscriptor():
    bus = Bus()
    ok = []
    bus.suscribir(ENTIDAD_NUEVA, lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    bus.suscribir(ENTIDAD_NUEVA, lambda e: ok.append(e))
    errores = bus.publicar(ENTIDAD_NUEVA, Entidad('ip', '8.8.8.8'))
    assert len(ok) == 1, "el segundo suscriptor corre aunque el primero falle"
    assert len(errores) == 1
