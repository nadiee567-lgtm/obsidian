"""Tests for the typed data model (F1). Roadmap steps 13-17, 21-22.

Run:  ../.venv/bin/python -m pytest test_modelo.py -q
"""
import pytest
from core.modelo import Entity, Relation, Store, normalize, TIPOS, valid_type
from core.eventos import Bus, ENTIDAD_NUEVA, ENTIDAD_ACTUALIZADA, RELACION_NUEVA


# ── deterministic id + normalization (steps 14, 22) ─────────────────────────
def test_id_deterministico_mismo_dato():
    a = Entity('domain', 'Example.com')
    b = Entity('domain', 'www.example.com.')   # www + uppercase + trailing dot
    assert a.id == b.id, "the same domain must give the same id"

def test_normalizacion():
    assert normalize('domain', 'WWW.Example.COM.') == 'example.com'
    assert normalize('email', 'A@B.COM') == 'a@b.com'
    assert normalize('ip', '2001:4860:4860:0:0:0:0:8888') == '2001:4860:4860::8888'
    assert normalize('url', 'http://x.com/') == 'http://x.com'

def test_ids_distintos_por_tipo_y_valor():
    assert Entity('domain', 'x.com').id != Entity('user', 'x.com').id
    assert Entity('ip', '8.8.8.8').id != Entity('ip', '1.1.1.1').id


# ── validation (step 14) ─────────────────────────────────────────────────────
def test_tipo_invalido_falla():
    with pytest.raises(ValueError):
        Entity('inventado', 'x')

def test_valor_vacio_falla():
    with pytest.raises(ValueError):
        Entity('domain', '   ')

def test_todos_los_tipos_del_catalogo_sirven():
    for type in TIPOS:
        assert valid_type(type)
        Entity(type, 'value-de-prueba')   # must not raise


# ── merge / dedup (step 17) ──────────────────────────────────────────────────
def test_fusionar_une_origenes_y_props():
    a = Entity('ip', '8.8.8.8', sources={'shodan'}, properties={'country': 'US'}, confidence=0.5)
    b = Entity('ip', '8.8.8.8', sources={'nmap'}, properties={'port': 53}, confidence=0.9)
    a.merge(b)
    assert a.sources == {'shodan', 'nmap'}
    assert a.properties == {'country': 'US', 'port': 53}
    assert a.confidence == 0.9

def test_fusionar_distinto_id_falla():
    with pytest.raises(ValueError):
        Entity('ip', '8.8.8.8').merge(Entity('ip', '1.1.1.1'))


# ── store: automatic dedup (steps 16, 17) ───────────────────────────────────
def test_almacen_deduplica():
    alm = Store()
    alm.create('domain', 'example.com', sources={'whois'})
    alm.create('domain', 'WWW.example.com', sources={'crtsh'})   # same domain
    assert len(alm) == 1, "must collapse into a single entity"
    ent = alm.find('domain', 'example.com')
    assert ent.sources == {'whois', 'crtsh'}, "merged sources"

def test_almacen_de_tipo_y_buscar():
    alm = Store()
    alm.create('ip', '8.8.8.8')
    alm.create('ip', '1.1.1.1')
    alm.create('email', 'a@b.com')
    assert len(alm.of_type('ip')) == 2
    assert alm.find('email', 'A@B.com') is not None   # respects normalization


# ── relations: deterministic and non-duplicated (step 15) ───────────────────
def test_relaciones_dedup():
    alm = Store()
    d = alm.create('domain', 'example.com')
    i = alm.create('ip', '93.184.216.34')
    alm.relate(d, i, 'resuelve_a')
    alm.relate(d, i, 'resuelve_a')   # same relation again
    assert len(alm.relations) == 1


# ── round-trip serialization (step 21) ──────────────────────────────────────
def test_roundtrip_almacen():
    alm = Store()
    d = alm.create('domain', 'example.com', sources={'whois'}, properties={'reg': 'GoDaddy'})
    i = alm.create('ip', '93.184.216.34', sources={'dns'})
    alm.relate(d, i, 'resuelve_a')

    d2 = alm.to_dict()
    alm2 = Store.from_dict(d2)

    assert len(alm2) == 2
    assert len(alm2.relations) == 1
    ent = alm2.find('domain', 'example.com')
    assert ent.sources == {'whois'}
    assert ent.properties == {'reg': 'GoDaddy'}


# ── analyst tags (step 23) ──────────────────────────────────────────────────
def test_tags():
    e = Entity('ip', '8.8.8.8')
    e.tag('interesting', 'revisar')
    assert e.tags == {'interesting', 'revisar'}
    e.untag('revisar')
    assert e.tags == {'interesting'}
    # tags survive serialization
    assert set(e.to_dict()['tags']) == {'interesting'}
    assert Entity.from_dict(e.to_dict()).tags == {'interesting'}

def test_tags_se_fusionan():
    a = Entity('ip', '8.8.8.8', tags={'a'})
    b = Entity('ip', '8.8.8.8', tags={'b'})
    a.merge(b)
    assert a.tags == {'a', 'b'}


# ── detailed provenance (step 18) ───────────────────────────────────────────
def test_valor_bien_formado():
    assert Entity('ip', '8.8.8.8').well_formed() is True
    assert Entity('domain', 'example.com').well_formed() is True
    assert Entity('email', 'a@b.com').well_formed() is True
    # a value malformed for its type is detected (even if it can be created)
    assert Entity('ip', '999.999.999.999').well_formed() is False
    # types without a strict validator: always True (person with spaces, etc.)
    assert Entity('person', 'Juan Perez Garcia').well_formed() is True


def test_procedencia():
    e = Entity('subdomain', 'mail.example.com')
    e.note_provenance('transform_subdominios', input_id='abc123')
    assert 'transform_subdominios' in e.sources
    assert {'transform': 'transform_subdominios', 'input': 'abc123'} in e.provenance
    # does not duplicate the same provenance
    e.note_provenance('transform_subdominios', input_id='abc123')
    assert len(e.provenance) == 1


# ── event bus (step 19) ─────────────────────────────────────────────────────
def test_bus_publica_entidad_nueva_y_actualizada():
    bus = Bus()
    nuevas, actualizadas = [], []
    bus.suscribir(ENTIDAD_NUEVA, lambda e: nuevas.append(e))
    bus.suscribir(ENTIDAD_ACTUALIZADA, lambda e: actualizadas.append(e))
    alm = Store(bus=bus)
    alm.create('domain', 'example.com')            # new
    alm.create('domain', 'www.example.com')        # same id -> updated
    assert len(nuevas) == 1
    assert len(actualizadas) == 1

def test_bus_publica_relacion_nueva():
    bus = Bus()
    rels = []
    bus.suscribir(RELACION_NUEVA, lambda r: rels.append(r))
    alm = Store(bus=bus)
    d = alm.create('domain', 'example.com')
    i = alm.create('ip', '93.184.216.34')
    alm.relate(d, i, 'resuelve_a')
    alm.relate(d, i, 'resuelve_a')   # dup: does not re-publish
    assert len(rels) == 1

def test_bus_aisla_fallos_de_suscriptor():
    bus = Bus()
    ok = []
    bus.suscribir(ENTIDAD_NUEVA, lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    bus.suscribir(ENTIDAD_NUEVA, lambda e: ok.append(e))
    errores = bus.publish(ENTIDAD_NUEVA, Entity('ip', '8.8.8.8'))
    assert len(ok) == 1, "the second subscriber runs even if the first fails"
    assert len(errores) == 1
