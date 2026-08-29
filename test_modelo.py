"""Tests for the typed data model (F1). Roadmap steps 13-17, 21-22.

Run:  ../.venv/bin/python -m pytest test_modelo.py -q
"""
import pytest
from core.modelo import Entity, Relation, Store, normalize, TYPES, valid_type
from core.eventos import Bus, ENTITY_NEW, ENTITY_UPDATED, RELATION_NEW


def test_id_deterministic_same_data():
    a = Entity('domain', 'Example.com')
    b = Entity('domain', 'www.example.com.')
    assert a.id == b.id, "the same domain must give the same id"

def test_normalization():
    assert normalize('domain', 'WWW.Example.COM.') == 'example.com'
    assert normalize('email', 'A@B.COM') == 'a@b.com'
    assert normalize('ip', '2001:4860:4860:0:0:0:0:8888') == '2001:4860:4860::8888'
    assert normalize('url', 'http://x.com/') == 'http://x.com'

def test_ids_distinct_per_type_value():
    assert Entity('domain', 'x.com').id != Entity('user', 'x.com').id
    assert Entity('ip', '8.8.8.8').id != Entity('ip', '1.1.1.1').id


def test_type_invalid_fails():
    with pytest.raises(ValueError):
        Entity('inventado', 'x')

def test_value_empty_fails():
    with pytest.raises(ValueError):
        Entity('domain', '   ')

def test_all_types_catalog_work():
    for type in TYPES:
        assert valid_type(type)
        Entity(type, 'value-de-prueba')


def test_merge_merges_sources_props():
    a = Entity('ip', '8.8.8.8', sources={'shodan'}, properties={'country': 'US'}, confidence=0.5)
    b = Entity('ip', '8.8.8.8', sources={'nmap'}, properties={'port': 53}, confidence=0.9)
    a.merge(b)
    assert a.sources == {'shodan', 'nmap'}
    assert a.properties == {'country': 'US', 'port': 53}
    assert a.confidence == 0.9

def test_merge_different_id_fails():
    with pytest.raises(ValueError):
        Entity('ip', '8.8.8.8').merge(Entity('ip', '1.1.1.1'))


def test_store_dedup():
    store = Store()
    store.create('domain', 'example.com', sources={'whois'})
    store.create('domain', 'WWW.example.com', sources={'crtsh'})
    assert len(store) == 1, "must collapse into a single entity"
    ent = store.find('domain', 'example.com')
    assert ent.sources == {'whois', 'crtsh'}, "merged sources"

def test_store_of_type_and_find():
    store = Store()
    store.create('ip', '8.8.8.8')
    store.create('ip', '1.1.1.1')
    store.create('email', 'a@b.com')
    assert len(store.of_type('ip')) == 2
    assert store.find('email', 'A@B.com') is not None


def test_relations_dedup():
    store = Store()
    d = store.create('domain', 'example.com')
    i = store.create('ip', '93.184.216.34')
    store.relate(d, i, 'resuelve_a')
    store.relate(d, i, 'resuelve_a')
    assert len(store.relations) == 1


def test_store_roundtrip():
    store = Store()
    d = store.create('domain', 'example.com', sources={'whois'}, properties={'reg': 'GoDaddy'})
    i = store.create('ip', '93.184.216.34', sources={'dns'})
    store.relate(d, i, 'resuelve_a')

    d2 = store.to_dict()
    alm2 = Store.from_dict(d2)

    assert len(alm2) == 2
    assert len(alm2.relations) == 1
    ent = alm2.find('domain', 'example.com')
    assert ent.sources == {'whois'}
    assert ent.properties == {'reg': 'GoDaddy'}


def test_tags():
    e = Entity('ip', '8.8.8.8')
    e.tag('interesting', 'revisar')
    assert e.tags == {'interesting', 'revisar'}
    e.untag('revisar')
    assert e.tags == {'interesting'}
    assert set(e.to_dict()['tags']) == {'interesting'}
    assert Entity.from_dict(e.to_dict()).tags == {'interesting'}

def test_tags_merge():
    a = Entity('ip', '8.8.8.8', tags={'a'})
    b = Entity('ip', '8.8.8.8', tags={'b'})
    a.merge(b)
    assert a.tags == {'a', 'b'}


def test_value_well_formed():
    assert Entity('ip', '8.8.8.8').well_formed() is True
    assert Entity('domain', 'example.com').well_formed() is True
    assert Entity('email', 'a@b.com').well_formed() is True
    assert Entity('ip', '999.999.999.999').well_formed() is False
    assert Entity('person', 'Juan Perez Garcia').well_formed() is True


def test_provenance():
    e = Entity('subdomain', 'mail.example.com')
    e.note_provenance('transform_subdominios', input_id='abc123')
    assert 'transform_subdominios' in e.sources
    assert {'transform': 'transform_subdominios', 'input': 'abc123'} in e.provenance
    e.note_provenance('transform_subdominios', input_id='abc123')
    assert len(e.provenance) == 1


def test_bus_publica_entidad_nueva_actualizada():
    bus = Bus()
    nuevas, actualizadas = [], []
    bus.subscribe(ENTITY_NEW, lambda e: nuevas.append(e))
    bus.subscribe(ENTITY_UPDATED, lambda e: actualizadas.append(e))
    store = Store(bus=bus)
    store.create('domain', 'example.com')
    store.create('domain', 'www.example.com')
    assert len(nuevas) == 1
    assert len(actualizadas) == 1

def test_bus_publishes_new_relation():
    bus = Bus()
    rels = []
    bus.subscribe(RELATION_NEW, lambda r: rels.append(r))
    store = Store(bus=bus)
    d = store.create('domain', 'example.com')
    i = store.create('ip', '93.184.216.34')
    store.relate(d, i, 'resuelve_a')
    store.relate(d, i, 'resuelve_a')
    assert len(rels) == 1

def test_bus_aisla_fallos_suscriptor():
    bus = Bus()
    ok = []
    bus.subscribe(ENTITY_NEW, lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    bus.subscribe(ENTITY_NEW, lambda e: ok.append(e))
    errores = bus.publish(ENTITY_NEW, Entity('ip', '8.8.8.8'))
    assert len(ok) == 1, "the second subscriber runs even if the first fails"
    assert len(errores) == 1
