"""Tests for F15 -- multilingual and regional sources.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_multiidioma.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


def _run_one(name, type, value):
    store = Store()
    e = store.create(type, value)
    return run_by_name(name, e, store), e


def test_platforms_regional():
    prod, _ = _run_one('regional_platforms', 'user', 'nadiee')
    plats = {p.properties.get('platform') for p in prod if p.type == 'url'}
    assert {'vk', 'ok', 'weibo', 'douyin', 'telegram'} == plats


def test_transliterate_funciones():
    from core.multiidioma import cyrillic_to_latin, latin_to_cyrillic
    assert cyrillic_to_latin('Иван') == 'ivan'
    assert latin_to_cyrillic('ivan') == 'иван'


def test_transliterate_transform():
    prod, _ = _run_one('transliterate', 'person', 'Иван')
    variants = {p.value for p in prod if p.type == 'person'}
    assert 'ivan' in variants


def test_records_regional():
    prod, _ = _run_one('regional_registries', 'org', 'ACME Corp')
    regs = {p.properties.get('registry') for p in prod if p.type == 'url'}
    assert {'china_qcc', 'rusia_rusprofile', 'opencorporates'} == regs


def test_engines_local():
    prod, _ = _run_one('local_engines', 'person', 'Ivan Petrov')
    motores = {p.properties.get('engine') for p in prod if p.type == 'url'}
    assert {'yandex', 'baidu', 'sogou'} == motores


def test_detect_language():
    from core.multiidioma import detect_language
    assert detect_language('Привет мир') == 'ru'
    assert detect_language('你好世界') == 'zh'
    assert detect_language('hola mundo') == 'es_en'


def test_language_endpoint(monkeypatch):
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/language', json={'text': 'Привет'}).get_json()
    assert d['idioma'] == 'ru' and 'Yandex' in d['fuente_sugerida']


def test_dorks_per_language():
    from core.multiidioma import dorks_by_language
    ru = dorks_by_language('Ivan', 'ru')
    assert any('почта' in d for d in ru) and any('vk.com' in d for d in ru)


def test_dorks_language_transform():
    prod, e = _run_one('language_dorks', 'person', 'Иван Петров')
    assert e.properties.get('language_searches')
    assert not [p for p in prod if p.type == 'url']


def test_normalize_phone():
    from core.multiidioma import normalize_phone
    assert normalize_phone('55 1234 5678', 'MX') == '+525512345678'
    assert normalize_phone('(415) 555-2671', 'US') == '+14155552671'
    assert normalize_phone('') == ''


def test_time_zone():
    from core.multiidioma import time_zone
    assert time_zone('MX')['tz'] == 'America/Mexico_City'
    assert time_zone('RU')['tz'] == 'Europe/Moscow'
    assert time_zone('XX')['tz'] == 'UTC'
    assert time_zone('CN')['hora_local'] is not None
