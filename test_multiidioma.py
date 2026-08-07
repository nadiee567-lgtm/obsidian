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


# ── 171: regional social platforms ──────────────────────────────────────────
def test_plataformas_regionales():
    prod, _ = _run_one('regional_platforms', 'user', 'nadiee')
    plats = {p.properties.get('platform') for p in prod if p.type == 'url'}
    assert {'vk', 'ok', 'weibo', 'douyin', 'telegram'} == plats


# ── 172: name transliteration ───────────────────────────────────────────────
def test_transliterar_funciones():
    from core.multiidioma import cyrillic_to_latin, latin_to_cyrillic
    assert cyrillic_to_latin('Иван') == 'ivan'
    assert latin_to_cyrillic('ivan') == 'иван'


def test_transliterar_transform():
    prod, _ = _run_one('transliterate', 'person', 'Иван')
    variants = {p.value for p in prod if p.type == 'person'}
    assert 'ivan' in variants                    # latin variant


# ── 173: regional registries ────────────────────────────────────────────────
def test_registros_regionales():
    prod, _ = _run_one('regional_registries', 'org', 'ACME Corp')
    regs = {p.properties.get('registry') for p in prod if p.type == 'url'}
    assert {'china_qcc', 'rusia_rusprofile', 'opencorporates'} == regs


# ── 174: local engines ──────────────────────────────────────────────────────
def test_motores_locales():
    prod, _ = _run_one('local_engines', 'person', 'Ivan Petrov')
    motores = {p.properties.get('engine') for p in prod if p.type == 'url'}
    assert {'yandex', 'baidu', 'sogou'} == motores


# ── 175: language detection and routing ─────────────────────────────────────
def test_detectar_idioma():
    from core.multiidioma import detect_language
    assert detect_language('Привет мир') == 'ru'
    assert detect_language('你好世界') == 'zh'
    assert detect_language('hola mundo') == 'es_en'


def test_idioma_endpoint(monkeypatch):
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/language', json={'text': 'Привет'}).get_json()
    assert d['idioma'] == 'ru' and 'Yandex' in d['fuente_sugerida']


# ── 176: dorks by language/region ───────────────────────────────────────────
def test_dorks_por_idioma():
    from core.multiidioma import dorks_by_language
    ru = dorks_by_language('Ivan', 'ru')
    assert any('почта' in d for d in ru) and any('vk.com' in d for d in ru)


def test_dorks_idioma_transform():
    prod, _ = _run_one('language_dorks', 'person', 'Иван Петров')   # cyrillic -> ru
    idiomas = {p.properties.get('language') for p in prod if p.type == 'url'}
    assert idiomas == {'ru'}


# ── 177: normalization by country ───────────────────────────────────────────
def test_normalizar_telefono():
    from core.multiidioma import normalize_phone
    assert normalize_phone('55 1234 5678', 'MX') == '+525512345678'
    assert normalize_phone('(415) 555-2671', 'US') == '+14155552671'
    assert normalize_phone('') == ''


# ── 178: local time zone (chrono-location) ──────────────────────────────────
def test_zona_horaria():
    from core.multiidioma import time_zone
    assert time_zone('MX')['tz'] == 'America/Mexico_City'
    assert time_zone('RU')['tz'] == 'Europe/Moscow'
    assert time_zone('XX')['tz'] == 'UTC'          # unknown country
    assert time_zone('CN')['hora_local'] is not None
