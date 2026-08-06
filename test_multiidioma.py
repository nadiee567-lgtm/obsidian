"""Tests for F15 -- multilingual and regional sources.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_multiidioma.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


def _run_one(name, type, value):
    alm = Store()
    e = alm.create(type, value)
    return run_by_name(name, e, alm), e


# ── 171: regional social platforms ──────────────────────────────────────────
def test_plataformas_regionales():
    prod, _ = _run_one('plataformas_regionales', 'user', 'nadiee')
    plats = {p.properties.get('platform') for p in prod if p.type == 'url'}
    assert {'vk', 'ok', 'weibo', 'douyin', 'telegram'} == plats


# ── 172: name transliteration ───────────────────────────────────────────────
def test_transliterar_funciones():
    from core.multiidioma import cirilico_a_latino, latino_a_cirilico
    assert cirilico_a_latino('Иван') == 'ivan'
    assert latino_a_cirilico('ivan') == 'иван'


def test_transliterar_transform():
    prod, _ = _run_one('transliterar', 'person', 'Иван')
    variantes = {p.value for p in prod if p.type == 'person'}
    assert 'ivan' in variantes                    # latin variant


# ── 173: regional registries ────────────────────────────────────────────────
def test_registros_regionales():
    prod, _ = _run_one('registros_regionales', 'org', 'ACME Corp')
    regs = {p.properties.get('registry') for p in prod if p.type == 'url'}
    assert {'china_qcc', 'rusia_rusprofile', 'opencorporates'} == regs


# ── 174: local engines ──────────────────────────────────────────────────────
def test_motores_locales():
    prod, _ = _run_one('motores_locales', 'person', 'Ivan Petrov')
    motores = {p.properties.get('engine') for p in prod if p.type == 'url'}
    assert {'yandex', 'baidu', 'sogou'} == motores


# ── 175: language detection and routing ─────────────────────────────────────
def test_detectar_idioma():
    from core.multiidioma import detectar_idioma
    assert detectar_idioma('Привет мир') == 'ru'
    assert detectar_idioma('你好世界') == 'zh'
    assert detectar_idioma('hola mundo') == 'es_en'


def test_idioma_endpoint(monkeypatch):
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/language', json={'texto': 'Привет'}).get_json()
    assert d['idioma'] == 'ru' and 'Yandex' in d['fuente_sugerida']


# ── 176: dorks by language/region ───────────────────────────────────────────
def test_dorks_por_idioma():
    from core.multiidioma import dorks_por_idioma
    ru = dorks_por_idioma('Ivan', 'ru')
    assert any('почта' in d for d in ru) and any('vk.com' in d for d in ru)


def test_dorks_idioma_transform():
    prod, _ = _run_one('dorks_idioma', 'person', 'Иван Петров')   # cyrillic -> ru
    idiomas = {p.properties.get('language') for p in prod if p.type == 'url'}
    assert idiomas == {'ru'}


# ── 177: normalization by country ───────────────────────────────────────────
def test_normalizar_telefono():
    from core.multiidioma import normalizar_telefono
    assert normalizar_telefono('55 1234 5678', 'MX') == '+525512345678'
    assert normalizar_telefono('(415) 555-2671', 'US') == '+14155552671'
    assert normalizar_telefono('') == ''


# ── 178: local time zone (chrono-location) ──────────────────────────────────
def test_zona_horaria():
    from core.multiidioma import zona_horaria
    assert zona_horaria('MX')['tz'] == 'America/Mexico_City'
    assert zona_horaria('RU')['tz'] == 'Europe/Moscow'
    assert zona_horaria('XX')['tz'] == 'UTC'          # unknown country
    assert zona_horaria('CN')['hora_local'] is not None
