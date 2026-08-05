"""Tests de F15 — multi-idioma y fuentes regionales.

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_multiidioma.py -q
"""
import obsidian_web as ob
from core.modelo import Almacen
from core.transforms import ejecutar_por_nombre


def _correr(nombre, tipo, valor):
    alm = Almacen()
    e = alm.crear(tipo, valor)
    return ejecutar_por_nombre(nombre, e, alm), e


# ── 171: plataformas sociales regionales ─────────────────────────────────────
def test_plataformas_regionales():
    prod, _ = _correr('plataformas_regionales', 'usuario', 'nadiee')
    plats = {p.propiedades.get('plataforma') for p in prod if p.tipo == 'url'}
    assert {'vk', 'ok', 'weibo', 'douyin', 'telegram'} == plats


# ── 172: transliteración de nombres ──────────────────────────────────────────
def test_transliterar_funciones():
    from core.multiidioma import cirilico_a_latino, latino_a_cirilico
    assert cirilico_a_latino('Иван') == 'ivan'
    assert latino_a_cirilico('ivan') == 'иван'


def test_transliterar_transform():
    prod, _ = _correr('transliterar', 'persona', 'Иван')
    variantes = {p.valor for p in prod if p.tipo == 'persona'}
    assert 'ivan' in variantes                    # variante latina


# ── 173: registros regionales ────────────────────────────────────────────────
def test_registros_regionales():
    prod, _ = _correr('registros_regionales', 'org', 'ACME Corp')
    regs = {p.propiedades.get('registro') for p in prod if p.tipo == 'url'}
    assert {'china_qcc', 'rusia_rusprofile', 'opencorporates'} == regs


# ── 174: motores locales ─────────────────────────────────────────────────────
def test_motores_locales():
    prod, _ = _correr('motores_locales', 'persona', 'Ivan Petrov')
    motores = {p.propiedades.get('motor') for p in prod if p.tipo == 'url'}
    assert {'yandex', 'baidu', 'sogou'} == motores


# ── 175: detección de idioma y ruteo ─────────────────────────────────────────
def test_detectar_idioma():
    from core.multiidioma import detectar_idioma
    assert detectar_idioma('Привет мир') == 'ru'
    assert detectar_idioma('你好世界') == 'zh'
    assert detectar_idioma('hola mundo') == 'es_en'


def test_idioma_endpoint(monkeypatch):
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/idioma', json={'texto': 'Привет'}).get_json()
    assert d['idioma'] == 'ru' and 'Yandex' in d['fuente_sugerida']


# ── 176: dorks por idioma/región ─────────────────────────────────────────────
def test_dorks_por_idioma():
    from core.multiidioma import dorks_por_idioma
    ru = dorks_por_idioma('Ivan', 'ru')
    assert any('почта' in d for d in ru) and any('vk.com' in d for d in ru)


def test_dorks_idioma_transform():
    prod, _ = _correr('dorks_idioma', 'persona', 'Иван Петров')   # cirílico -> ru
    idiomas = {p.propiedades.get('idioma') for p in prod if p.tipo == 'url'}
    assert idiomas == {'ru'}


# ── 177: normalización por país ──────────────────────────────────────────────
def test_normalizar_telefono():
    from core.multiidioma import normalizar_telefono
    assert normalizar_telefono('55 1234 5678', 'MX') == '+525512345678'
    assert normalizar_telefono('(415) 555-2671', 'US') == '+14155552671'
    assert normalizar_telefono('') == ''


# ── 178: zona horaria local (cronolocalización) ──────────────────────────────
def test_zona_horaria():
    from core.multiidioma import zona_horaria
    assert zona_horaria('MX')['tz'] == 'America/Mexico_City'
    assert zona_horaria('RU')['tz'] == 'Europe/Moscow'
    assert zona_horaria('XX')['tz'] == 'UTC'          # país desconocido
    assert zona_horaria('CN')['hora_local'] is not None
