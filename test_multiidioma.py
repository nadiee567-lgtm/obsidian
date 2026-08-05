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
