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
