"""Tests de F14 — capa de IA.

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_ia.py -q
"""


# ── 161: extracción de entidades de texto ────────────────────────────────────
def test_extraer_entidades():
    from core.extraccion import extraer_entidades
    txt = ('Contacto admin@acme.com vía https://acme.com desde 8.8.8.8. '
           'Adjunto reporte.pdf y foto.jpg. IP mala 999.1.1.1.')
    vals = {v for _, v in extraer_entidades(txt)}
    assert 'admin@acme.com' in vals
    assert '8.8.8.8' in vals
    assert 'https://acme.com' in vals
    assert 'acme.com' in vals                    # dominio extraído
    assert 'reporte.pdf' not in vals             # anti-FP: archivo, no dominio
    assert 'foto.jpg' not in vals
    assert '999.1.1.1' not in vals               # octeto inválido descartado


def test_extraer_wallets_de_texto():
    from core.extraccion import extraer_entidades
    txt = 'paga a 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
    tipos = {t for t, _ in extraer_entidades(txt)}
    assert 'wallet' in tipos
