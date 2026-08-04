"""Tests de la página de estado (F7 paso 105).

Correr:  ../.venv/bin/python -m pytest test_estado.py -q
"""
from core.estado import render_estado


def _datos():
    return {
        'generado': '2026-08-04 01:30',
        'transforms': {'total': 39, 'por_tipo': {'dominio': 12, 'ip': 7}, 'con_key': ['abuseipdb']},
        'herramientas': {'dig': True, 'nuclei': False},
        'keys': ['github', 'abuseipdb'],
        'ia': {'disponible': True, 'modelo': 'qwen2.5:3b'},
        'workspaces': 3,
        'monitor': True,
        'ntfy': False,
    }


def test_render_muestra_datos():
    html = render_estado(_datos())
    for txt in ('estado del sistema', '39', 'dominio', 'qwen2.5:3b', 'github', 'abuseipdb', 'dig'):
        assert txt in html, f'falta: {txt}'


def test_render_sin_keys():
    d = _datos(); d['keys'] = []
    html = render_estado(d)
    assert 'ninguna' in html


def test_render_escapa_xss():
    d = _datos()
    d['keys'] = ['<script>x</script>']
    html = render_estado(d)
    assert '<script>x</script>' not in html
    assert '&lt;script&gt;' in html


def test_render_ia_no_disponible():
    d = _datos(); d['ia'] = {'disponible': False, 'modelo': '?'}
    html = render_estado(d)
    assert 'estado del sistema' in html      # no revienta con ia caída
