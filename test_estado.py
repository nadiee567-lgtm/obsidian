"""Tests for the status page (F7 step 105).

Run:  ../.venv/bin/python -m pytest test_estado.py -q
"""
from core.estado import render_estado


def _datos():
    return {
        'generado': '2026-08-04 01:30',
        'transforms': {'total': 39, 'por_tipo': {'domain': 12, 'ip': 7}, 'con_key': ['abuseipdb']},
        'herramientas': {'dig': True, 'nuclei': False},
        'keys': ['github', 'abuseipdb'],
        'ia': {'disponible': True, 'modelo': 'qwen2.5:3b'},
        'workspaces': 3,
        'monitor': True,
        'ntfy': False,
    }


def test_render_muestra_datos():
    html = render_estado(_datos())
    for txt in ('system status', '39', 'domain', 'qwen2.5:3b', 'github', 'abuseipdb', 'dig'):
        assert txt in html, f'missing: {txt}'


def test_render_sin_keys():
    d = _datos(); d['keys'] = []
    html = render_estado(d)
    assert 'none' in html


def test_render_escapa_xss():
    d = _datos()
    d['keys'] = ['<script>x</script>']
    html = render_estado(d)
    assert '<script>x</script>' not in html
    assert '&lt;script&gt;' in html


def test_render_ia_no_disponible():
    d = _datos(); d['ia'] = {'disponible': False, 'modelo': '?'}
    html = render_estado(d)
    assert 'system status' in html      # does not blow up with AI down
