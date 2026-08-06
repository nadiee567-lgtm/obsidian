"""Tests for the HTML report generator (F7 step 93).

Run:  ../.venv/bin/python -m pytest test_reporte.py -q
"""
from core.modelo import Store
from core.correlacion import Finding
from core.reporte import generar_reporte


def _almacen_demo():
    alm = Store()
    d = alm.crear('dominio', 'objetivo.com', propiedades={'org': 'ACME'})
    ip = alm.crear('ip', '93.184.216.34', propiedades={'pais': 'US'})
    ip.etiquetar('listado-amenaza')
    alm.relacionar(d.id, ip.id, 'resuelve')
    return alm, d, ip


def test_reporte_tiene_secciones():
    alm, d, ip = _almacen_demo()
    h = [Finding('ip-listada', 'alto', 'IP en feed de amenazas', [ip.id])]
    html = generar_reporte(alm, hallazgos=h, score=20,
                           meta={'workspace': 'caso-1', 'objetivo': 'objetivo.com'})
    for txt in ('Risk summary', 'Findings', 'Entity inventory',
                'objetivo.com', '93.184.216.34', 'ip-listada', '20/100', 'caso-1'):
        assert txt in html, f'missing from the report: {txt}'


def test_reporte_sin_hallazgos():
    alm, _, _ = _almacen_demo()
    html = generar_reporte(alm, hallazgos=[], score=0)
    assert 'No risks detected' in html
    assert '0/100' in html


def test_reporte_almacen_vacio():
    html = generar_reporte(Store(), hallazgos=[], score=0)
    assert 'No entities' in html


def test_reporte_escapa_xss():
    """Raw target data with a payload → must come out escaped, never executable."""
    alm = Store()
    alm.crear('dominio', 'malo.com',
              propiedades={'nota': '<script>alert(1)</script>'})
    h = [Finding('r', 'critico', 'injection <img src=x onerror=alert(1)>', [])]
    html = generar_reporte(alm, hallazgos=h, score=40)
    assert '<script>alert(1)</script>' not in html          # raw NO
    assert '&lt;script&gt;' in html                          # escaped YES
    assert '<img src=x onerror' not in html                  # the finding's neither
    assert '&lt;img src=x' in html


def test_reporte_grafo_embebido():
    alm, d, ip = _almacen_demo()
    # fake vis_js: we only check it gets embedded and builds the datasets
    html = generar_reporte(alm, hallazgos=[], score=0, vis_js='/*VISLIB*/')
    assert 'Relationship graph' in html
    assert '/*VISLIB*/' in html
    assert 'vis.Network' in html
    assert d.id in html and ip.id in html                    # nodes by id
