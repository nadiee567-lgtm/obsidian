"""Tests del generador de reportes HTML (F7 paso 93).

Correr:  ../.venv/bin/python -m pytest test_reporte.py -q
"""
from core.modelo import Almacen
from core.correlacion import Hallazgo
from core.reporte import generar_reporte


def _almacen_demo():
    alm = Almacen()
    d = alm.crear('dominio', 'objetivo.com', propiedades={'org': 'ACME'})
    ip = alm.crear('ip', '93.184.216.34', propiedades={'pais': 'US'})
    ip.etiquetar('listado-amenaza')
    alm.relacionar(d.id, ip.id, 'resuelve')
    return alm, d, ip


def test_reporte_tiene_secciones():
    alm, d, ip = _almacen_demo()
    h = [Hallazgo('ip-listada', 'alto', 'IP en feed de amenazas', [ip.id])]
    html = generar_reporte(alm, hallazgos=h, score=20,
                           meta={'workspace': 'caso-1', 'objetivo': 'objetivo.com'})
    for txt in ('Risk summary', 'Findings', 'Entity inventory',
                'objetivo.com', '93.184.216.34', 'ip-listada', '20/100', 'caso-1'):
        assert txt in html, f'falta en el reporte: {txt}'


def test_reporte_sin_hallazgos():
    alm, _, _ = _almacen_demo()
    html = generar_reporte(alm, hallazgos=[], score=0)
    assert 'No risks detected' in html
    assert '0/100' in html


def test_reporte_almacen_vacio():
    html = generar_reporte(Almacen(), hallazgos=[], score=0)
    assert 'No entities' in html


def test_reporte_escapa_xss():
    """Dato crudo del objetivo con payload → debe salir escapado, nunca ejecutable."""
    alm = Almacen()
    alm.crear('dominio', 'malo.com',
              propiedades={'nota': '<script>alert(1)</script>'})
    h = [Hallazgo('r', 'critico', 'inyección <img src=x onerror=alert(1)>', [])]
    html = generar_reporte(alm, hallazgos=h, score=40)
    assert '<script>alert(1)</script>' not in html          # crudo NO
    assert '&lt;script&gt;' in html                          # escapado SÍ
    assert '<img src=x onerror' not in html                  # el del hallazgo tampoco
    assert '&lt;img src=x' in html


def test_reporte_grafo_embebido():
    alm, d, ip = _almacen_demo()
    # vis_js falso: solo comprobamos que se embebe y arma los datasets
    html = generar_reporte(alm, hallazgos=[], score=0, vis_js='/*VISLIB*/')
    assert 'Relationship graph' in html
    assert '/*VISLIB*/' in html
    assert 'vis.Network' in html
    assert d.id in html and ip.id in html                    # nodos por id
