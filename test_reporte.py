"""Tests for the HTML report generator (F7 step 93).

Run:  ../.venv/bin/python -m pytest test_reporte.py -q
"""
from core.modelo import Store
from core.correlacion import Finding
from core.reporte import generate_report


def _store_demo():
    alm = Store()
    d = alm.create('domain', 'target.com', properties={'org': 'ACME'})
    ip = alm.create('ip', '93.184.216.34', properties={'country': 'US'})
    ip.tag('threat-listed')
    alm.relate(d.id, ip.id, 'resuelve')
    return alm, d, ip


def test_report_has_sections():
    alm, d, ip = _store_demo()
    h = [Finding('ip-listed', 'high', 'IP en feed de amenazas', [ip.id])]
    html = generate_report(alm, hallazgos=h, score=20,
                           meta={'workspace': 'caso-1', 'target': 'target.com'})
    for txt in ('Risk summary', 'Findings', 'Entity inventory',
                'target.com', '93.184.216.34', 'ip-listed', '20/100', 'caso-1'):
        assert txt in html, f'missing from the report: {txt}'


def test_report_no_findings():
    alm, _, _ = _store_demo()
    html = generate_report(alm, hallazgos=[], score=0)
    assert 'No risks detected' in html
    assert '0/100' in html


def test_report_empty_store():
    html = generate_report(Store(), hallazgos=[], score=0)
    assert 'No entities' in html


def test_report_escapes_xss():
    """Raw target data with a payload → must come out escaped, never executable."""
    alm = Store()
    alm.create('domain', 'malo.com',
              properties={'nota': '<script>alert(1)</script>'})
    h = [Finding('r', 'critical', 'injection <img src=x onerror=alert(1)>', [])]
    html = generate_report(alm, hallazgos=h, score=40)
    assert '<script>alert(1)</script>' not in html          # raw NO
    assert '&lt;script&gt;' in html                          # escaped YES
    assert '<img src=x onerror' not in html                  # the finding's neither
    assert '&lt;img src=x' in html


def test_report_embedded_graph():
    alm, d, ip = _store_demo()
    # fake vis_js: we only check it gets embedded and builds the datasets
    html = generate_report(alm, hallazgos=[], score=0, vis_js='/*VISLIB*/')
    assert 'Relationship graph' in html
    assert '/*VISLIB*/' in html
    assert 'vis.Network' in html
    assert d.id in html and ip.id in html                    # nodes by id
