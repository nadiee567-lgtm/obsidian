"""Tests for the correlation engine (F4).

Run:  ../.venv/bin/python -m pytest test_correlacion.py -q
"""
from core.modelo import Store
from core.correlacion import correlate, risk_score, Finding


def test_puerto_sensible():
    alm = Store()
    alm.create('port', '1.2.3.4:3389', properties={'service': 'rdp'})
    alm.create('port', '1.2.3.4:443')   # https, not sensitive
    h = correlate(alm)
    reglas = [x.rule for x in h]
    assert 'sensitive-port' in reglas
    assert sum(1 for x in h if x.rule == 'sensitive-port') == 1   # only the 3389


def test_cert_vencido():
    alm = Store()
    alm.create('domain', 'viejo.com', properties={'cert_expira': 'Jan 1 00:00:00 2020 GMT'})
    alm.create('domain', 'nuevo.com', properties={'cert_expira': 'Jan 1 00:00:00 2099 GMT'})
    reglas = [x.rule for x in correlate(alm)]
    assert reglas.count('cert-expired') == 1   # only the 2020 one


def test_ip_maliciosa_es_critica():
    alm = Store()
    ip = alm.create('ip', '45.9.9.9')
    ip.tag('malicious')
    h = correlate(alm)
    assert h[0].rule == 'ip-malicious' and h[0].severity == 'critical'   # comes first


def test_email_filtrado_y_spoofable():
    alm = Store()
    e = alm.create('email', 'a@b.com')
    e.tag('leaked', 'spoofable')
    reglas = {x.rule for x in correlate(alm)}
    assert {'email-leaked', 'email-spoofable'} <= reglas


def test_orden_por_severidad():
    alm = Store()
    alm.create('email', 'x@y.com').tag('spoofable')   # medium
    alm.create('ip', '45.0.0.1').tag('malicious')     # critical
    alm.create('port', '1.1.1.1:3306')                    # high
    sev = [x.severity for x in correlate(alm)]
    assert sev == sorted(sev, key=lambda s: -{'critical':4,'high':3,'medium':2,'low':1}[s])
    assert sev[0] == 'critical'


def test_score_riesgo():
    assert risk_score([]) == 0
    h = [Finding('a', 'critical', 'x'), Finding('b', 'medium', 'y')]
    assert risk_score(h) == 48          # 40 + 8
    # caps at 100
    muchos = [Finding('r', 'critical', 'm') for _ in range(5)]
    assert risk_score(muchos) == 100


def test_sin_datos_sin_hallazgos():
    assert correlate(Store()) == []


def test_feedback_suprime_descartados():
    """If the analyst tags the entity as a false positive, its finding disappears."""
    alm = Store()
    ip = alm.create('ip', '45.9.9.9')
    ip.tag('malicious')
    assert len(correlate(alm)) == 1
    ip.tag('false-positive')          # analyst feedback
    assert correlate(alm) == []
