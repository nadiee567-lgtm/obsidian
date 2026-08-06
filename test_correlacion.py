"""Tests for the correlation engine (F4).

Run:  ../.venv/bin/python -m pytest test_correlacion.py -q
"""
from core.modelo import Almacen
from core.correlacion import correlacionar, score_riesgo, Hallazgo


def test_puerto_sensible():
    alm = Almacen()
    alm.crear('puerto', '1.2.3.4:3389', propiedades={'servicio': 'rdp'})
    alm.crear('puerto', '1.2.3.4:443')   # https, not sensitive
    h = correlacionar(alm)
    reglas = [x.regla for x in h]
    assert 'puerto-sensible' in reglas
    assert sum(1 for x in h if x.regla == 'puerto-sensible') == 1   # only the 3389


def test_cert_vencido():
    alm = Almacen()
    alm.crear('dominio', 'viejo.com', propiedades={'cert_expira': 'Jan 1 00:00:00 2020 GMT'})
    alm.crear('dominio', 'nuevo.com', propiedades={'cert_expira': 'Jan 1 00:00:00 2099 GMT'})
    reglas = [x.regla for x in correlacionar(alm)]
    assert reglas.count('cert-vencido') == 1   # only the 2020 one


def test_ip_maliciosa_es_critica():
    alm = Almacen()
    ip = alm.crear('ip', '45.9.9.9')
    ip.etiquetar('malicioso')
    h = correlacionar(alm)
    assert h[0].regla == 'ip-maliciosa' and h[0].severidad == 'critico'   # comes first


def test_email_filtrado_y_spoofable():
    alm = Almacen()
    e = alm.crear('email', 'a@b.com')
    e.etiquetar('filtrado', 'spoofable')
    reglas = {x.regla for x in correlacionar(alm)}
    assert {'email-filtrado', 'email-spoofable'} <= reglas


def test_orden_por_severidad():
    alm = Almacen()
    alm.crear('email', 'x@y.com').etiquetar('spoofable')   # medium
    alm.crear('ip', '45.0.0.1').etiquetar('malicioso')     # critical
    alm.crear('puerto', '1.1.1.1:3306')                    # high
    sev = [x.severidad for x in correlacionar(alm)]
    assert sev == sorted(sev, key=lambda s: -{'critico':4,'alto':3,'medio':2,'bajo':1}[s])
    assert sev[0] == 'critico'


def test_score_riesgo():
    assert score_riesgo([]) == 0
    h = [Hallazgo('a', 'critico', 'x'), Hallazgo('b', 'medio', 'y')]
    assert score_riesgo(h) == 48          # 40 + 8
    # caps at 100
    muchos = [Hallazgo('r', 'critico', 'm') for _ in range(5)]
    assert score_riesgo(muchos) == 100


def test_sin_datos_sin_hallazgos():
    assert correlacionar(Almacen()) == []


def test_feedback_suprime_descartados():
    """If the analyst tags the entity as a false positive, its finding disappears."""
    alm = Almacen()
    ip = alm.crear('ip', '45.9.9.9')
    ip.etiquetar('malicioso')
    assert len(correlacionar(alm)) == 1
    ip.etiquetar('falso-positivo')          # analyst feedback
    assert correlacionar(alm) == []
