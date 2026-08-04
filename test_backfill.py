"""Tests del backfill de F2/F4 (módulos viejos migrados a transforms + reglas).

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_backfill.py -q
"""
import obsidian_web as ob
from core.modelo import Almacen
from core.transforms import ejecutar_por_nombre


def _correr(nombre, tipo, valor):
    alm = Almacen()
    e = alm.crear(tipo, valor)
    return ejecutar_por_nombre(nombre, e, alm), e, alm


# ── 33: teléfono ─────────────────────────────────────────────────────────────
def test_telefono_dorks_keyless():
    prod, _, _ = _correr('telefono_dorks', 'telefono', '+14155552671')
    dorks = {p.propiedades.get('dork') for p in prod if p.tipo == 'url'}
    assert dorks == {'truecaller', 'whitepages', 'mensajeria', 'general'}
    assert all(p.tipo == 'url' for p in prod)      # sin key: solo dorks, sin país


# ── 34: typosquatting / buckets / takeover / passivedns ──────────────────────
def test_typosquatting(monkeypatch):
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: '1.2.3.4\n')   # todo "resuelve"
    prod, _, _ = _correr('typosquatting', 'dominio', 'google.com')
    assert prod and all(p.tipo == 'dominio' and 'typosquat' in p.tags for p in prod)


def test_buckets(monkeypatch):
    class R:
        status_code = 200
        text = ''
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: R())
    prod, _, _ = _correr('buckets', 'org', 'ACME Corp')
    assert prod and all(p.tipo == 'bucket' for p in prod)
    assert any('publico' in p.tags for p in prod)


def test_takeover(monkeypatch):
    class Rj:
        status_code = 200
        text = "There isn't a GitHub Pages site here"
        def json(self):
            return [{'name_value': 'abandonado.ejemplo.com'}]
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: Rj())
    monkeypatch.setattr(ob, 'run_tool', lambda *a, **k: 'user.github.io.\n')  # CNAME huérfano
    prod, _, _ = _correr('takeover', 'dominio', 'ejemplo.com')
    vulns = [p for p in prod if 'takeover' in p.tags]
    assert vulns and vulns[0].valor == 'abandonado.ejemplo.com'


def test_passivedns(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: 'k')
    class R:
        def json(self):
            return {'data': [{'attributes': {'ip_address': '9.9.9.9', 'date': 1600000000}}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: R())
    prod, _, _ = _correr('passivedns', 'dominio', 'ejemplo.com')
    assert {p.valor for p in prod if p.tipo == 'ip'} == {'9.9.9.9'}


def test_passivedns_sin_key(monkeypatch):
    monkeypatch.setattr(ob._boveda, 'obtener', lambda s: None)
    monkeypatch.setenv('VT_API_KEY', '')
    prod, _, _ = _correr('passivedns', 'dominio', 'ejemplo.com')
    assert prod == []
