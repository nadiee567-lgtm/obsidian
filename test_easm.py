"""Tests for F12 -- continuous attack surface (EASM).

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_easm.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import ejecutar_por_nombre


class _R:
    def __init__(self, data=None):
        self._data = data
    def json(self):
        return self._data


def _cliente_con(alm, monkeypatch):
    monkeypatch.setattr(ob, '_almacen', alm)
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    return c


# ── 144: asset inventory ────────────────────────────────────────────────────
def test_inventario(monkeypatch):
    alm = Store()
    alm.crear('dominio', 'x.com')
    alm.crear('ip', '1.2.3.4')
    alm.crear('puerto', '1.2.3.4:443')
    alm.crear('email', 'a@x.com')                # NOT an internet-facing asset
    c = _cliente_con(alm, monkeypatch)
    d = c.get('/api/v2/inventario').get_json()
    assert d['total_activos'] == 3               # domain+ip+port, not the email
    assert set(d['inventario']) == {'dominio', 'ip', 'puerto'}


# ── 145 + 146: continuous discovery + change detection (via the monitor) ─────
def test_descubrimiento_y_cambios_via_monitor():
    from core.monitor import snapshot, diff
    alm = Store()
    d = alm.crear('dominio', 'x.com', propiedades={'cert_expira': '2027'})
    antes = snapshot(alm)
    alm.crear('subdominio', 'nuevo.x.com')       # new asset (145)
    alm.crear('puerto', '1.2.3.4:22')            # new port (146)
    d.propiedades['cert_expira'] = '2020'        # cert changed (146)
    cambios = diff(antes, snapshot(alm))
    valores = {e['valor'] for e in cambios.nuevas_entidades}
    assert {'nuevo.x.com', '1.2.3.4:22'} <= valores
    assert any(c['campo'] == 'cert_expira' for c in cambios.cambios_prop)


# ── 147: infrastructure clustering ──────────────────────────────────────────
def test_infra_compartida():
    from core.correlacion import correlacionar
    alm = Store()
    alm.crear('dominio', 'a.com', propiedades={'favicon_hash': '123456'})
    alm.crear('dominio', 'b.com', propiedades={'favicon_hash': '123456'})   # same favicon
    alm.crear('dominio', 'c.com', propiedades={'favicon_hash': '999'})       # different
    r = [x for x in correlacionar(alm) if x.regla == 'infra-compartida']
    assert len(r) == 1 and len(r[0].entidades) == 2                          # a.com and b.com


def test_infra_compartida_sin_grupo():
    from core.correlacion import correlacionar
    alm = Store()
    alm.crear('dominio', 'solo.com', propiedades={'favicon_hash': '111'})
    assert not [x for x in correlacionar(alm) if x.regla == 'infra-compartida']


# ── 148: tech -> CVE map (cve_lookup, with anti-noise CPE filter) ────────────
def test_cve_lookup_tech(monkeypatch):
    resp = {'vulnerabilities': [
        {'cve': {'id': 'CVE-2021-1234',
                 'configurations': [{'nodes': [{'cpeMatch': [{'criteria': 'cpe:2.3:a:nginx:nginx:1.0'}]}]}]}},
        {'cve': {'id': 'CVE-2021-9999',      # apache, must NOT show up for tech=nginx
                 'configurations': [{'nodes': [{'cpeMatch': [{'criteria': 'cpe:2.3:a:apache:httpd:2.4'}]}]}]}},
    ]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=resp))
    alm = Store()
    prod = ejecutar_por_nombre('cve_lookup', alm.crear('tech', 'nginx'), alm)
    cids = {x.valor for x in prod if x.tipo == 'cve'}
    assert cids == {'CVE-2021-1234'}             # anti-noise CPE filter: only the nginx one


# ── 149: exposure scoring ───────────────────────────────────────────────────
def test_score_exposicion():
    from core.correlacion import score_exposicion
    assert score_exposicion({}, 0) == 0
    # surface: 10 subdom + 3 ports(*2) = 16 ; risk 40//2 = 20 -> 36
    assert score_exposicion({'subdominio': 10, 'puerto': 3}, 40) == 36
    assert score_exposicion({'subdominio': 999}, 100) == 100          # caps at 100


def test_exposicion_endpoint(monkeypatch):
    alm = Store()
    for i in range(5):
        alm.crear('subdominio', f's{i}.x.com')
    c = _cliente_con(alm, monkeypatch)
    d = c.get('/api/v2/exposicion').get_json()
    assert d['superficie']['subdominio'] == 5 and 0 <= d['exposicion'] <= 100


# ── 150: Shadow IT / forgotten assets ───────────────────────────────────────
def test_shadow_it():
    from core.correlacion import correlacionar
    alm = Store()
    alm.crear('bucket', 'acme-backups').etiquetar('publico')           # open storage
    alm.crear('subdominio', 'viejo.acme.com', propiedades={'http_status': 503})  # broken
    alm.crear('subdominio', 'vivo.acme.com', propiedades={'http_status': 200})   # healthy
    r = [x for x in correlacionar(alm) if x.regla == 'shadow-it']
    sev = {x.severidad for x in r}
    assert len(r) == 2 and sev == {'alto', 'medio'}                    # bucket + broken subdom


# ── 151: historical surface diff ────────────────────────────────────────────
def test_diff_historico(tmp_path):
    from core.workspaces import Manager
    g = Manager(str(tmp_path))
    g.crear('caso')
    alm = Store()
    alm.crear('subdominio', 'a.x.com')
    g.guardar('caso', alm)
    sid = g.snapshot('caso')                     # historical snapshot: 1 asset
    alm.crear('subdominio', 'b.x.com')           # a new asset appeared
    g.guardar('caso', alm)
    viejo = g.cargar_snapshot('caso', sid)
    assert len(viejo) == 1
    nuevos = {e.id for e in g.cargar('caso').entidades} - {e.id for e in viejo.entidades}
    assert len(nuevos) == 1                       # b.x.com appeared since the snapshot
