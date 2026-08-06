"""Tests for F11 -- crypto and financial tracing.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_cripto.py -q
"""
import obsidian_web as ob
from core.modelo import Store
from core.transforms import run_by_name


class _R:
    def __init__(self, text='', data=None):
        self.text = text
        self._data = data
    def json(self):
        return self._data


def _correr(nombre, type, value):
    alm = Store()
    e = alm.create(type, value)
    return run_by_name(nombre, e, alm), e, alm


# ── 137: wallet extraction ──────────────────────────────────────────────────
def test_extraer_wallets(monkeypatch):
    eth = '0x' + 'a' * 40
    txt = f'donate to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or to {eth} thanks'
    monkeypatch.setattr(ob, '_fetch_seguro', lambda *a, **k: _R(text=txt))
    prod, _, _ = _correr('extraer_wallets', 'url', 'https://x.com')
    ws = {e.value for e in prod if e.type == 'wallet'}
    assert '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' in ws and eth in ws


# ── 138: transaction graph ──────────────────────────────────────────────────
_GENESIS = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'


def test_tx_grafo(monkeypatch):
    tx_json = {'txs': [{'inputs': [{'prev_out': {'addr': 'inp111'}}],
                        'out': [{'addr': 'out222'}, {'addr': _GENESIS}]}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=tx_json))
    prod, _, _ = _correr('tx_grafo', 'wallet', _GENESIS)
    ws = {e.value for e in prod if e.type == 'wallet'}
    assert ws == {'inp111', 'out222'}                # counterparties, without itself


def test_tx_grafo_ignora_no_btc():
    prod, _, _ = _correr('tx_grafo', 'wallet', '0x' + 'a' * 40)   # ETH -> not applicable yet
    assert prod == []


# ── 139: clustering by co-inputs ────────────────────────────────────────────
def test_cluster_wallets(monkeypatch):
    tx_json = {'txs': [{'inputs': [{'prev_out': {'addr': _GENESIS}},
                                   {'prev_out': {'addr': 'hermana1'}}],
                        'out': [{'addr': 'target'}]}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=tx_json))
    prod, _, _ = _correr('cluster_wallets', 'wallet', _GENESIS)
    hermanas = [e for e in prod if e.type == 'wallet']
    assert {e.value for e in hermanas} == {'hermana1'}          # co-input, not the destination
    assert 'mismo-dueño' in hermanas[0].tags


# ── 140: exchange attribution (links to tools) ──────────────────────────────
def test_exchange_attrib():
    prod, _, _ = _correr('exchange_attrib', 'wallet', _GENESIS)
    herrs = {e.properties.get('herramienta') for e in prod if e.type == 'url'}
    assert herrs == {'blockchair', 'walletexplorer', 'arkham', 'oxt'}


# ── 141: risk scoring (ransomware) + rule ───────────────────────────────────
def test_riesgo_wallet_y_regla(monkeypatch):
    from core.correlacion import correlate
    monkeypatch.setattr(ob, '_ransom_addrs', lambda: {'1BadRansomAddr'})
    prod, e, alm = _correr('riesgo_wallet', 'wallet', '1BadRansomAddr')
    assert 'ransomware' in e.tags
    h = correlate(alm)
    assert any(x.regla == 'wallet-ransomware' and x.severidad == 'critical' for x in h)


def test_riesgo_wallet_limpia(monkeypatch):
    monkeypatch.setattr(ob, '_ransom_addrs', lambda: {'1BadRansomAddr'})
    _, e, _ = _correr('riesgo_wallet', 'wallet', _GENESIS)   # not in the list
    assert 'ransomware' not in e.tags


# ── 142: multi-chain (Ethereum) ─────────────────────────────────────────────
def test_eth_balance(monkeypatch):
    # 0xDE0B6B3A7640000 = 1 ETH in wei
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: _R(data={'result': '0xDE0B6B3A7640000'}))
    _, e, _ = _correr('eth_balance', 'wallet', '0x' + 'a' * 40)
    assert abs(e.properties.get('eth_balance') - 1.0) < 1e-9 and e.properties.get('cadena') == 'eth'


def test_eth_balance_ignora_btc():
    _, e, _ = _correr('eth_balance', 'wallet', _GENESIS)     # BTC -> not applicable
    assert 'eth_balance' not in e.properties


# ── 143: movement alerts (via the existing monitor) ─────────────────────────
def test_monitor_detecta_movimiento_wallet():
    """Watching a wallet = the monitor diffs its balance; a movement => alert."""
    from core.monitor import snapshot, diff
    alm = Store()
    w = alm.create('wallet', _GENESIS, properties={'btc_balance': 1.5, 'btc_tx': 10})
    antes = snapshot(alm)
    w.properties['btc_balance'] = 3.0                 # money moved in/out
    w.properties['btc_tx'] = 11
    cambios = diff(antes, snapshot(alm))
    campos = {c['campo'] for c in cambios.cambios_prop}
    assert {'btc_balance', 'btc_tx'} <= campos and cambios.hay()
