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


def _run_one(name, type, value):
    store = Store()
    e = store.create(type, value)
    return run_by_name(name, e, store), e, store


# ── 137: wallet extraction ──────────────────────────────────────────────────
def test_extract_wallets(monkeypatch):
    eth = '0x' + 'a' * 40
    txt = f'donate to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or to {eth} thanks'
    monkeypatch.setattr(ob, '_fetch_seguro', lambda *a, **k: _R(text=txt))
    prod, _, _ = _run_one('extract_wallets', 'url', 'https://x.com')
    ws = {e.value for e in prod if e.type == 'wallet'}
    assert '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' in ws and eth in ws


# ── 138: transaction graph ──────────────────────────────────────────────────
_GENESIS = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'


def test_tx_graph(monkeypatch):
    tx_json = {'txs': [{'inputs': [{'prev_out': {'addr': 'inp111'}}],
                        'out': [{'addr': 'out222'}, {'addr': _GENESIS}]}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=tx_json))
    prod, _, _ = _run_one('tx_graph', 'wallet', _GENESIS)
    ws = {e.value for e in prod if e.type == 'wallet'}
    assert ws == {'inp111', 'out222'}                # counterparties, without itself


def test_tx_graph_ignores_non_btc():
    prod, _, _ = _run_one('tx_graph', 'wallet', '0x' + 'a' * 40)   # ETH -> not applicable yet
    assert prod == []


# ── 139: clustering by co-inputs ────────────────────────────────────────────
def test_cluster_wallets(monkeypatch):
    tx_json = {'txs': [{'inputs': [{'prev_out': {'addr': _GENESIS}},
                                   {'prev_out': {'addr': 'hermana1'}}],
                        'out': [{'addr': 'target'}]}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=tx_json))
    prod, _, _ = _run_one('cluster_wallets', 'wallet', _GENESIS)
    hermanas = [e for e in prod if e.type == 'wallet']
    assert {e.value for e in hermanas} == {'hermana1'}          # co-input, not the destination
    assert 'same-owner' in hermanas[0].tags


# ── 140: exchange attribution (links to tools) ──────────────────────────────
def test_exchange_attrib():
    prod, _, _ = _run_one('exchange_attrib', 'wallet', _GENESIS)
    herrs = {e.properties.get('tool') for e in prod if e.type == 'url'}
    assert herrs == {'blockchair', 'walletexplorer', 'arkham', 'oxt'}


# ── 141: risk scoring (ransomware) + rule ───────────────────────────────────
def test_wallet_risk_rule(monkeypatch):
    from core.correlacion import correlate
    monkeypatch.setattr(ob, '_ransom_addrs', lambda: {'1BadRansomAddr'})
    prod, e, store = _run_one('wallet_risk', 'wallet', '1BadRansomAddr')
    assert 'ransomware' in e.tags
    h = correlate(store)
    assert any(x.rule == 'wallet-ransomware' and x.severity == 'critical' for x in h)


def test_wallet_risk_clears(monkeypatch):
    monkeypatch.setattr(ob, '_ransom_addrs', lambda: {'1BadRansomAddr'})
    _, e, _ = _run_one('wallet_risk', 'wallet', _GENESIS)   # not in the list
    assert 'ransomware' not in e.tags


# ── 142: multi-chain (Ethereum) ─────────────────────────────────────────────
def test_eth_balance(monkeypatch):
    # 0xDE0B6B3A7640000 = 1 ETH in wei
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: _R(data={'result': '0xDE0B6B3A7640000'}))
    _, e, _ = _run_one('eth_balance', 'wallet', '0x' + 'a' * 40)
    assert abs(e.properties.get('eth_balance') - 1.0) < 1e-9 and e.properties.get('cadena') == 'eth'


def test_eth_balance_ignores_btc():
    _, e, _ = _run_one('eth_balance', 'wallet', _GENESIS)     # BTC -> not applicable
    assert 'eth_balance' not in e.properties


# ── 143: movement alerts (via the existing monitor) ─────────────────────────
def test_monitor_detects_movement_wallet():
    """Watching a wallet = the monitor diffs its balance; a movement => alert."""
    from core.monitor import snapshot, diff
    store = Store()
    w = store.create('wallet', _GENESIS, properties={'btc_balance': 1.5, 'btc_tx': 10})
    before = snapshot(store)
    w.properties['btc_balance'] = 3.0                 # money moved in/out
    w.properties['btc_tx'] = 11
    changes = diff(before, snapshot(store))
    campos = {c['field'] for c in changes.prop_changes}
    assert {'btc_balance', 'btc_tx'} <= campos and changes.has_changes()
