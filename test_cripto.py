"""Tests de F11 — cripto y rastreo financiero.

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_cripto.py -q
"""
import obsidian_web as ob
from core.modelo import Almacen
from core.transforms import ejecutar_por_nombre


class _R:
    def __init__(self, text='', data=None):
        self.text = text
        self._data = data
    def json(self):
        return self._data


def _correr(nombre, tipo, valor):
    alm = Almacen()
    e = alm.crear(tipo, valor)
    return ejecutar_por_nombre(nombre, e, alm), e, alm


# ── 137: extracción de wallets ───────────────────────────────────────────────
def test_extraer_wallets(monkeypatch):
    eth = '0x' + 'a' * 40
    txt = f'donar a 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa o a {eth} gracias'
    monkeypatch.setattr(ob, '_fetch_seguro', lambda *a, **k: _R(text=txt))
    prod, _, _ = _correr('extraer_wallets', 'url', 'https://x.com')
    ws = {e.valor for e in prod if e.tipo == 'wallet'}
    assert '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' in ws and eth in ws


# ── 138: grafo de transacciones ──────────────────────────────────────────────
_GENESIS = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'


def test_tx_grafo(monkeypatch):
    tx_json = {'txs': [{'inputs': [{'prev_out': {'addr': 'inp111'}}],
                        'out': [{'addr': 'out222'}, {'addr': _GENESIS}]}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=tx_json))
    prod, _, _ = _correr('tx_grafo', 'wallet', _GENESIS)
    ws = {e.valor for e in prod if e.tipo == 'wallet'}
    assert ws == {'inp111', 'out222'}                # contrapartes, sin la propia


def test_tx_grafo_ignora_no_btc():
    prod, _, _ = _correr('tx_grafo', 'wallet', '0x' + 'a' * 40)   # ETH -> no aplica aún
    assert prod == []


# ── 139: clustering por co-inputs ────────────────────────────────────────────
def test_cluster_wallets(monkeypatch):
    tx_json = {'txs': [{'inputs': [{'prev_out': {'addr': _GENESIS}},
                                   {'prev_out': {'addr': 'hermana1'}}],
                        'out': [{'addr': 'destino'}]}]}
    monkeypatch.setattr(ob.SESSION, 'get', lambda *a, **k: _R(data=tx_json))
    prod, _, _ = _correr('cluster_wallets', 'wallet', _GENESIS)
    hermanas = [e for e in prod if e.tipo == 'wallet']
    assert {e.valor for e in hermanas} == {'hermana1'}          # co-input, no el destino
    assert 'mismo-dueño' in hermanas[0].tags


# ── 140: atribución a exchanges (enlaces a herramientas) ─────────────────────
def test_exchange_attrib():
    prod, _, _ = _correr('exchange_attrib', 'wallet', _GENESIS)
    herrs = {e.propiedades.get('herramienta') for e in prod if e.tipo == 'url'}
    assert herrs == {'blockchair', 'walletexplorer', 'arkham', 'oxt'}


# ── 141: scoring de riesgo (ransomware) + regla ──────────────────────────────
def test_riesgo_wallet_y_regla(monkeypatch):
    from core.correlacion import correlacionar
    monkeypatch.setattr(ob, '_ransom_addrs', lambda: {'1BadRansomAddr'})
    prod, e, alm = _correr('riesgo_wallet', 'wallet', '1BadRansomAddr')
    assert 'ransomware' in e.tags
    h = correlacionar(alm)
    assert any(x.regla == 'wallet-ransomware' and x.severidad == 'critico' for x in h)


def test_riesgo_wallet_limpia(monkeypatch):
    monkeypatch.setattr(ob, '_ransom_addrs', lambda: {'1BadRansomAddr'})
    _, e, _ = _correr('riesgo_wallet', 'wallet', _GENESIS)   # no está en la lista
    assert 'ransomware' not in e.tags


# ── 142: multi-cadena (Ethereum) ─────────────────────────────────────────────
def test_eth_balance(monkeypatch):
    # 0xDE0B6B3A7640000 = 1 ETH en wei
    monkeypatch.setattr(ob.SESSION, 'post', lambda *a, **k: _R(data={'result': '0xDE0B6B3A7640000'}))
    _, e, _ = _correr('eth_balance', 'wallet', '0x' + 'a' * 40)
    assert abs(e.propiedades.get('eth_balance') - 1.0) < 1e-9 and e.propiedades.get('cadena') == 'eth'


def test_eth_balance_ignora_btc():
    _, e, _ = _correr('eth_balance', 'wallet', _GENESIS)     # BTC -> no aplica
    assert 'eth_balance' not in e.propiedades
