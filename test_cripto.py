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
