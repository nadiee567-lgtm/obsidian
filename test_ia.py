"""Tests for F14 -- the AI layer.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_ia.py -q
"""


# ── 161: entity extraction from text ────────────────────────────────────────
def test_extraer_entidades():
    from core.extraccion import extract_entities
    txt = ('Contact admin@acme.com via https://acme.com from 8.8.8.8. '
           'Attached reporte.pdf and foto.jpg. Bad IP 999.1.1.1.')
    vals = {v for _, v in extract_entities(txt)}
    assert 'admin@acme.com' in vals
    assert '8.8.8.8' in vals
    assert 'https://acme.com' in vals
    assert 'acme.com' in vals                    # extracted domain
    assert 'reporte.pdf' not in vals             # anti-FP: file, not a domain
    assert 'foto.jpg' not in vals
    assert '999.1.1.1' not in vals               # invalid octet discarded


def test_extraer_wallets_de_texto():
    from core.extraccion import extract_entities
    txt = 'pay to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
    tipos = {t for t, _ in extract_entities(txt)}
    assert 'wallet' in tipos


# ── 162: translation of foreign sources ─────────────────────────────────────
def test_traducir(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'Hello world')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/translate', json={'texto': '你好世界'}).get_json()
    assert d['traduccion'] == 'Hello world'
    assert c.post('/api/v2/translate', json={'texto': ''}).status_code == 400


def test_traducir_sin_ia(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: False)
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    assert c.post('/api/v2/translate', json={'texto': 'x'}).status_code == 503


# ── 163: natural-language case summary (AI mode) ────────────────────────────
def test_resumen_modo_ia(monkeypatch):
    import obsidian_web as ob
    assert 'summary' in ob._PROMPTS_IA
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'The target has 3 exposed subdomains.')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/ia/summary').get_json()
    assert d['modo'] == 'summary' and 'subdomains' in d['resultado']


# ── 164/166/167: AI modes (next step, narrative, classification) ────────────
def test_modos_ia_extra():
    import obsidian_web as ob
    assert {'siguiente', 'narrativa', 'clasificar'} <= set(ob._PROMPTS_IA)


# ── 165: natural-language query -> plan ─────────────────────────────────────
def test_consulta_nl(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: '1. dns_a on the domain\n2. crtsh')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/query', json={'pregunta': 'find everything about acme.com'}).get_json()
    assert 'plan' in d and 'dns_a' in d['plan']
    assert c.post('/api/v2/query', json={'pregunta': ''}).status_code == 400


# ── 168: connect with NEXO (per-task model routing) ─────────────────────────
def test_elegir_modelo_nexo():
    from core.ia import pick_model
    assert pick_model('find an exploit for this vuln') == 'dolphin-llama3'     # security
    assert pick_model('recon of the domain and its subdomains') == 'qwen2.5:3b'   # osint
    assert pick_model('scan of 8.8.8.8') == 'dolphin-llama3'                   # IP -> security
    assert pick_model('hello how are you') == 'qwen2.5:1.5b'                   # no signal -> fast


# ── 169: AI detection (a hint, not proof) ───────────────────────────────────
def test_deteccion_ia(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'Very uniform text, possibly AI.')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/ai_detection', json={'texto': 'lorem ipsum...'}).get_json()
    assert 'evaluacion' in d and 'A HINT' in d['aviso']   # honesty: gives no certainty


# ── 170: chat about the case ────────────────────────────────────────────────
def test_chat_case(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'IP 1.2.3.4 hosts the domain.')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/chat', json={'pregunta': 'relation between the ip and the domain?'}).get_json()
    assert 'respuesta' in d and '1.2.3.4' in d['respuesta']
    assert c.post('/api/v2/chat', json={'pregunta': ''}).status_code == 400
