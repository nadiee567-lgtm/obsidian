"""Tests for F14 -- the AI layer.

Run:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_ia.py -q
"""


def test_extraer_entities():
    from core.extraccion import extract_entities
    txt = ('Contact admin@acme.com via https://acme.com from 8.8.8.8. '
           'Attached reporte.pdf and foto.jpg. Bad IP 999.1.1.1.')
    vals = {v for _, v in extract_entities(txt)}
    assert 'admin@acme.com' in vals
    assert '8.8.8.8' in vals
    assert 'https://acme.com' in vals
    assert 'acme.com' in vals
    assert 'reporte.pdf' not in vals
    assert 'foto.jpg' not in vals
    assert '999.1.1.1' not in vals


def test_extract_wallets_texto():
    from core.extraccion import extract_entities
    txt = 'pay to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
    tipos = {t for t, _ in extract_entities(txt)}
    assert 'wallet' in tipos


def test_translate(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'Hello world')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/translate', json={'text': '你好世界'}).get_json()
    assert d['traduccion'] == 'Hello world'
    assert c.post('/api/v2/translate', json={'text': ''}).status_code == 400


def test_translate_without_ai(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: False)
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    assert c.post('/api/v2/translate', json={'text': 'x'}).status_code == 503


def test_summary_mode_ai(monkeypatch):
    import obsidian_web as ob
    assert 'summary' in ob._AI_PROMPTS
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'The target has 3 exposed subdomains.')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/ia/summary').get_json()
    assert d['modo'] == 'summary' and 'subdomains' in d['result']


def test_modes_ai_extra():
    import obsidian_web as ob
    assert {'siguiente', 'narrativa', 'clasificar'} <= set(ob._AI_PROMPTS)


def test_query_nl(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: '1. dns_a on the domain\n2. crtsh')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/query', json={'pregunta': 'find everything about acme.com'}).get_json()
    assert 'plan' in d and 'dns_a' in d['plan']
    assert c.post('/api/v2/query', json={'pregunta': ''}).status_code == 400


def test_choose_model_nexo():
    from core.ia import pick_model
    assert pick_model('find an exploit for this vuln') == 'dolphin-llama3'
    assert pick_model('recon of the domain and its subdomains') == 'qwen2.5:7b'
    assert pick_model('scan of 8.8.8.8') == 'dolphin-llama3'
    assert pick_model('hello how are you') == 'qwen2.5:3b'


def test_detection_ai(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'available', lambda: True)
    monkeypatch.setattr(ob.ia, 'ask', lambda *a, **k: 'Very uniform text, possibly AI.')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/ai_detection', json={'text': 'lorem ipsum...'}).get_json()
    assert 'evaluacion' in d and 'A HINT' in d['aviso']


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
