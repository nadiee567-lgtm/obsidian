"""Tests de F14 — capa de IA.

Correr:  OBSIDIAN_PASSWORD=x ../.venv/bin/python -m pytest test_ia.py -q
"""


# ── 161: extracción de entidades de texto ────────────────────────────────────
def test_extraer_entidades():
    from core.extraccion import extraer_entidades
    txt = ('Contacto admin@acme.com vía https://acme.com desde 8.8.8.8. '
           'Adjunto reporte.pdf y foto.jpg. IP mala 999.1.1.1.')
    vals = {v for _, v in extraer_entidades(txt)}
    assert 'admin@acme.com' in vals
    assert '8.8.8.8' in vals
    assert 'https://acme.com' in vals
    assert 'acme.com' in vals                    # dominio extraído
    assert 'reporte.pdf' not in vals             # anti-FP: archivo, no dominio
    assert 'foto.jpg' not in vals
    assert '999.1.1.1' not in vals               # octeto inválido descartado


def test_extraer_wallets_de_texto():
    from core.extraccion import extraer_entidades
    txt = 'paga a 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
    tipos = {t for t, _ in extraer_entidades(txt)}
    assert 'wallet' in tipos


# ── 162: traducción de fuentes extranjeras ───────────────────────────────────
def test_traducir(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'disponible', lambda: True)
    monkeypatch.setattr(ob.ia, 'consultar', lambda *a, **k: 'Hola mundo')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/traducir', json={'texto': '你好世界'}).get_json()
    assert d['traduccion'] == 'Hola mundo'
    assert c.post('/api/v2/traducir', json={'texto': ''}).status_code == 400


def test_traducir_sin_ia(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'disponible', lambda: False)
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    assert c.post('/api/v2/traducir', json={'texto': 'x'}).status_code == 503


# ── 163: resumen del caso en lenguaje natural (modo IA) ───────────────────────
def test_resumen_modo_ia(monkeypatch):
    import obsidian_web as ob
    assert 'resumen' in ob._PROMPTS_IA
    monkeypatch.setattr(ob.ia, 'disponible', lambda: True)
    monkeypatch.setattr(ob.ia, 'consultar', lambda *a, **k: 'El objetivo tiene 3 subdominios expuestos.')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/ia/resumen').get_json()
    assert d['modo'] == 'resumen' and 'subdominios' in d['resultado']


# ── 164/166/167: modos IA (siguiente paso, narrativa, clasificación) ─────────
def test_modos_ia_extra():
    import obsidian_web as ob
    assert {'siguiente', 'narrativa', 'clasificar'} <= set(ob._PROMPTS_IA)


# ── 165: consulta en lenguaje natural -> plan ─────────────────────────────────
def test_consulta_nl(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'disponible', lambda: True)
    monkeypatch.setattr(ob.ia, 'consultar', lambda *a, **k: '1. dns_a sobre el dominio\n2. crtsh')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/consulta', json={'pregunta': 'encuentra todo sobre acme.com'}).get_json()
    assert 'plan' in d and 'dns_a' in d['plan']
    assert c.post('/api/v2/consulta', json={'pregunta': ''}).status_code == 400


# ── 168: conectar con NEXO (ruteo de modelo por tarea) ────────────────────────
def test_elegir_modelo_nexo():
    from core.ia import elegir_modelo
    assert elegir_modelo('busca un exploit para esta vuln') == 'dolphin-llama3'   # seguridad
    assert elegir_modelo('recon del dominio y sus subdominios') == 'qwen2.5:3b'   # osint
    assert elegir_modelo('scan de 8.8.8.8') == 'dolphin-llama3'                   # IP -> seguridad
    assert elegir_modelo('hola qué tal') == 'qwen2.5:1.5b'                        # sin señal -> rápido


# ── 169: detección de IA (indicio, no prueba) ─────────────────────────────────
def test_deteccion_ia(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'disponible', lambda: True)
    monkeypatch.setattr(ob.ia, 'consultar', lambda *a, **k: 'Texto muy uniforme, posible IA.')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/deteccion_ia', json={'texto': 'lorem ipsum...'}).get_json()
    assert 'evaluacion' in d and 'INDICIO' in d['aviso']   # honestidad: no da certeza


# ── 170: chat sobre el caso ───────────────────────────────────────────────────
def test_chat_caso(monkeypatch):
    import obsidian_web as ob
    monkeypatch.setattr(ob.ia, 'disponible', lambda: True)
    monkeypatch.setattr(ob.ia, 'consultar', lambda *a, **k: 'La IP 1.2.3.4 aloja el dominio.')
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.post('/api/v2/chat', json={'pregunta': '¿relación entre la ip y el dominio?'}).get_json()
    assert 'respuesta' in d and '1.2.3.4' in d['respuesta']
    assert c.post('/api/v2/chat', json={'pregunta': ''}).status_code == 400
