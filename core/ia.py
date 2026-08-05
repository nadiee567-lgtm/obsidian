"""Capa de IA ÚNICA de OBSIDIAN — una sola "cabeza" que todos los features usan.

En vez de regar llamadas a Ollama por el código (resumen, verificador, futura
extracción de entidades, traducción, chat...), TODO pasa por aquí. Una sola
puerta: cambiar de modelo o apuntar a NEXO (router) se hace en UN solo lugar.

Es UN modelo local (Ollama), no varios. Local = sin costo por token (corre en
la GPU del usuario); el único costo es tiempo de cómputo.

Módulo PURO: su propio cliente HTTP, no depende de Flask."""
import os
import re
import requests

OLLAMA = os.environ.get('OBSIDIAN_OLLAMA', 'http://localhost:11434')
MODELO = os.environ.get('OBSIDIAN_MODELO_IA', 'qwen2.5:3b')
NEXO = os.environ.get('OBSIDIAN_NEXO', '')       # '1' activa el ruteo estilo NEXO

_S = requests.Session()

# Ruteo estilo NEXO (paso 168): clasifica la tarea por keywords → modelo local.
_RUTEO = {
    'seguridad': (['exploit', 'vuln', 'cve', 'ataque', 'attack', 'malware', 'ransomware',
                   'payload', 'pentest', 'shell', 'takeover'], 'dolphin-llama3'),
    'osint': (['osint', 'dominio', 'subdominio', 'whois', 'dns', 'recon', 'wallet',
               'breach', 'leak', 'filtrac'], 'qwen2.5:3b'),
    'codigo': (['código', 'codigo', 'python', 'function', 'regex', 'script', 'bug'], 'qwen2.5:3b'),
}


def elegir_modelo(texto):
    """Elige el modelo local según la tarea (router estilo NEXO). Una IP explícita
    pesa hacia seguridad; sin señales, un modelo rápido por defecto."""
    t = (texto or '').lower()
    puntajes = {cat: sum(t.count(k) for k in kws) for cat, (kws, _) in _RUTEO.items()}
    if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', t):
        puntajes['seguridad'] += 2
    cat = max(puntajes, key=puntajes.get)
    return _RUTEO[cat][1] if puntajes[cat] > 0 else 'qwen2.5:1.5b'


def disponible():
    """¿Está corriendo Ollama? (para degradar con gracia si no)."""
    try:
        return _S.get(f'{OLLAMA}/api/tags', timeout=3).ok
    except Exception:
        return False


def consultar(prompt, sistema=None, max_tokens=300, temp=0.4, modelo=None):
    """La ÚNICA función que habla con la IA. Devuelve texto (o lanza si Ollama
    no responde — el llamador decide cómo degradar).

    Si OBSIDIAN_NEXO está activo (y no se fuerza `modelo`), enruta al mejor modelo
    local según la tarea (paso 168), sin tocar a los que la llaman."""
    m = modelo or (elegir_modelo(f'{sistema or ""} {prompt}') if NEXO else MODELO)
    mensajes = ([{'role': 'system', 'content': sistema}] if sistema else [])
    mensajes.append({'role': 'user', 'content': prompt})
    r = _S.post(f'{OLLAMA}/api/chat', json={
        'model': m,
        'messages': mensajes,
        'stream': False,
        'options': {'num_ctx': 2048, 'num_predict': max_tokens, 'temperature': temp},
    }, timeout=(10, 120))
    return (r.json().get('message', {}) or {}).get('content', '').strip()
