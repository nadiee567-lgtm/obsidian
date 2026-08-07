"""OBSIDIAN's SINGLE AI layer -- one "head" that every feature uses.

Instead of scattering Ollama calls across the code (summary, verifier, future
entity extraction, translation, chat...), EVERYTHING goes through here. One door:
switching model or pointing to NEXO (router) is done in a SINGLE place.

It is ONE local model (Ollama), not several. Local = no per-token cost (runs on
the user's GPU); the only cost is compute time.

PURE module: its own HTTP client, does not depend on Flask."""
import os
import re
import requests

OLLAMA = os.environ.get('OBSIDIAN_OLLAMA', 'http://localhost:11434')
MODELO = os.environ.get('OBSIDIAN_MODELO_IA', 'qwen2.5:3b')
NEXO = os.environ.get('OBSIDIAN_NEXO', '')       # '1' enables NEXO-style routing

_S = requests.Session()

# NEXO-style routing (step 168): classifies the task by keywords -> local model.
_ROUTING = {
    'seguridad': (['exploit', 'vuln', 'cve', 'attack', 'malware', 'ransomware',
                   'payload', 'pentest', 'shell', 'takeover'], 'dolphin-llama3'),
    'osint': (['osint', 'domain', 'subdomain', 'whois', 'dns', 'recon', 'wallet',
               'breach', 'leak'], 'qwen2.5:3b'),
    'codigo': (['code', 'python', 'function', 'regex', 'script', 'bug'], 'qwen2.5:3b'),
}


def pick_model(text):
    """Picks the local model based on the task (NEXO-style router). An explicit IP
    leans toward security; with no signals, a fast model by default."""
    t = (text or '').lower()
    puntajes = {cat: sum(t.count(k) for k in kws) for cat, (kws, _) in _ROUTING.items()}
    if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', t):
        puntajes['seguridad'] += 2
    cat = max(puntajes, key=puntajes.get)
    return _ROUTING[cat][1] if puntajes[cat] > 0 else 'qwen2.5:1.5b'


def available():
    """Is Ollama running? (to degrade gracefully if not)."""
    try:
        return _S.get(f'{OLLAMA}/api/tags', timeout=3).ok
    except Exception:
        return False


def ask(prompt, sistema=None, max_tokens=300, temp=0.4, modelo=None):
    """The ONLY function that talks to the AI. Returns text (or raises if Ollama
    does not respond -- the caller decides how to degrade).

    If OBSIDIAN_NEXO is active (and `modelo` is not forced), it routes to the best
    local model for the task (step 168), without touching the callers."""
    m = modelo or (pick_model(f'{sistema or ""} {prompt}') if NEXO else MODELO)
    mensajes = ([{'role': 'system', 'content': sistema}] if sistema else [])
    mensajes.append({'role': 'user', 'content': prompt})
    r = _S.post(f'{OLLAMA}/api/chat', json={
        'model': m,
        'messages': mensajes,
        'stream': False,
        'options': {'num_ctx': 2048, 'num_predict': max_tokens, 'temperature': temp},
    }, timeout=(10, 120))
    return (r.json().get('message', {}) or {}).get('content', '').strip()
