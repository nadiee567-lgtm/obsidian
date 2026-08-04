"""Capa de IA ÚNICA de OBSIDIAN — una sola "cabeza" que todos los features usan.

En vez de regar llamadas a Ollama por el código (resumen, verificador, futura
extracción de entidades, traducción, chat...), TODO pasa por aquí. Una sola
puerta: cambiar de modelo o apuntar a NEXO (router) se hace en UN solo lugar.

Es UN modelo local (Ollama), no varios. Local = sin costo por token (corre en
la GPU del usuario); el único costo es tiempo de cómputo.

Módulo PURO: su propio cliente HTTP, no depende de Flask."""
import os
import requests

OLLAMA = os.environ.get('OBSIDIAN_OLLAMA', 'http://localhost:11434')
MODELO = os.environ.get('OBSIDIAN_MODELO_IA', 'qwen2.5:3b')

_S = requests.Session()


def disponible():
    """¿Está corriendo Ollama? (para degradar con gracia si no)."""
    try:
        return _S.get(f'{OLLAMA}/api/tags', timeout=3).ok
    except Exception:
        return False


def consultar(prompt, sistema=None, max_tokens=300, temp=0.4):
    """La ÚNICA función que habla con la IA. Devuelve texto (o lanza si Ollama
    no responde — el llamador decide cómo degradar).

    Aquí, a futuro, se puede enrutar a NEXO para elegir el mejor modelo local
    según la tarea, sin tocar a los que la llaman."""
    mensajes = ([{'role': 'system', 'content': sistema}] if sistema else [])
    mensajes.append({'role': 'user', 'content': prompt})
    r = _S.post(f'{OLLAMA}/api/chat', json={
        'model': MODELO,
        'messages': mensajes,
        'stream': False,
        'options': {'num_ctx': 2048, 'num_predict': max_tokens, 'temperature': temp},
    }, timeout=(10, 120))
    return (r.json().get('message', {}) or {}).get('content', '').strip()
