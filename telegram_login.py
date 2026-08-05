#!/usr/bin/env python3
"""Login interactivo de Telegram para OBSIDIAN — F10 paso 130.

Se corre UNA vez para crear la sesión que usa el transform 'telegram'. Pide tu
teléfono y el código que te llega. Necesitas api_id:api_hash (gratis en
https://my.telegram.org → API development tools).

Uso:
    OBSIDIAN_API_ID=12345 OBSIDIAN_API_HASH=abc... python telegram_login.py
o, si ya guardaste 'telegram' = 'api_id:api_hash' en la bóveda de OBSIDIAN, se lee
de ahí automáticamente.

La sesión se guarda en ~/.obsidian/telegram.session (local, tuya, no se sube a nada).
"""
import os

from core.config import HOME
try:
    from core.boveda import Boveda
except Exception:
    Boveda = None

SESION = os.path.join(HOME, '.obsidian', 'telegram.session')


def _cred():
    api_id = os.environ.get('OBSIDIAN_API_ID', '')
    api_hash = os.environ.get('OBSIDIAN_API_HASH', '')
    if api_id and api_hash:
        return api_id, api_hash
    if Boveda is not None:
        try:
            cred = Boveda(os.path.join(HOME, '.obsidian')).obtener('telegram') or ''
            if ':' in cred:
                a, b = cred.split(':', 1)
                return a, b
        except Exception:
            pass
    return None, None


def main():
    api_id, api_hash = _cred()
    if not api_id or not api_hash:
        print("Falta api_id/api_hash. Sácalos en https://my.telegram.org y corre:\n"
              "  OBSIDIAN_API_ID=... OBSIDIAN_API_HASH=... python telegram_login.py")
        return 1
    from telethon.sync import TelegramClient
    os.makedirs(os.path.dirname(SESION), exist_ok=True)
    with TelegramClient(SESION, int(api_id), api_hash) as cli:
        cli.start()   # pide teléfono + código de forma interactiva
        yo = cli.get_me()
        print(f"✓ Sesión creada para @{getattr(yo, 'username', None) or yo.id}")
        print(f"  Guardada en {SESION}. Ya puedes usar el transform 'telegram' en OBSIDIAN.")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
