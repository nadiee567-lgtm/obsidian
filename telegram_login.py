#!/usr/bin/env python3
"""Interactive Telegram login for OBSIDIAN -- F10 step 130.

Run ONCE to create the session used by the 'telegram' transform. It asks for your
phone and the code you receive. You need api_id:api_hash (free at
https://my.telegram.org -> API development tools).

Usage:
    OBSIDIAN_API_ID=12345 OBSIDIAN_API_HASH=abc... python telegram_login.py
or, if you already saved 'telegram' = 'api_id:api_hash' in OBSIDIAN's vault, it is
read from there automatically.

The session is saved to ~/.obsidian/telegram.session (local, yours, not uploaded anywhere).
"""
import os

from core.config import HOME
try:
    from core.boveda import Vault
except Exception:
    Vault = None

SESION = os.path.join(HOME, '.obsidian', 'telegram.session')


def _cred():
    api_id = os.environ.get('OBSIDIAN_API_ID', '')
    api_hash = os.environ.get('OBSIDIAN_API_HASH', '')
    if api_id and api_hash:
        return api_id, api_hash
    if Vault is not None:
        try:
            cred = Vault(os.path.join(HOME, '.obsidian')).obtener('telegram') or ''
            if ':' in cred:
                a, b = cred.split(':', 1)
                return a, b
        except Exception:
            pass
    return None, None


def main():
    api_id, api_hash = _cred()
    if not api_id or not api_hash:
        print("Missing api_id/api_hash. Get them at https://my.telegram.org and run:\n"
              "  OBSIDIAN_API_ID=... OBSIDIAN_API_HASH=... python telegram_login.py")
        return 1
    from telethon.sync import TelegramClient
    os.makedirs(os.path.dirname(SESION), exist_ok=True)
    with TelegramClient(SESION, int(api_id), api_hash) as cli:
        cli.start()   # asks for phone + code interactively
        yo = cli.get_me()
        print(f"✓ Session created for @{getattr(yo, 'username', None) or yo.id}")
        print(f"  Saved to {SESION}. You can now use the 'telegram' transform in OBSIDIAN.")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
