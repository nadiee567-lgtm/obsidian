"""Minimal Metasploit RPC (msfrpcd) client over MessagePack — for the OBSIDIAN
Metasploit console GUI.

msfrpcd speaks MessagePack over HTTP at /api/. We talk to it directly (no heavy
third-party lib): auth.login to get a token, then console.* to drive a real
msfconsole remotely.

SECURITY: this drives Metasploit — an exploitation framework. The web layer gates
it to a loopback bind + the app login, and it only works once the operator has
started msfrpcd and set its password. Use ONLY against authorized targets.
"""
from __future__ import annotations
import msgpack
import requests

_S = requests.Session()


def _d(v):
    """Decode msgpack bytes -> str recursively (msfrpcd returns bytes)."""
    if isinstance(v, bytes):
        try:
            return v.decode('utf-8', 'replace')
        except Exception:
            return v
    if isinstance(v, dict):
        return {_d(k): _d(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_d(x) for x in v]
    return v


class MsfRpc:
    def __init__(self, host='127.0.0.1', port=55553, password='', user='msf', ssl=True):
        self.url = f"{'https' if ssl else 'http'}://{host}:{port}/api/"
        self.user, self.password = user, password
        self.token = None

    def _call(self, method, *args, auth=True, timeout=20):
        payload = [method]
        if auth and self.token:
            payload.append(self.token)
        payload += list(args)
        r = _S.post(self.url, data=msgpack.packb(payload, use_bin_type=True),
                    headers={'Content-Type': 'binary/message-pack'},
                    timeout=timeout, verify=False)
        return _d(msgpack.unpackb(r.content, raw=True))

    def login(self):
        res = self._call('auth.login', self.user, self.password, auth=False)
        if isinstance(res, dict) and res.get('result') == 'success':
            self.token = res.get('token')
            return True
        return False

    def _ensure(self):
        if not self.token and not self.login():
            raise RuntimeError('msfrpcd auth failed (check password)')

    def version(self):
        self._ensure()
        return self._call('core.version')

    def module_stats(self):
        self._ensure()
        try:
            return self._call('module.count') if False else {
                'exploits': len((self._call('module.exploits') or {}).get('modules', [])),
                'auxiliary': len((self._call('module.auxiliary') or {}).get('modules', [])),
                'payloads': len((self._call('module.payloads') or {}).get('modules', [])),
            }
        except Exception:
            return {}

    def console_create(self):
        self._ensure()
        return self._call('console.create')  # -> {'id':'0','prompt':...,'busy':...}

    def console_write(self, cid, data):
        self._ensure()
        if not data.endswith('\n'):
            data += '\n'
        return self._call('console.write', str(cid), data)

    def console_read(self, cid):
        self._ensure()
        return self._call('console.read', str(cid))  # -> {'data':..,'prompt':..,'busy':bool}

    def console_list(self):
        self._ensure()
        return self._call('console.list')

    def console_destroy(self, cid):
        self._ensure()
        return self._call('console.destroy', str(cid))
