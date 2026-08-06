"""Encrypted API key vault -- F3 step 51.

Encrypts keys with Fernet (AES-128, the `cryptography` standard). The master key
lives in a local file with 0600 permissions; the encrypted file (vault.enc) is
useless without it. Values are NEVER exposed -- only service names are listed.
No home-made crypto.

PURE module (no Flask). Class parameterized by directory, so it's testable."""
import os
import json

from cryptography.fernet import Fernet


class Vault:
    def __init__(self, directorio):
        self.dir = directorio
        os.makedirs(self.dir, exist_ok=True)
        self.key_file = os.path.join(self.dir, 'vault.key')
        self.enc_file = os.path.join(self.dir, 'vault.enc')

    def _fernet(self):
        if not os.path.exists(self.key_file):
            with open(self.key_file, 'wb') as f:
                f.write(Fernet.generate_key())
            os.chmod(self.key_file, 0o600)
        with open(self.key_file, 'rb') as f:
            return Fernet(f.read())

    def _leer(self):
        if not os.path.exists(self.enc_file):
            return {}
        try:
            with open(self.enc_file, 'rb') as f:
                return json.loads(self._fernet().decrypt(f.read()).decode())
        except Exception:
            return {}   # wrong key or corrupt file -> empty, does not crash

    def _escribir(self, d):
        token = self._fernet().encrypt(json.dumps(d).encode())
        with open(self.enc_file, 'wb') as f:
            f.write(token)
        os.chmod(self.enc_file, 0o600)

    # -- public API --
    def save(self, service, value):
        d = self._leer()
        d[service] = value
        self._escribir(d)

    def get(self, service):
        return self._leer().get(service)

    def servicios(self):
        """Only the configured service NAMES -- never the values."""
        return sorted(self._leer().keys())

    def delete(self, service):
        d = self._leer()
        if service in d:
            del d[service]
            self._escribir(d)
            return True
        return False
