"""Bóveda de API keys cifrada — F3 paso 51.

Cifra las keys con Fernet (AES-128, el estándar de `cryptography`). La clave
maestra vive en un archivo local con permisos 0600; el archivo cifrado
(vault.enc) es inútil sin ella. Los valores NUNCA se exponen — solo se listan
los nombres de servicio. Nada de cifrado casero.

Módulo PURO (sin Flask). Clase parametrizada por directorio, para poder testear."""
import os
import json

from cryptography.fernet import Fernet


class Boveda:
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
            return {}   # clave equivocada o archivo corrupto → vacío, no crashea

    def _escribir(self, d):
        token = self._fernet().encrypt(json.dumps(d).encode())
        with open(self.enc_file, 'wb') as f:
            f.write(token)
        os.chmod(self.enc_file, 0o600)

    # -- API pública --
    def guardar(self, servicio, valor):
        d = self._leer()
        d[servicio] = valor
        self._escribir(d)

    def obtener(self, servicio):
        return self._leer().get(servicio)

    def servicios(self):
        """Solo los NOMBRES de servicio configurados — nunca los valores."""
        return sorted(self._leer().keys())

    def borrar(self, servicio):
        d = self._leer()
        if servicio in d:
            del d[servicio]
            self._escribir(d)
            return True
        return False
