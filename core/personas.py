"""Sock puppet vault -- F13 step 152.

Manages non-attributable research personas (fake identities an OSINT investigator
uses to avoid exposing themselves). Stores name, email, username, notes... in a
local JSON. These are NOT secret credentials (that's core/boveda.py, encrypted);
they are working identities, hence stored in the clear but outside the repo.

PURE module."""
from __future__ import annotations
import datetime
import json
import os


class PersonaManager:
    def __init__(self, ruta: str):
        self.ruta = ruta

    def _leer(self) -> dict:
        try:
            with open(self.ruta, encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _escribir(self, d: dict):
        os.makedirs(os.path.dirname(self.ruta), exist_ok=True)
        with open(self.ruta, 'w', encoding='utf-8') as f:
            json.dump(d, f, indent=2, ensure_ascii=False)

    def create(self, nombre: str, datos: dict) -> str:
        d = self._leer()
        d[nombre] = {**(datos or {}),
                     'creada': datetime.datetime.now().isoformat(timespec='seconds')}
        self._escribir(d)
        return nombre

    def listar(self) -> list:
        return sorted(self._leer().keys())

    def obtener(self, nombre: str):
        return self._leer().get(nombre)

    def borrar(self, nombre: str) -> bool:
        d = self._leer()
        if nombre in d:
            del d[nombre]
            self._escribir(d)
            return True
        return False
