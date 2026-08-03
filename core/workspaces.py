"""Gestor de workspaces (casos) de OBSIDIAN — F3, pasos 43-47.

Modelo de recon-ng: cada investigación es un WORKSPACE con su propia base SQLite
aislada. Aquí solo la gestión (crear/listar/abrir/borrar/renombrar); la lectura
y escritura del modelo tipado la hace core/persistencia.

Seguridad: los nombres pasan por _slug_caso (anti path traversal) y toda ruta se
verifica contenida en el directorio de workspaces. Módulo PURO (sin Flask)."""
import os
import glob

from core.modelo import Almacen
from core.persistencia import guardar_almacen, cargar_almacen
from core.validacion import _slug_caso


class Gestor:
    """Administra los workspaces dentro de un directorio (uno = un archivo .db)."""

    def __init__(self, directorio):
        self.dir = directorio
        os.makedirs(self.dir, exist_ok=True)

    def _ruta(self, nombre):
        """Ruta .db saneada y contenida en self.dir, o None si el nombre es inválido."""
        slug = _slug_caso(nombre)
        if not slug:
            return None
        ruta = os.path.join(self.dir, slug + '.db')
        if not os.path.realpath(ruta).startswith(os.path.realpath(self.dir) + os.sep):
            return None
        return ruta

    def listar(self):
        return sorted(os.path.splitext(os.path.basename(p))[0]
                      for p in glob.glob(os.path.join(self.dir, '*.db')))

    def existe(self, nombre):
        r = self._ruta(nombre)
        return bool(r and os.path.exists(r))

    def crear(self, nombre):
        """Crea un workspace vacío (con su esquema). Devuelve su Almacen."""
        r = self._ruta(nombre)
        if not r:
            raise ValueError('nombre de workspace inválido')
        if os.path.exists(r):
            raise ValueError('ya existe un workspace con ese nombre')
        alm = Almacen()
        guardar_almacen(alm, r)   # crea el archivo + esquema
        return alm

    def cargar(self, nombre):
        r = self._ruta(nombre)
        if not r or not os.path.exists(r):
            raise KeyError('workspace no encontrado')
        return cargar_almacen(r)

    def guardar(self, nombre, almacen):
        r = self._ruta(nombre)
        if not r:
            raise ValueError('nombre de workspace inválido')
        guardar_almacen(almacen, r)

    def borrar(self, nombre):
        r = self._ruta(nombre)
        if r and os.path.exists(r):
            os.remove(r)
            return True
        return False

    def renombrar(self, viejo, nuevo):
        rv, rn = self._ruta(viejo), self._ruta(nuevo)
        if not rv or not os.path.exists(rv):
            raise KeyError('workspace no encontrado')
        if not rn:
            raise ValueError('nombre nuevo inválido')
        if os.path.exists(rn):
            raise ValueError('ya existe un workspace con el nombre nuevo')
        os.rename(rv, rn)
