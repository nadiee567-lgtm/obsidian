"""OBSIDIAN workspace (case) manager -- F3, steps 43-47.

recon-ng model: each investigation is a WORKSPACE with its own isolated SQLite
database. Here only the management (create/list/open/delete/rename); reading and
writing the typed model is done by core/persistencia.

Security: names go through _slug_caso (anti path traversal) and every path is
verified to be contained in the workspaces directory. PURE module (no Flask)."""
import os
import glob
import shutil
import datetime

from core.modelo import Store
from core.persistencia import guardar_almacen, cargar_almacen, registrar_evento, leer_historial
from core.validacion import _slug_caso


class Gestor:
    """Manages the workspaces inside a directory (one = one .db file)."""

    def __init__(self, directorio):
        self.dir = directorio
        os.makedirs(self.dir, exist_ok=True)

    def _ruta(self, nombre):
        """Sanitized .db path contained in self.dir, or None if the name is invalid."""
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
        """Creates an empty workspace (with its schema). Returns its Store."""
        r = self._ruta(nombre)
        if not r:
            raise ValueError('invalid workspace name')
        if os.path.exists(r):
            raise ValueError('a workspace with that name already exists')
        alm = Store()
        guardar_almacen(alm, r)   # creates the file + schema
        return alm

    def cargar(self, nombre):
        r = self._ruta(nombre)
        if not r or not os.path.exists(r):
            raise KeyError('workspace not found')
        return cargar_almacen(r)

    def guardar(self, nombre, almacen):
        r = self._ruta(nombre)
        if not r:
            raise ValueError('invalid workspace name')
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
            raise KeyError('workspace not found')
        if not rn:
            raise ValueError('invalid new name')
        if os.path.exists(rn):
            raise ValueError('a workspace with the new name already exists')
        os.rename(rv, rn)

    # ── History / audit (step 48) ──
    def registrar(self, nombre, transform, entrada, salidas):
        r = self._ruta(nombre)
        if r and os.path.exists(r):
            registrar_evento(r, transform, entrada, salidas)

    def historial(self, nombre):
        r = self._ruta(nombre)
        return leer_historial(r) if (r and os.path.exists(r)) else []

    # ── Snapshots / versions (step 49) ──
    def _dir_snaps(self, nombre):
        slug = _slug_caso(nombre)
        d = os.path.join(self.dir, '_snapshots', slug) if slug else None
        if d:
            os.makedirs(d, exist_ok=True)
        return d

    def snapshot(self, nombre):
        """Copies the case .db to a timestamped snapshot. Returns its id."""
        r = self._ruta(nombre)
        d = self._dir_snaps(nombre)
        if not r or not os.path.exists(r) or not d:
            raise KeyError('workspace not found')
        snap_id = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')  # us: unique ids
        shutil.copy2(r, os.path.join(d, snap_id + '.db'))
        return snap_id

    def listar_snapshots(self, nombre):
        d = self._dir_snaps(nombre)
        if not d:
            return []
        return sorted((os.path.splitext(os.path.basename(p))[0]
                       for p in glob.glob(os.path.join(d, '*.db'))), reverse=True)

    def cargar_snapshot(self, nombre, snap_id):
        """Loads a snapshot's Store WITHOUT restoring it (for historical diff, step 151)."""
        d = self._dir_snaps(nombre)
        sid = _slug_caso(snap_id)
        ruta = os.path.join(d, sid + '.db') if (d and sid) else None
        if not ruta or not os.path.exists(ruta):
            raise KeyError('snapshot not found')
        return cargar_almacen(ruta)

    def restaurar(self, nombre, snap_id):
        """Reverts the case to an earlier snapshot (snapshots the current one first)."""
        r = self._ruta(nombre)
        d = self._dir_snaps(nombre)
        if not r or not d:
            raise KeyError('workspace not found')
        origen = os.path.join(d, _slug_caso(snap_id) + '.db') if _slug_caso(snap_id) else None
        if not origen or not os.path.exists(origen):
            raise KeyError('snapshot not found')
        if os.path.exists(r):
            self.snapshot(nombre)     # back up the current state before overwriting
        shutil.copy2(origen, r)
