"""OBSIDIAN workspace (case) manager -- F3, steps 43-47.

recon-ng model: each investigation is a WORKSPACE with its own isolated SQLite
database. Here only the management (create/list/open/delete/rename); reading and
writing the typed model is done by core/persistencia.

Security: names go through _case_slug (anti path traversal) and every path is
verified to be contained in the workspaces directory. PURE module (no Flask)."""
import os
import glob
import shutil
import datetime

from core.modelo import Store
from core.persistencia import save_store, load_store, record_event, read_history
from core.validacion import _case_slug


class Manager:
    """Manages the workspaces inside a directory (one = one .db file)."""

    def __init__(self, directorio):
        self.dir = directorio
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, name):
        """Sanitized .db path contained in self.dir, or None if the name is invalid."""
        slug = _case_slug(name)
        if not slug:
            return None
        ruta = os.path.join(self.dir, slug + '.db')
        if not os.path.realpath(ruta).startswith(os.path.realpath(self.dir) + os.sep):
            return None
        return ruta

    def list_ws(self):
        return sorted(os.path.splitext(os.path.basename(p))[0]
                      for p in glob.glob(os.path.join(self.dir, '*.db')))

    def exists(self, name):
        r = self._path(name)
        return bool(r and os.path.exists(r))

    def create(self, name):
        """Creates an empty workspace (with its schema). Returns its Store."""
        r = self._path(name)
        if not r:
            raise ValueError('invalid workspace name')
        if os.path.exists(r):
            raise ValueError('a workspace with that name already exists')
        alm = Store()
        save_store(alm, r)   # creates the file + schema
        return alm

    def load(self, name):
        r = self._path(name)
        if not r or not os.path.exists(r):
            raise KeyError('workspace not found')
        return load_store(r)

    def save(self, name, almacen):
        r = self._path(name)
        if not r:
            raise ValueError('invalid workspace name')
        save_store(almacen, r)

    def delete(self, name):
        r = self._path(name)
        if r and os.path.exists(r):
            os.remove(r)
            return True
        return False

    def rename(self, viejo, nuevo):
        rv, rn = self._path(viejo), self._path(nuevo)
        if not rv or not os.path.exists(rv):
            raise KeyError('workspace not found')
        if not rn:
            raise ValueError('invalid new name')
        if os.path.exists(rn):
            raise ValueError('a workspace with the new name already exists')
        os.rename(rv, rn)

    # ── History / audit (step 48) ──
    def record(self, name, transform, input, outputs):
        r = self._path(name)
        if r and os.path.exists(r):
            record_event(r, transform, input, outputs)

    def history(self, name):
        r = self._path(name)
        return read_history(r) if (r and os.path.exists(r)) else []

    # ── Snapshots / versions (step 49) ──
    def _dir_snaps(self, name):
        slug = _case_slug(name)
        d = os.path.join(self.dir, '_snapshots', slug) if slug else None
        if d:
            os.makedirs(d, exist_ok=True)
        return d

    def snapshot(self, name):
        """Copies the case .db to a timestamped snapshot. Returns its id."""
        r = self._path(name)
        d = self._dir_snaps(name)
        if not r or not os.path.exists(r) or not d:
            raise KeyError('workspace not found')
        snap_id = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')  # us: unique ids
        shutil.copy2(r, os.path.join(d, snap_id + '.db'))
        return snap_id

    def list_snapshots(self, name):
        d = self._dir_snaps(name)
        if not d:
            return []
        return sorted((os.path.splitext(os.path.basename(p))[0]
                       for p in glob.glob(os.path.join(d, '*.db'))), reverse=True)

    def load_snapshot(self, name, snap_id):
        """Loads a snapshot's Store WITHOUT restoring it (for historical diff, step 151)."""
        d = self._dir_snaps(name)
        sid = _case_slug(snap_id)
        ruta = os.path.join(d, sid + '.db') if (d and sid) else None
        if not ruta or not os.path.exists(ruta):
            raise KeyError('snapshot not found')
        return load_store(ruta)

    def restore(self, name, snap_id):
        """Reverts the case to an earlier snapshot (snapshots the current one first)."""
        r = self._path(name)
        d = self._dir_snaps(name)
        if not r or not d:
            raise KeyError('workspace not found')
        source = os.path.join(d, _case_slug(snap_id) + '.db') if _case_slug(snap_id) else None
        if not source or not os.path.exists(source):
            raise KeyError('snapshot not found')
        if os.path.exists(r):
            self.snapshot(name)     # back up the current state before overwriting
        shutil.copy2(source, r)
