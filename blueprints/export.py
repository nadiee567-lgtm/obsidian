"""Case export endpoints: JSON / CSV / Obsidian notes vault.

First Flask blueprint split out of the obsidian_web.py monolith. Shared mutable
state (_store, _ws_activo) is read from obsidian_web *at request time* via the
module object, so it always reflects the current case even when a global is
rebound elsewhere (e.g. opening a workspace)."""
from __future__ import annotations
import io
import zipfile
import datetime

from flask import Blueprint, Response

from core.correlacion import correlate, risk_score
from core.exportar import export_json, export_csv, export_obsidian_vault
from core.validacion import _case_slug
import obsidian_web as W

bp = Blueprint('export', __name__)


def _export_name() -> str:
    base = _case_slug(W._ws_activo) if W._ws_activo else 'caso'
    return f'obsidian-{base}-{datetime.datetime.now():%Y%m%d}'


@bp.route('/api/v2/export/json')
def export_json_route():
    """Full case in JSON, re-importable (F7 step 94)."""
    h = correlate(W._store)
    data = export_json(W._store, h, risk_score(h),
                       {'workspace': W._ws_activo, 'target': W._target_of_store()})
    return Response(data, mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename="{_export_name()}.json"'})


@bp.route('/api/v2/export/csv')
def export_csv_route():
    """Entities as flat CSV, sanitized against formula injection (F7 step 94)."""
    data = export_csv(W._store)
    return Response(data, mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename="{_export_name()}.csv"'})


@bp.route('/api/v2/export/obsidian')
def export_obsidian_route():
    """Case as an Obsidian notes vault (entities as notes, relations as [[wikilinks]]),
    delivered as a .zip. Unzip into the Obsidian app and the graph rebuilds the case."""
    h = correlate(W._store)
    files = export_obsidian_vault(W._store, h, risk_score(h),
                                  {'workspace': W._ws_activo, 'target': W._target_of_store()})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for rel, content in files.items():
            z.writestr(rel, content)
    return Response(buf.getvalue(), mimetype='application/zip',
                    headers={'Content-Disposition': f'attachment; filename="{_export_name()}-notes.zip"'})
