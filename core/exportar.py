"""OBSIDIAN data exporters -- F7 step 94.

Leaves the case in structured formats to import into other tools:
  - JSON: the full case (entities + relations + findings + meta), machine-readable.
  - CSV:  one row per entity, for spreadsheets / other tools.

PURE module: does not touch Flask or the network.

Security: the CSV neutralizes FORMULA INJECTION (CSV injection). A raw OSINT value
starting with = + - @ (or tab/CR) is interpreted as a formula when the file is
opened in Excel/Sheets -> an apostrophe is prepended. It is the analogue of the
report's anti-XSS escaping: the target's data is untrusted."""
from __future__ import annotations
import csv
import io
import json
import datetime

_PELIGRO = ('=', '+', '-', '@')   # starts Excel/Sheets treat as a formula


def _celda(v) -> str:
    """Neutralizes formula injection in a CSV cell."""
    s = '' if v is None else str(v)
    if s and (s[0] in _PELIGRO or s[0] in ('\t', '\r')):
        s = "'" + s
    return s


def exportar_json(almacen, hallazgos=None, score=0, meta=None) -> str:
    """Full case in JSON, re-importable with Store.from_dict()."""
    meta = dict(meta or {})
    meta.setdefault('generado', datetime.datetime.now().isoformat(timespec='seconds'))
    d = almacen.to_dict()
    d['meta'] = meta
    d['score'] = int(score)
    d['hallazgos'] = [h.to_dict() for h in (hallazgos or [])]
    return json.dumps(d, ensure_ascii=False, indent=2)


def exportar_csv(almacen) -> str:
    """One row per entity. Cells sanitized against formula injection."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['type', 'value', 'tags', 'sources', 'confidence', 'properties'])
    for e in sorted(almacen.entities, key=lambda x: (x.type, x.value)):
        props = '; '.join(f'{k}={v}' for k, v in (e.properties or {}).items())
        w.writerow([_celda(e.type), _celda(e.value), _celda(' '.join(sorted(e.tags))),
                    _celda(' '.join(sorted(e.sources))),
                    _celda(getattr(e, 'confidence', 1.0)), _celda(props)])
    return buf.getvalue()
