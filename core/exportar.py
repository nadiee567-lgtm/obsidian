"""Exportadores de datos de OBSIDIAN — F7 paso 94.

Deja el caso en formatos estructurados para importar en otras herramientas:
  - JSON: el caso completo (entidades + relaciones + hallazgos + meta), máquina.
  - CSV:  una fila por entidad, para hojas de cálculo / otras tools.

Módulo PURO: no toca Flask ni red.

Seguridad: el CSV neutraliza INYECCIÓN DE FÓRMULAS (CSV injection). Un valor de
OSINT crudo que empiece con = + - @ (o tab/CR) se interpreta como fórmula al
abrir el archivo en Excel/Sheets → se le antepone un apóstrofo. Es el análogo del
escape anti-XSS del reporte: los datos del objetivo no son de confianza."""
from __future__ import annotations
import csv
import io
import json
import datetime

_PELIGRO = ('=', '+', '-', '@')   # inicios que Excel/Sheets tratan como fórmula


def _celda(v) -> str:
    """Neutraliza inyección de fórmulas en una celda CSV."""
    s = '' if v is None else str(v)
    if s and (s[0] in _PELIGRO or s[0] in ('\t', '\r')):
        s = "'" + s
    return s


def exportar_json(almacen, hallazgos=None, score=0, meta=None) -> str:
    """Caso completo en JSON, re-importable con Almacen.from_dict()."""
    meta = dict(meta or {})
    meta.setdefault('generado', datetime.datetime.now().isoformat(timespec='seconds'))
    d = almacen.to_dict()
    d['meta'] = meta
    d['score'] = int(score)
    d['hallazgos'] = [h.to_dict() for h in (hallazgos or [])]
    return json.dumps(d, ensure_ascii=False, indent=2)


def exportar_csv(almacen) -> str:
    """Una fila por entidad. Celdas saneadas contra inyección de fórmulas."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['tipo', 'valor', 'tags', 'fuentes', 'confianza', 'propiedades'])
    for e in sorted(almacen.entidades, key=lambda x: (x.tipo, x.valor)):
        props = '; '.join(f'{k}={v}' for k, v in (e.propiedades or {}).items())
        w.writerow([_celda(e.tipo), _celda(e.valor), _celda(' '.join(sorted(e.tags))),
                    _celda(' '.join(sorted(e.origenes))),
                    _celda(getattr(e, 'confianza', 1.0)), _celda(props)])
    return buf.getvalue()
