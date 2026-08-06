#!/usr/bin/env python3
"""OBSIDIAN CLI -- F7 step 98.

Everything the web engine does, scriptable from the terminal: run transforms, do
automatic recon, correlate risks, generate a report and export -- over the same
persistent workspaces as the UI.

Importing obsidian_web registers ALL transforms in REGISTRO (they live there)
without starting the server. The CLI uses the core directly (Almacen, transforms,
report, export, workspaces) -- zero logic duplication.

Examples:
    obsidian_cli.py transforms dominio
    obsidian_cli.py run dominio github.com dns_a
    obsidian_cli.py recon dominio github.com -w case-1
    obsidian_cli.py report -w case-1 -o report.html
    obsidian_cli.py export json -w case-1 -o case.json
    obsidian_cli.py workspaces
"""
import argparse
import os
import sys

import obsidian_web as _ob   # registers the transforms (does not start Flask)
from core.modelo import Almacen, tipo_valido
from core.transforms import REGISTRO, ejecutar_por_nombre, ejecutar_lote
from core.correlacion import correlacionar, score_riesgo
from core.reporte import generar_reporte
from core.exportar import exportar_json, exportar_csv
from core.workspaces import Gestor
from core.config import WORKSPACES_DIR, STATIC_DIR, VIS_FILE

_gestor = Gestor(WORKSPACES_DIR)


def _almacen(ws):
    if ws and _gestor.existe(ws):
        return _gestor.cargar(ws)
    return Almacen()


def _guardar(ws, alm):
    if ws:
        if not _gestor.existe(ws):
            _gestor.crear(ws)
        _gestor.guardar(ws, alm)


def _err(msg):
    print(f"error: {msg}", file=sys.stderr)
    return 1


def cmd_transforms(a):
    ts = REGISTRO.aplicables(a.tipo)
    if not ts:
        print(f"(no transforms for type '{a.tipo}')")
        return 0
    for t in sorted(ts, key=lambda x: x.nombre):
        key = '  [requires key]' if t.requiere_key else ''
        print(f"  {t.nombre:22} → {', '.join(t.salidas)}{key}")
    return 0


def cmd_run(a):
    if not tipo_valido(a.tipo):
        return _err(f"invalid type: {a.tipo}")
    alm = _almacen(a.workspace)
    try:
        semilla = alm.crear(a.tipo, a.valor)
        producidas = ejecutar_por_nombre(a.transform, semilla, alm)
    except (KeyError, ValueError) as e:
        return _err(str(e))
    _guardar(a.workspace, alm)
    print(f"✓ {a.transform} → +{len(producidas)} entity(ies) (total {len(alm)})")
    for e in producidas:
        print(f"    {e.tipo:12} {e.valor}")
    return 0


def cmd_recon(a):
    """Runs ALL applicable transforms IN PARALLEL (keyless, unless --with-keys)."""
    import time
    if not tipo_valido(a.tipo):
        return _err(f"invalid type: {a.tipo}")
    alm = _almacen(a.workspace)
    alm.crear(a.tipo, a.valor)
    ts = [t for t in REGISTRO.aplicables(a.tipo) if a.with_keys or not t.requiere_key]
    tareas = [(a.tipo, a.valor, t.nombre) for t in ts]
    print(f"recon on {a.tipo} {a.valor} -- {len(tareas)} transform(s) in parallel")
    t0 = time.time()
    for nombre, n in sorted(ejecutar_lote(tareas, alm)):
        print(f"  {nombre:22} +{n}")
    _guardar(a.workspace, alm)
    h = correlacionar(alm)
    print(f"total: {len(alm)} entities · {len(h)} finding(s) · "
          f"risk {score_riesgo(h)}/100 · {time.time() - t0:.1f}s")
    return 0


def _vis_js():
    ruta = os.path.join(STATIC_DIR, VIS_FILE)
    if os.path.exists(ruta):
        with open(ruta, encoding='utf-8') as f:
            return f.read()
    return None


def cmd_report(a):
    alm = _almacen(a.workspace)
    if not len(alm):
        return _err("empty or nonexistent workspace")
    h = correlacionar(alm)
    html = generar_reporte(alm, h, score_riesgo(h),
                           meta={'workspace': a.workspace},
                           vis_js=None if a.no_graph else _vis_js())
    if a.output:
        with open(a.output, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"✓ report → {a.output} ({len(html)} bytes)")
    else:
        sys.stdout.write(html)
    return 0


def cmd_export(a):
    alm = _almacen(a.workspace)
    if not len(alm):
        return _err("empty or nonexistent workspace")
    if a.formato == 'json':
        h = correlacionar(alm)
        data = exportar_json(alm, h, score_riesgo(h), {'workspace': a.workspace})
    else:
        data = exportar_csv(alm)
    if a.output:
        with open(a.output, 'w', encoding='utf-8') as f:
            f.write(data)
        print(f"✓ export {a.formato} → {a.output}")
    else:
        sys.stdout.write(data)
    return 0


def cmd_workspaces(a):
    ws = _gestor.listar()
    if not ws:
        print("(no workspaces)")
    for w in ws:
        alm = _gestor.cargar(w)
        print(f"  {w:24} {len(alm)} entity(ies)")
    return 0


def construir_parser():
    p = argparse.ArgumentParser(prog='obsidian', description='OBSIDIAN -- OSINT engine from the terminal')
    sub = p.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('transforms', help='list transforms of a type')
    s.add_argument('tipo')
    s.set_defaults(fn=cmd_transforms)

    s = sub.add_parser('run', help='run a transform')
    s.add_argument('tipo'); s.add_argument('valor'); s.add_argument('transform')
    s.add_argument('-w', '--workspace')
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser('recon', help='run all applicable transforms')
    s.add_argument('tipo'); s.add_argument('valor')
    s.add_argument('-w', '--workspace')
    s.add_argument('--with-keys', action='store_true', help='include transforms that require a key')
    s.set_defaults(fn=cmd_recon)

    s = sub.add_parser('report', help='generate HTML report of a workspace')
    s.add_argument('-w', '--workspace', required=True)
    s.add_argument('-o', '--output')
    s.add_argument('--no-graph', action='store_true')
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser('export', help='export json/csv of a workspace')
    s.add_argument('formato', choices=['json', 'csv'])
    s.add_argument('-w', '--workspace', required=True)
    s.add_argument('-o', '--output')
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser('workspaces', help='list the workspaces')
    s.set_defaults(fn=cmd_workspaces)
    return p


def main(argv=None):
    args = construir_parser().parse_args(argv)
    return args.fn(args)


if __name__ == '__main__':
    sys.exit(main())
