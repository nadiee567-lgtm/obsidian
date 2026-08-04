#!/usr/bin/env python3
"""OBSIDIAN CLI — F7 paso 98.

Todo lo del motor web, scriptable desde la terminal: correr transforms, hacer
recon automático, correlacionar riesgos, generar reporte y exportar — sobre los
mismos workspaces persistentes que la UI.

Importar obsidian_web registra TODOS los transforms en REGISTRO (viven ahí) sin
levantar el servidor. El CLI usa el core directamente (Almacen, transforms,
reporte, exportar, workspaces) — cero duplicación de lógica.

Ejemplos:
    obsidian_cli.py transforms dominio
    obsidian_cli.py run dominio github.com dns_a
    obsidian_cli.py recon dominio github.com -w investigacion-1
    obsidian_cli.py report -w investigacion-1 -o reporte.html
    obsidian_cli.py export json -w investigacion-1 -o caso.json
    obsidian_cli.py workspaces
"""
import argparse
import os
import sys

import obsidian_web as _ob   # registra los transforms (no arranca Flask)
from core.modelo import Almacen, tipo_valido
from core.transforms import REGISTRO, ejecutar_por_nombre
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
        print(f"(sin transforms para tipo '{a.tipo}')")
        return 0
    for t in sorted(ts, key=lambda x: x.nombre):
        key = '  [requiere key]' if t.requiere_key else ''
        print(f"  {t.nombre:22} → {', '.join(t.salidas)}{key}")
    return 0


def cmd_run(a):
    if not tipo_valido(a.tipo):
        return _err(f"tipo inválido: {a.tipo}")
    alm = _almacen(a.workspace)
    try:
        semilla = alm.crear(a.tipo, a.valor)
        producidas = ejecutar_por_nombre(a.transform, semilla, alm)
    except (KeyError, ValueError) as e:
        return _err(str(e))
    _guardar(a.workspace, alm)
    print(f"✓ {a.transform} → +{len(producidas)} entidad(es) (total {len(alm)})")
    for e in producidas:
        print(f"    {e.tipo:12} {e.valor}")
    return 0


def cmd_recon(a):
    """Corre TODOS los transforms aplicables (sin key, salvo --con-keys) sobre la semilla."""
    if not tipo_valido(a.tipo):
        return _err(f"tipo inválido: {a.tipo}")
    alm = _almacen(a.workspace)
    semilla = alm.crear(a.tipo, a.valor)
    ts = [t for t in REGISTRO.aplicables(a.tipo) if a.con_keys or not t.requiere_key]
    print(f"recon sobre {a.tipo} {a.valor} — {len(ts)} transform(s)")
    for t in sorted(ts, key=lambda x: x.nombre):
        try:
            n = len(ejecutar_por_nombre(t.nombre, semilla, alm))
            print(f"  {t.nombre:22} +{n}")
        except Exception as e:
            print(f"  {t.nombre:22} ✗ {e}")
    _guardar(a.workspace, alm)
    h = correlacionar(alm)
    print(f"total: {len(alm)} entidades · {len(h)} hallazgo(s) · riesgo {score_riesgo(h)}/100")
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
        return _err("workspace vacío o inexistente")
    h = correlacionar(alm)
    html = generar_reporte(alm, h, score_riesgo(h),
                           meta={'workspace': a.workspace},
                           vis_js=None if a.sin_grafo else _vis_js())
    if a.output:
        with open(a.output, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"✓ reporte → {a.output} ({len(html)} bytes)")
    else:
        sys.stdout.write(html)
    return 0


def cmd_export(a):
    alm = _almacen(a.workspace)
    if not len(alm):
        return _err("workspace vacío o inexistente")
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
        print("(sin workspaces)")
    for w in ws:
        alm = _gestor.cargar(w)
        print(f"  {w:24} {len(alm)} entidad(es)")
    return 0


def construir_parser():
    p = argparse.ArgumentParser(prog='obsidian', description='OBSIDIAN — motor OSINT desde terminal')
    sub = p.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('transforms', help='lista transforms de un tipo')
    s.add_argument('tipo')
    s.set_defaults(fn=cmd_transforms)

    s = sub.add_parser('run', help='corre un transform')
    s.add_argument('tipo'); s.add_argument('valor'); s.add_argument('transform')
    s.add_argument('-w', '--workspace')
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser('recon', help='corre todos los transforms aplicables')
    s.add_argument('tipo'); s.add_argument('valor')
    s.add_argument('-w', '--workspace')
    s.add_argument('--con-keys', action='store_true', help='incluye transforms que requieren key')
    s.set_defaults(fn=cmd_recon)

    s = sub.add_parser('report', help='genera reporte HTML de un workspace')
    s.add_argument('-w', '--workspace', required=True)
    s.add_argument('-o', '--output')
    s.add_argument('--sin-grafo', action='store_true')
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser('export', help='exporta json/csv de un workspace')
    s.add_argument('formato', choices=['json', 'csv'])
    s.add_argument('-w', '--workspace', required=True)
    s.add_argument('-o', '--output')
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser('workspaces', help='lista los workspaces')
    s.set_defaults(fn=cmd_workspaces)
    return p


def main(argv=None):
    args = construir_parser().parse_args(argv)
    return args.fn(args)


if __name__ == '__main__':
    sys.exit(main())
