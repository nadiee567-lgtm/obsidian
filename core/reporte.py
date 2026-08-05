"""OBSIDIAN HTML report generator -- F7 step 93.

Takes a Store (typed model) + correlation findings and produces a SELF-CONTAINED
HTML report: risk summary, findings ordered by severity, entity inventory by type,
and the embedded graph (vis-network inline, no CDN).

PURE module: no Flask, no network. EVERY dynamic value (raw target data) goes
through html.escape -> same anti-XSS care as the rest of OBSIDIAN; a report also
opens in a browser."""
from __future__ import annotations
import html
import json
import datetime

from core.modelo import TIPOS

_SEV_COLOR = {'critico': '#f38ba8', 'alto': '#fab387', 'medio': '#f9e2af', 'bajo': '#89b4fa'}  # Catppuccin Mocha
_SEV_ORDEN = {'critico': 4, 'alto': 3, 'medio': 2, 'bajo': 1}


def _e(v) -> str:
    """Escapes any target data before putting it into the HTML."""
    return html.escape(str(v), quote=True)


def _resumen_severidad(hallazgos) -> dict:
    conteo = {'critico': 0, 'alto': 0, 'medio': 0, 'bajo': 0}
    for h in hallazgos:
        sev = getattr(h, 'severidad', None)
        if sev in conteo:
            conteo[sev] += 1
    return conteo


def _grafo_data(almacen) -> tuple:
    """Nodes/edges for vis-network, with the same per-type color as /v2."""
    nodos, aristas = [], []
    for e in almacen.entidades:
        color = TIPOS.get(e.tipo, {}).get('color', '#8b8b98')
        nodos.append({'id': e.id, 'label': e.valor, 'color': color, 'shape': 'dot',
                      'group': e.tipo})
    for r in almacen.relaciones:
        aristas.append({'from': r.origen, 'to': r.destino, 'label': r.etiqueta})
    return nodos, aristas


def generar_reporte(almacen, hallazgos=None, score=0, meta=None, vis_js=None) -> str:
    """Returns the full report HTML.

    almacen   -- typed Store (source of entities/relations)
    hallazgos -- list of Hallazgo from correlacion.correlacionar() (or None)
    score     -- risk score 0-100 (correlacion.score_riesgo)
    meta      -- {'workspace','objetivo','generado'} optional
    vis_js    -- vis-network.min.js content to embed (or None: no graph)
    """
    hallazgos = list(hallazgos or [])
    hallazgos.sort(key=lambda h: -_SEV_ORDEN.get(getattr(h, 'severidad', ''), 0))
    meta = meta or {}
    generado = meta.get('generado') or datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    ws = meta.get('workspace') or 'ephemeral'
    objetivo = meta.get('objetivo') or '—'
    conteo = _resumen_severidad(hallazgos)

    # ── score bar colored by level ──
    if score >= 70:   score_col = _SEV_COLOR['critico']
    elif score >= 40: score_col = _SEV_COLOR['alto']
    elif score >= 15: score_col = _SEV_COLOR['medio']
    else:             score_col = _SEV_COLOR['bajo']

    # ── findings ──
    if hallazgos:
        filas = []
        for h in hallazgos:
            sev = getattr(h, 'severidad', 'bajo')
            col = _SEV_COLOR.get(sev, '#8b8b98')
            n_ent = len(getattr(h, 'entidades', []) or [])
            filas.append(
                f'<tr><td><span class="sev" style="background:{col}">{_e(sev)}</span></td>'
                f'<td class="regla">{_e(getattr(h, "regla", ""))}</td>'
                f'<td>{_e(getattr(h, "mensaje", ""))}</td>'
                f'<td class="num">{n_ent}</td></tr>')
        hallazgos_html = (
            '<table class="hallazgos"><thead><tr><th>Severity</th><th>Rule</th>'
            '<th>Detail</th><th>Entities</th></tr></thead><tbody>'
            + ''.join(filas) + '</tbody></table>')
    else:
        hallazgos_html = '<p class="vacio">No risks detected by the correlation engine.</p>'

    # ── entity inventory by type ──
    bloques = []
    for tipo, info in TIPOS.items():
        ents = almacen.de_tipo(tipo)
        if not ents:
            continue
        color = info['color']
        items = []
        for e in sorted(ents, key=lambda x: x.valor):
            tags = ''.join(f'<span class="tag">{_e(t)}</span>' for t in sorted(e.tags))
            props = e.propiedades or {}
            extra = ''
            if props:
                pares = [f'{_e(k)}: {_e(str(v)[:80])}' for k, v in list(props.items())[:4]]
                extra = '<div class="props">' + ' · '.join(pares) + '</div>'
            fuentes = ', '.join(_e(o) for o in sorted(e.origenes)) or '—'
            items.append(
                f'<li><span class="val">{_e(e.valor)}</span> {tags}'
                f'<div class="fuente">sources: {fuentes}</div>{extra}</li>')
        bloques.append(
            f'<section class="tipo"><h3><span class="dot" style="background:{color}"></span>'
            f'{_e(info["etiqueta"])} <span class="cnt">{len(ents)}</span></h3>'
            f'<ul>{"".join(items)}</ul></section>')
    inventario_html = ''.join(bloques) or '<p class="vacio">No entities.</p>'

    # ── embedded graph (optional, self-contained) ──
    if vis_js:
        nodos, aristas = _grafo_data(almacen)
        grafo_html = f'''
  <h2>Relationship graph</h2>
  <div id="grafo"></div>
  <script>{vis_js}</script>
  <script>
    const _nodos = new vis.DataSet({json.dumps(nodos)});
    const _aristas = new vis.DataSet({json.dumps(aristas)});
    new vis.Network(document.getElementById('grafo'),
      {{nodes:_nodos, edges:_aristas}},
      {{physics:{{stabilization:true}}, nodes:{{font:{{color:'#c8c8d0',size:11}}}},
        edges:{{color:'#3a3a45',font:{{color:'#6a6a78',size:9}}}}}});
  </script>'''
    else:
        grafo_html = ''

    chips = ''.join(
        f'<span class="chip" style="border-color:{_SEV_COLOR[s]}">'
        f'<b style="color:{_SEV_COLOR[s]}">{conteo[s]}</b> {s}</span>'
        for s in ('critico', 'alto', 'medio', 'bajo'))

    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OBSIDIAN · Report · {_e(ws)}</title>
<style>
  :root{{--bg:#1e1e2e;--panel:#181825;--line:#313244;--txt:#cdd6f4;--muted:#6c7086;--cyan:#89dceb;--amber:#fab387}}  /* Catppuccin Mocha */
  *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--txt);
    font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:2rem;max-width:1000px;margin:auto}}
  h1{{font-size:1.5rem;margin:0 0 .2rem;letter-spacing:.05em}}
  h1 .sq{{display:inline-block;width:.9rem;height:.9rem;background:linear-gradient(135deg,#5b9bd5,#b07a9e);vertical-align:middle;margin-right:.5rem;border-radius:2px}}
  h2{{font-size:1.05rem;margin:2rem 0 .8rem;border-bottom:1px solid var(--line);padding-bottom:.4rem}}
  .meta{{color:var(--muted);font-size:.82rem;margin-bottom:1.5rem}} .meta b{{color:var(--txt)}}
  .score{{display:flex;align-items:center;gap:1rem;margin:1rem 0}}
  .score .barra{{flex:1;height:14px;background:var(--panel);border-radius:7px;overflow:hidden}}
  .score .fill{{height:100%;border-radius:7px}}
  .score .n{{font-family:ui-monospace,monospace;font-size:1.3rem;font-weight:700;min-width:5rem}}
  .chips{{display:flex;gap:.5rem;flex-wrap:wrap;margin:.8rem 0}}
  .chip{{border:1px solid var(--line);border-radius:12px;padding:.15rem .6rem;font-size:.78rem;color:var(--muted)}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th{{text-align:left;color:var(--muted);font-weight:600;padding:.4rem .6rem;border-bottom:1px solid var(--line);font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}}
  td{{padding:.5rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}}
  td.num,.num{{text-align:center;color:var(--muted);font-family:ui-monospace,monospace}}
  .regla{{font-family:ui-monospace,monospace;color:var(--cyan);font-size:.8rem}}
  .sev{{display:inline-block;padding:.1rem .5rem;border-radius:4px;color:#16161e;font-weight:700;font-size:.72rem;text-transform:uppercase}}
  .tipo{{margin:1.2rem 0}} .tipo h3{{font-size:.92rem;margin:0 0 .5rem;display:flex;align-items:center;gap:.5rem}}
  .tipo .dot{{width:.7rem;height:.7rem;border-radius:50%}} .tipo .cnt{{color:var(--muted);font-family:ui-monospace,monospace;font-size:.8rem}}
  .tipo ul{{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.5rem}}
  .tipo li{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.6rem .7rem}}
  .val{{font-family:ui-monospace,monospace;color:var(--txt);word-break:break-all}}
  .tag{{display:inline-block;background:#2a2a36;color:var(--amber);border-radius:4px;padding:.02rem .4rem;font-size:.68rem;margin-left:.3rem}}
  .fuente,.props{{color:var(--muted);font-size:.72rem;margin-top:.3rem;word-break:break-all}}
  .vacio{{color:var(--muted);font-style:italic}}
  #grafo{{height:520px;background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-top:.5rem}}
  footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--muted);font-size:.78rem}}
  footer .lema{{color:var(--cyan);font-style:italic}}
  .toolbar{{display:flex;gap:.5rem;justify-content:flex-end;margin-bottom:1rem}}
  .toolbar button,.toolbar a{{background:var(--panel);color:var(--txt);border:1px solid var(--line);
    border-radius:6px;padding:.35rem .7rem;font-size:.8rem;cursor:pointer;text-decoration:none;font-family:inherit}}
  .toolbar button:hover,.toolbar a:hover{{border-color:var(--cyan);color:var(--cyan)}}
  @media print{{body{{background:#fff;color:#111;max-width:none}} .tipo li,.score .barra,#grafo{{background:#f4f4f6}}
    h2{{border-color:#ccc}} td,th{{border-color:#ddd}} #grafo{{display:none}} .no-print{{display:none}}}}
</style></head>
<body>
  <div class="toolbar no-print">
    <button onclick="window.print()">🖨 PDF</button>
    <a href="/api/v2/export/json" download>⬇ JSON</a>
    <a href="/api/v2/export/csv" download>⬇ CSV</a>
  </div>
  <h1><span class="sq"></span>OBSIDIAN — Reconnaissance report</h1>
  <div class="meta">Workspace: <b>{_e(ws)}</b> · Target: <b>{_e(objetivo)}</b> ·
    Entities: <b>{len(almacen)}</b> · Generated: <b>{_e(generado)}</b></div>

  <h2>Risk summary</h2>
  <div class="score">
    <div class="n" style="color:{score_col}">{int(score)}/100</div>
    <div class="barra"><div class="fill" style="width:{max(0,min(100,int(score)))}%;background:{score_col}"></div></div>
  </div>
  <div class="chips">{chips}</div>

  <h2>Findings</h2>
  {hallazgos_html}

  <h2>Entity inventory</h2>
  {inventario_html}
  {grafo_html}

  <footer>
    Generated by <b>OBSIDIAN</b> · {_e(generado)}<br>
    <span class="lema">Security should not come at an exorbitant price.</span>
  </footer>
</body></html>'''
