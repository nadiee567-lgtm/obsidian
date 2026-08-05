"""System status page -- F7 step 105.

PURE (testable) render of OBSIDIAN's health: available transforms, configured keys,
present system tools, local AI, workspaces and monitor. Data collection (which
touches the system) lives in the endpoint; here we only paint the dict."""
from __future__ import annotations
import html


def _e(v) -> str:
    return html.escape(str(v), quote=True)


def _punto(ok: bool) -> str:
    col = '#a6e3a1' if ok else '#6c7086'
    txt = 'yes' if ok else 'no'
    return f'<span class="dot" style="background:{col}"></span>{txt}'


def render_estado(data: dict) -> str:
    t = data.get('transforms', {})
    por_tipo = t.get('por_tipo', {})
    tipos_html = ''.join(
        f'<span class="chip">{_e(tp)} <b>{n}</b></span>' for tp, n in sorted(por_tipo.items()))

    herr = data.get('herramientas', {})
    herr_html = ''.join(
        f'<tr><td>{_e(nombre)}</td><td>{_punto(ok)}</td></tr>' for nombre, ok in herr.items())

    keys = data.get('keys', [])
    keys_html = (', '.join(_e(k) for k in keys)) if keys else '<span class="muted">none</span>'

    ia = data.get('ia', {})
    ia_ok = ia.get('disponible')

    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OBSIDIAN · system status</title>
<style>
  :root{{--bg:#1e1e2e;--panel:#181825;--line:#313244;--txt:#cdd6f4;--muted:#6c7086;--blue:#89b4fa;--green:#a6e3a1}}
  *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--txt);
    font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:2rem;max-width:820px;margin:auto}}
  h1{{font-size:1.4rem;margin:0 0 .3rem}} h1 .sq{{display:inline-block;width:.85rem;height:.85rem;
    background:linear-gradient(135deg,#89b4fa,#cba6f7);vertical-align:middle;margin-right:.5rem;border-radius:2px}}
  h2{{font-size:1rem;margin:1.8rem 0 .7rem;border-bottom:1px solid var(--line);padding-bottom:.35rem}}
  .meta{{color:var(--muted);font-size:.82rem;margin-bottom:1rem}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.7rem}}
  .kpi{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.7rem .9rem}}
  .kpi .n{{font-size:1.6rem;font-weight:700;color:var(--blue);font-family:ui-monospace,monospace}}
  .kpi .l{{color:var(--muted);font-size:.78rem}}
  .chip{{display:inline-block;background:var(--panel);border:1px solid var(--line);border-radius:12px;
    padding:.1rem .55rem;font-size:.76rem;margin:.15rem;font-family:ui-monospace,monospace}}
  .chip b{{color:var(--blue)}}
  table{{border-collapse:collapse;font-size:.85rem}} td{{padding:.3rem .9rem .3rem 0}}
  .dot{{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;margin-right:.4rem;vertical-align:middle}}
  .muted{{color:var(--muted)}} a{{color:var(--blue)}}
  @media print{{body{{background:#fff;color:#111}}}}
</style></head>
<body>
  <h1><span class="sq"></span>OBSIDIAN — system status</h1>
  <div class="meta">Generated: {_e(data.get('generado', '—'))} · <a href="/v2">← to graph</a></div>

  <div class="grid">
    <div class="kpi"><div class="n">{t.get('total', 0)}</div><div class="l">transforms</div></div>
    <div class="kpi"><div class="n">{data.get('workspaces', 0)}</div><div class="l">workspaces</div></div>
    <div class="kpi"><div class="n">{len(keys)}</div><div class="l">API keys</div></div>
    <div class="kpi"><div class="n">{'●' if data.get('monitor') else '○'}</div><div class="l">monitor {'active' if data.get('monitor') else 'off'}</div></div>
  </div>

  <h2>Transforms by entity type</h2>
  <div>{tipos_html or '<span class="muted">none</span>'}</div>

  <h2>System tools</h2>
  <table>{herr_html}</table>

  <h2>Local AI (Ollama)</h2>
  <p>{_punto(bool(ia_ok))} — model: <code>{_e(ia.get('modelo', '?'))}</code></p>

  <h2>Integrations</h2>
  <p>Configured API keys: {keys_html}</p>
  <p>ntfy notifications: {_punto(bool(data.get('ntfy')))}</p>
</body></html>'''
