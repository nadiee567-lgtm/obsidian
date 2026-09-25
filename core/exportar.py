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
import re
import datetime

_PELIGRO = ('=', '+', '-', '@')


def _cell(v) -> str:
    """Neutralizes formula injection in a CSV cell."""
    s = '' if v is None else str(v)
    if s and (s[0] in _PELIGRO or s[0] in ('\t', '\r')):
        s = "'" + s
    return s


def export_json(store, findings=None, score=0, meta=None) -> str:
    """Full case in JSON, re-importable with Store.from_dict()."""
    meta = dict(meta or {})
    meta.setdefault('generado', datetime.datetime.now().isoformat(timespec='seconds'))
    d = store.to_dict()
    d['meta'] = meta
    d['score'] = int(score)
    d['findings'] = [h.to_dict() for h in (findings or [])]
    return json.dumps(d, ensure_ascii=False, indent=2)


def export_csv(store) -> str:
    """One row per entity. Cells sanitized against formula injection."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['type', 'value', 'tags', 'sources', 'confidence', 'properties'])
    for e in sorted(store.entities, key=lambda x: (x.type, x.value)):
        props = '; '.join(f'{k}={v}' for k, v in (e.properties or {}).items())
        w.writerow([_cell(e.type), _cell(e.value), _cell(' '.join(sorted(e.tags))),
                    _cell(' '.join(sorted(e.sources))),
                    _cell(getattr(e, 'confidence', 1.0)), _cell(props)])
    return buf.getvalue()


# ── Obsidian (notes app) vault export ────────────────────────────────────────
# Turns a case into a folder of Markdown notes: one note per entity, relations as
# [[wikilinks]], plus an index note with the risk findings. Opened in the Obsidian
# notes app, the local graph reconstructs the whole investigation.

_UNSAFE = re.compile(r'[\\/:*?"<>|#^\[\]]')  # filesystem + wikilink hostile chars


def _slug(value: str, maxlen: int = 80) -> str:
    """Filesystem- and wikilink-safe note basename. Neutralizes path traversal:
    slashes become '_', so a hostile value like '../../etc/passwd' collapses to a
    single harmless filename."""
    s = _UNSAFE.sub('_', str(value or ''))
    s = re.sub(r'\s+', ' ', s.replace('\n', ' ').replace('\r', ' ')).strip()
    s = s.strip('.').strip()          # no leading/trailing dots (Windows-hostile)
    return (s or 'entity')[:maxlen]


def _frontmatter(d: dict) -> str:
    """YAML frontmatter block. Uses PyYAML (already a dependency) with a safe
    manual fallback; either way strings are quoted so hostile values can't break
    the block."""
    try:
        import yaml
        body = yaml.safe_dump(d, allow_unicode=True, sort_keys=False,
                              default_flow_style=False).strip()
    except Exception:
        lines = []
        for k, v in d.items():
            if isinstance(v, (list, tuple)):
                lines.append(f'{k}:')
                lines += [f'  - {json.dumps(str(i), ensure_ascii=False)}' for i in v]
            else:
                lines.append(f'{k}: {json.dumps(str(v), ensure_ascii=False)}')
        body = '\n'.join(lines)
    return f'---\n{body}\n---\n'


def export_obsidian_vault(store, findings=None, score=0, meta=None) -> dict:
    """Render a case as an Obsidian (notes app) vault.

    Returns {relative_path: markdown_content}; the caller writes the files. PURE:
    no filesystem, no network -- so it is fully testable.
    """
    meta = dict(meta or {})
    case = str(meta.get('workspace') or meta.get('case') or 'case')
    case_slug = _slug(case, 60)
    now = datetime.datetime.now().isoformat(timespec='seconds')
    findings = list(findings or [])
    ents = sorted(store.entities, key=lambda e: (e.type, e.value))

    # unique note name per entity id (so [[links]] resolve unambiguously)
    name_by_id, used = {}, set()
    for e in ents:
        base = _slug(e.value)
        name = base if base.lower() not in used else f'{base}-{e.id[:6]}'
        used.add(name.lower())
        name_by_id[e.id] = name

    rels_out, rels_in = {}, {}
    for r in store.relations:
        rels_out.setdefault(r.source, []).append((r.target, r.label))
        rels_in.setdefault(r.target, []).append((r.source, r.label))

    find_by_ent = {}
    for h in findings:
        for eid in (getattr(h, 'entities', None) or []):
            find_by_ent.setdefault(eid, []).append(h)

    files, folder = {}, case_slug
    index_name = f'{case_slug} — index'

    for e in ents:
        fm = {
            'type': e.type,
            'value': e.value,
            'id': e.id,
            'confidence': getattr(e, 'confidence', 1.0),
            'created': getattr(e, 'created', now),
            'sources': sorted(e.sources) if e.sources else [],
            'tags': (sorted(e.tags) if e.tags else []) + [f'osint/{e.type}'],
        }
        p = [_frontmatter(fm), f'# {e.value}\n', f'`{e.type}`\n']
        if e.properties:
            p.append('## Properties\n')
            p += [f'- **{k}:** `{v}`' for k, v in e.properties.items()]
            p.append('')
        links = [f'- [[{name_by_id[t]}]]' + (f' — {lbl}' if lbl else '')
                 for t, lbl in rels_out.get(e.id, []) if t in name_by_id]
        links += [f'- [[{name_by_id[s]}]]' + (f' — {lbl}' if lbl else '') + ' _(incoming)_'
                  for s, lbl in rels_in.get(e.id, []) if s in name_by_id]
        if links:
            p.append('## Relations\n'); p += links; p.append('')
        fs = find_by_ent.get(e.id)
        if fs:
            p.append('## Findings\n')
            p += [f'- **{h.severity.upper()}** ({h.rule}): {h.message}' for h in fs]
            p.append('')
        p.append(f'[[{index_name}|← back to case]]')
        files[f'{folder}/{name_by_id[e.id]}.md'] = '\n'.join(p).rstrip() + '\n'

    # index note
    order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    idx = [_frontmatter({'case': case, 'generated': now, 'risk_score': int(score),
                         'entities': len(ents), 'tags': ['osint', 'obsidian-case']})]
    idx.append(f'# {case} — OBSIDIAN case\n')
    idx.append(f'**Risk score:** {int(score)}/100  ·  **Entities:** {len(ents)}  ·  '
               f'Generated {now}\n')
    if findings:
        idx.append('## Findings\n')
        idx.append('| Severity | Rule | Detail |')
        idx.append('|---|---|---|')
        for h in sorted(findings, key=lambda x: -order.get(x.severity, 0)):
            msg = str(h.message).replace('|', r'\|').replace('\n', ' ')
            idx.append(f'| {h.severity.upper()} | {h.rule} | {msg} |')
        idx.append('')
    idx.append('## Entities\n')
    by_type = {}
    for e in ents:
        by_type.setdefault(e.type, []).append(e)
    for t in sorted(by_type):
        idx.append(f'### {t} ({len(by_type[t])})')
        idx += [f'- [[{name_by_id[e.id]}]]' for e in by_type[t]]
        idx.append('')
    files[f'{folder}/{index_name}.md'] = '\n'.join(idx).rstrip() + '\n'
    return files
