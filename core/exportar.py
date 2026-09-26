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


# ── Interoperability exporters (STIX 2.1 / MISP / GraphML) ────────────────────
import uuid as _uuid

_STIX_SCO = {  # entity type -> (STIX SCO type, value property)
    'domain': ('domain-name', 'value'), 'subdomain': ('domain-name', 'value'),
    'ip': ('ipv4-addr', 'value'), 'url': ('url', 'value'),
    'email': ('email-addr', 'value'), 'file': ('file', 'name'),
    'netblock': ('ipv4-addr', 'value'),
}


def export_stix(store, findings=None, meta=None) -> str:
    """A STIX 2.1 bundle of observables (SCOs) for the mappable entities, plus the
    risk findings as `note` objects. Importable into TIPs that speak STIX."""
    objects = []
    for e in store.entities:
        m = _STIX_SCO.get(e.type)
        if not m:
            continue
        stype, prop = m
        oid = f'{stype}--{_uuid.uuid5(_uuid.NAMESPACE_URL, f"{stype}:{e.value}")}'
        objects.append({'type': stype, 'spec_version': '2.1', 'id': oid, prop: e.value})
    for h in (findings or []):
        objects.append({
            'type': 'note', 'spec_version': '2.1',
            'id': f'note--{_uuid.uuid5(_uuid.NAMESPACE_URL, f"{h.rule}:{h.message}")}',
            'abstract': f'[{h.severity}] {h.rule}', 'content': h.message,
        })
    bundle = {'type': 'bundle',
              'id': f'bundle--{_uuid.uuid4()}', 'objects': objects}
    return json.dumps(bundle, ensure_ascii=False, indent=2)


_MISP_ATTR = {  # entity type -> (MISP attribute type, category)
    'domain': ('domain', 'Network activity'), 'subdomain': ('domain', 'Network activity'),
    'ip': ('ip-dst', 'Network activity'), 'url': ('url', 'Network activity'),
    'email': ('email-src', 'Payload delivery'), 'hash': ('sha256', 'Payload delivery'),
    'netblock': ('ip-dst', 'Network activity'),
}


def export_misp(store, meta=None) -> str:
    """A MISP event JSON: one attribute per mappable entity. Import via MISP's
    'Populate from... > JSON'."""
    meta = dict(meta or {})
    attrs = []
    for e in store.entities:
        m = _MISP_ATTR.get(e.type)
        if not m:
            continue
        atype, cat = m
        attrs.append({'type': atype, 'category': cat, 'to_ids': False, 'value': e.value})
    event = {'Event': {
        'info': f"OBSIDIAN — {meta.get('workspace') or 'case'}",
        'date': datetime.datetime.now().strftime('%Y-%m-%d'),
        'analysis': '0', 'threat_level_id': '4', 'distribution': '0',
        'Attribute': attrs,
    }}
    return json.dumps(event, ensure_ascii=False, indent=2)


def _xml(s) -> str:
    return (str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;'))


def export_graphml(store) -> str:
    """GraphML (nodes + typed edges) — opens in Gephi, yEd, Cytoscape, and Maltego
    (via CSV/GraphML import). Keeps the whole graph structure, not just a flat list."""
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
           '<key id="type" for="node" attr.name="type" attr.type="string"/>',
           '<key id="value" for="node" attr.name="value" attr.type="string"/>',
           '<key id="label" for="edge" attr.name="label" attr.type="string"/>',
           '<graph edgedefault="directed">']
    for e in store.entities:
        out.append(f'<node id="{_xml(e.id)}"><data key="type">{_xml(e.type)}</data>'
                   f'<data key="value">{_xml(e.value)}</data></node>')
    for i, r in enumerate(store.relations):
        out.append(f'<edge id="e{i}" source="{_xml(r.source)}" target="{_xml(r.target)}">'
                   f'<data key="label">{_xml(r.label)}</data></edge>')
    out.append('</graph></graphml>')
    return '\n'.join(out)
