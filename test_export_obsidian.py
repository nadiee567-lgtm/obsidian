"""Tests for the Obsidian (notes app) vault export."""
from core.modelo import Store
from core.correlacion import Finding
from core.exportar import export_obsidian_vault


def _demo_store():
    s = Store()
    d = s.create('domain', 'example.com')
    ip = s.create('ip', '203.0.113.10')
    s.relate(d, ip, 'resolves')
    return s, d, ip


def test_vault_structure_and_links():
    s, d, ip = _demo_store()
    f = Finding('sensitive-port', 'critical', 'RDP exposed', [ip.id])
    files = export_obsidian_vault(s, [f], 100, {'workspace': 'case1'})

    # one index + one note per entity
    assert len(files) == 3
    assert any(p.endswith('index.md') for p in files)

    dom = next(v for k, v in files.items() if k.endswith('example.com.md'))
    # relation rendered as a wikilink with its label
    assert '[[203.0.113.10]]' in dom and 'resolves' in dom
    # frontmatter carries the type and the obsidian tag
    assert 'type: domain' in dom and 'osint/domain' in dom

    ipnote = next(v for k, v in files.items() if k.endswith('203.0.113.10.md'))
    assert 'RDP exposed' in ipnote            # finding shown on the involved entity

    idx = next(v for k, v in files.items() if k.endswith('index.md'))
    assert 'RDP exposed' in idx               # findings table
    assert '[[example.com]]' in idx and '[[203.0.113.10]]' in idx


def test_vault_is_path_traversal_safe():
    s = Store()
    s.create('user', '../../etc/passwd')      # hostile OSINT value
    files = export_obsidian_vault(s, [], 0, {'workspace': 'c'})
    for p in files:
        segments = p.split('/')
        assert '..' not in segments           # no traversal segment
        assert not p.startswith('/')          # no absolute path


def test_export_stix():
    import json
    from core.exportar import export_stix
    s, d, ip = _demo_store()
    b = json.loads(export_stix(s, [], {'workspace': 'c'}))
    assert b['type'] == 'bundle'
    types = {o['type'] for o in b['objects']}
    assert 'domain-name' in types and 'ipv4-addr' in types


def test_export_misp():
    import json
    from core.exportar import export_misp
    s, d, ip = _demo_store()
    ev = json.loads(export_misp(s, {'workspace': 'c'}))
    vals = {a['value'] for a in ev['Event']['Attribute']}
    assert 'example.com' in vals and '203.0.113.10' in vals


def test_export_graphml():
    from core.exportar import export_graphml
    s, d, ip = _demo_store()
    x = export_graphml(s)
    assert '<graphml' in x and 'example.com' in x and '<edge' in x
