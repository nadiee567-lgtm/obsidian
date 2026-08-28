"""Tests for the old->typed migration adapter (F1 step 24).

Run:  ../.venv/bin/python -m pytest test_migracion.py -q
"""
from core.migracion import migrate_case


# a realistic old case, as the OSINT modules used to leave it
CASE_VIEJO = {
    'name': 'caso1',
    'target': 'example.com',
    'data': {
        'domain': {
            'type': 'domain', 'target': 'example.com',
            'results': {
                'dns': {'A': '93.184.216.34'},
                'subdominios': ['mail.example.com', 'www.example.com'],
                'emails': ['admin@example.com'],
                'tecnologias': {'Server': 'nginx'},
            },
        },
        'ip': {
            'type': 'ip', 'target': '93.184.216.34',
            'results': {'geo': {'country': 'US', 'org': 'Edgecast'}, 'ptr': 'edge.example.com'},
        },
        'email': {
            'type': 'email', 'target': 'admin@example.com',
            'results': {'email_sec': {'spoofable': True}, 'hibp_breaches': ['LinkedIn']},
        },
        'takeover': {
            'type': 'subdomain_takeover', 'target': 'example.com',
            'results': {'vulnerables': [{'subdomain': 'old.example.com',
                                            'service': 'GitHub Pages', 'status': '404'}]},
        },
        'roto': {'type': 'ip'},   # malformed module: must not break anything
    },
}


def test_migration_creates_entities_typed():
    store = migrate_case(CASE_VIEJO)
    # target + domain + ip + subdomains + email + country + org + ptr + takeover...
    assert store.find('target', 'example.com') is not None
    assert store.find('domain', 'example.com') is not None
    assert store.find('ip', '93.184.216.34') is not None
    assert store.find('email', 'admin@example.com') is not None
    assert store.find('country', 'US') is not None
    assert store.find('tech', 'nginx') is not None


def test_migration_dedup_email_between_modules():
    # the email appears in the 'domain' module (emails) and the 'email' module:
    # it must be ONE single entity with both sources
    store = migrate_case(CASE_VIEJO)
    e = store.find('email', 'admin@example.com')
    assert 'domain' in e.sources and 'email' in e.sources


def test_migration_tags_props():
    store = migrate_case(CASE_VIEJO)
    e = store.find('email', 'admin@example.com')
    assert 'spoofable' in e.tags and 'leaked' in e.tags
    assert e.properties.get('hibp_breaches') == ['LinkedIn']
    sub = store.find('subdomain', 'old.example.com')
    assert 'takeover' in sub.tags


def test_migration_no_crash_with_module_broken():
    # the 'roto' module has no 'target'; the migration skips it without error
    store = migrate_case(CASE_VIEJO)
    assert len(store) > 0


def test_migration_empty_case():
    store = migrate_case({'target': None, 'data': {}})
    assert len(store) == 0
