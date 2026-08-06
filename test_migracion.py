"""Tests for the old->typed migration adapter (F1 step 24).

Run:  ../.venv/bin/python -m pytest test_migracion.py -q
"""
from core.migracion import migrate_case


# a realistic old case, as the OSINT modules used to leave it
CASE_VIEJO = {
    'nombre': 'caso1',
    'objetivo': 'example.com',
    'datos': {
        'dominio': {
            'type': 'dominio', 'objetivo': 'example.com',
            'resultados': {
                'dns': {'A': '93.184.216.34'},
                'subdominios': ['mail.example.com', 'www.example.com'],
                'emails': ['admin@example.com'],
                'tecnologias': {'Server': 'nginx'},
            },
        },
        'ip': {
            'type': 'ip', 'objetivo': '93.184.216.34',
            'resultados': {'geo': {'country': 'US', 'org': 'Edgecast'}, 'ptr': 'edge.example.com'},
        },
        'email': {
            'type': 'email', 'objetivo': 'admin@example.com',
            'resultados': {'email_sec': {'spoofable': True}, 'hibp_breaches': ['LinkedIn']},
        },
        'takeover': {
            'type': 'subdomain_takeover', 'objetivo': 'example.com',
            'resultados': {'vulnerables': [{'subdominio': 'old.example.com',
                                            'servicio': 'GitHub Pages', 'status': '404'}]},
        },
        'roto': {'type': 'ip'},   # malformed module: must not break anything
    },
}


def test_migracion_crea_entidades_tipadas():
    alm = migrate_case(CASE_VIEJO)
    # target + domain + ip + subdomains + email + country + org + ptr + takeover...
    assert alm.buscar('objetivo', 'example.com') is not None
    assert alm.buscar('dominio', 'example.com') is not None
    assert alm.buscar('ip', '93.184.216.34') is not None
    assert alm.buscar('email', 'admin@example.com') is not None
    assert alm.buscar('pais', 'US') is not None
    assert alm.buscar('tech', 'nginx') is not None


def test_migracion_dedup_email_entre_modulos():
    # the email appears in the 'dominio' module (emails) and the 'email' module:
    # it must be ONE single entity with both sources
    alm = migrate_case(CASE_VIEJO)
    e = alm.buscar('email', 'admin@example.com')
    assert 'dominio' in e.sources and 'email' in e.sources


def test_migracion_tags_y_props():
    alm = migrate_case(CASE_VIEJO)
    e = alm.buscar('email', 'admin@example.com')
    assert 'spoofable' in e.tags and 'filtrado' in e.tags
    assert e.properties.get('hibp_breaches') == ['LinkedIn']
    sub = alm.buscar('subdominio', 'old.example.com')
    assert 'takeover' in sub.tags


def test_migracion_no_truena_con_modulo_roto():
    # the 'roto' module has no 'objetivo'; the migration skips it without error
    alm = migrate_case(CASE_VIEJO)
    assert len(alm) > 0


def test_migracion_caso_vacio():
    alm = migrate_case({'objetivo': None, 'datos': {}})
    assert len(alm) == 0
