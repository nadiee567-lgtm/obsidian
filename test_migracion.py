"""Tests del adaptador de migración viejo→tipado (F1 paso 24).

Correr:  ../.venv/bin/python -m pytest test_migracion.py -q
"""
from core.migracion import migrar_caso


# un case viejo realista, como lo dejaban los módulos OSINT
CASE_VIEJO = {
    'nombre': 'caso1',
    'objetivo': 'example.com',
    'datos': {
        'dominio': {
            'tipo': 'dominio', 'objetivo': 'example.com',
            'resultados': {
                'dns': {'A': '93.184.216.34'},
                'subdominios': ['mail.example.com', 'www.example.com'],
                'emails': ['admin@example.com'],
                'tecnologias': {'Server': 'nginx'},
            },
        },
        'ip': {
            'tipo': 'ip', 'objetivo': '93.184.216.34',
            'resultados': {'geo': {'country': 'US', 'org': 'Edgecast'}, 'ptr': 'edge.example.com'},
        },
        'email': {
            'tipo': 'email', 'objetivo': 'admin@example.com',
            'resultados': {'email_sec': {'spoofable': True}, 'hibp_breaches': ['LinkedIn']},
        },
        'takeover': {
            'tipo': 'subdomain_takeover', 'objetivo': 'example.com',
            'resultados': {'vulnerables': [{'subdominio': 'old.example.com',
                                            'servicio': 'GitHub Pages', 'status': '404'}]},
        },
        'roto': {'tipo': 'ip'},   # módulo malformado: no debe tumbar nada
    },
}


def test_migracion_crea_entidades_tipadas():
    alm = migrar_caso(CASE_VIEJO)
    # objetivo + dominio + ip + subdominios + email + pais + org + ptr + takeover...
    assert alm.buscar('objetivo', 'example.com') is not None
    assert alm.buscar('dominio', 'example.com') is not None
    assert alm.buscar('ip', '93.184.216.34') is not None
    assert alm.buscar('email', 'admin@example.com') is not None
    assert alm.buscar('pais', 'US') is not None
    assert alm.buscar('tech', 'nginx') is not None


def test_migracion_dedup_email_entre_modulos():
    # el email aparece en el módulo 'dominio' (emails) y en el módulo 'email':
    # debe ser UNA sola entidad con ambos orígenes
    alm = migrar_caso(CASE_VIEJO)
    e = alm.buscar('email', 'admin@example.com')
    assert 'dominio' in e.origenes and 'email' in e.origenes


def test_migracion_tags_y_props():
    alm = migrar_caso(CASE_VIEJO)
    e = alm.buscar('email', 'admin@example.com')
    assert 'spoofable' in e.tags and 'filtrado' in e.tags
    assert e.propiedades.get('hibp_breaches') == ['LinkedIn']
    sub = alm.buscar('subdominio', 'old.example.com')
    assert 'takeover' in sub.tags


def test_migracion_no_truena_con_modulo_roto():
    # el módulo 'roto' no tiene 'objetivo'; la migración lo salta sin error
    alm = migrar_caso(CASE_VIEJO)
    assert len(alm) > 0


def test_migracion_caso_vacio():
    alm = migrar_caso({'objetivo': None, 'datos': {}})
    assert len(alm) == 0
