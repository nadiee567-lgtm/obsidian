"""Tests de la capa unificada de buscadores + traductor (F8 steps 106, 117).

Correr:  ../.venv/bin/python -m pytest test_motores.py -q
"""
import pytest

from core.motores import traducir, traducir_todos, available_engines, MOTORES


def test_traducir_ip_por_motor():
    assert traducir('shodan', {'ip': '1.2.3.4'}) == 'ip:1.2.3.4'
    assert traducir('fofa', {'ip': '1.2.3.4'}) == 'ip="1.2.3.4"'
    assert traducir('zoomeye', {'ip': '1.2.3.4'}) == 'ip:"1.2.3.4"'


def test_traducir_favicon():
    assert traducir('shodan', {'favicon': '123'}) == 'http.favicon.hash:123'
    assert traducir('fofa', {'favicon': '123'}) == 'icon_hash="123"'
    assert traducir('quake', {'favicon': '123'}) == 'favicon:"123"'


def test_join_operador_por_motor():
    campos = {'ip': '1.2.3.4', 'port': '443'}
    assert traducir('shodan', campos) == 'ip:1.2.3.4 port:443'          # espacio
    assert traducir('fofa', campos) == 'ip="1.2.3.4" && port="443"'     # &&
    assert traducir('quake', campos) == 'ip:"1.2.3.4" AND port:"443"'   # AND


def test_ignora_campos_no_soportados():
    # binaryedge no soporta 'favicon' → se omite, queda solo el puerto
    assert traducir('binaryedge', {'favicon': '9', 'port': '80'}) == 'port:80'


def test_ignora_vacios():
    assert traducir('shodan', {'ip': '', 'port': '80'}) == 'port:80'
    assert traducir('shodan', {}) == ''


def test_traducir_todos():
    d = traducir_todos({'favicon': '123'})
    # all engines that support favicon must appear; criminalip/binaryedge do not
    assert 'shodan' in d and 'fofa' in d and 'zoomeye' in d
    assert 'criminalip' not in d
    assert d['fofa'] == 'icon_hash="123"'


def test_motores_chinos():
    cn = set(available_engines(cn=True))
    assert {'fofa', 'zoomeye', 'quake'} <= cn
    assert 'shodan' not in cn
    assert 'shodan' in available_engines(cn=False)


def test_motor_desconocido():
    with pytest.raises(KeyError):
        traducir('noexiste', {'ip': '1.2.3.4'})


def test_todos_los_motores_tienen_ip():
    # invariante: todo motor debe poder find por IP
    for m, info in MOTORES.items():
        assert 'ip' in info['campos'], f'{m} sin campo ip'
