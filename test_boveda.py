"""Tests de la bóveda cifrada (F3 paso 51).

Correr:  ../.venv/bin/python -m pytest test_boveda.py -q
"""
from core.boveda import Boveda


def test_guardar_y_obtener(tmp_path):
    b = Boveda(str(tmp_path))
    b.guardar('shodan', 'SECRETO-123')
    assert b.obtener('shodan') == 'SECRETO-123'
    assert b.obtener('inexistente') is None


def test_solo_nombres_no_valores(tmp_path):
    b = Boveda(str(tmp_path))
    b.guardar('shodan', 'k1')
    b.guardar('hibp', 'k2')
    assert b.servicios() == ['hibp', 'shodan']   # nombres ordenados, sin valores


def test_persiste_entre_instancias(tmp_path):
    Boveda(str(tmp_path)).guardar('vt', 'MI-KEY')
    # otra instancia (simula reinicio) lee lo mismo
    assert Boveda(str(tmp_path)).obtener('vt') == 'MI-KEY'


def test_archivo_esta_cifrado(tmp_path):
    b = Boveda(str(tmp_path))
    b.guardar('shodan', 'VALOR-EN-CLARO-XYZ')
    # el archivo en disco NO debe contener el valor en texto plano
    raw = open(b.enc_file, 'rb').read()
    assert b'VALOR-EN-CLARO-XYZ' not in raw
    assert b'shodan' not in raw


def test_sin_la_clave_no_se_puede_leer(tmp_path):
    b = Boveda(str(tmp_path))
    b.guardar('shodan', 'SECRETO')
    # borrar la clave maestra → el cifrado queda ilegible (no crashea, da vacío)
    import os
    os.remove(b.key_file)
    b2 = Boveda(str(tmp_path))
    assert b2.obtener('shodan') is None


def test_borrar(tmp_path):
    b = Boveda(str(tmp_path))
    b.guardar('x', 'k')
    assert b.borrar('x') is True
    assert b.obtener('x') is None
    assert b.borrar('x') is False
