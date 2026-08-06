"""Tests for the encrypted vault (F3 step 51).

Run:  ../.venv/bin/python -m pytest test_boveda.py -q
"""
from core.boveda import Vault


def test_guardar_y_obtener(tmp_path):
    b = Vault(str(tmp_path))
    b.guardar('shodan', 'SECRETO-123')
    assert b.get('shodan') == 'SECRETO-123'
    assert b.get('inexistente') is None


def test_solo_nombres_no_valores(tmp_path):
    b = Vault(str(tmp_path))
    b.guardar('shodan', 'k1')
    b.guardar('hibp', 'k2')
    assert b.servicios() == ['hibp', 'shodan']   # sorted names, no values


def test_persiste_entre_instancias(tmp_path):
    Vault(str(tmp_path)).guardar('vt', 'MI-KEY')
    # another instance (simulates a restart) reads the same
    assert Vault(str(tmp_path)).get('vt') == 'MI-KEY'


def test_archivo_esta_cifrado(tmp_path):
    b = Vault(str(tmp_path))
    b.guardar('shodan', 'VALOR-EN-CLARO-XYZ')
    # the on-disk file must NOT contain the value in plaintext
    raw = open(b.enc_file, 'rb').read()
    assert b'VALOR-EN-CLARO-XYZ' not in raw
    assert b'shodan' not in raw


def test_sin_la_clave_no_se_puede_leer(tmp_path):
    b = Vault(str(tmp_path))
    b.guardar('shodan', 'SECRETO')
    # deleting the master key → the ciphertext is unreadable (no crash, returns empty)
    import os
    os.remove(b.key_file)
    b2 = Vault(str(tmp_path))
    assert b2.get('shodan') is None


def test_borrar(tmp_path):
    b = Vault(str(tmp_path))
    b.guardar('x', 'k')
    assert b.delete('x') is True
    assert b.get('x') is None
    assert b.delete('x') is False
