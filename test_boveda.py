"""Tests for the encrypted vault (F3 step 51).

Run:  ../.venv/bin/python -m pytest test_boveda.py -q
"""
from core.boveda import Vault


def test_save_and_get(tmp_path):
    b = Vault(str(tmp_path))
    b.save('shodan', 'SECRETO-123')
    assert b.get('shodan') == 'SECRETO-123'
    assert b.get('inexistente') is None


def test_only_names_no_values(tmp_path):
    b = Vault(str(tmp_path))
    b.save('shodan', 'k1')
    b.save('hibp', 'k2')
    assert b.servicios() == ['hibp', 'shodan']   # sorted names, no values


def test_persists_between_instances(tmp_path):
    Vault(str(tmp_path)).save('vt', 'MI-KEY')
    # another instance (simulates a restart) reads the same
    assert Vault(str(tmp_path)).get('vt') == 'MI-KEY'


def test_file_is_encrypted(tmp_path):
    b = Vault(str(tmp_path))
    b.save('shodan', 'VALOR-EN-CLARO-XYZ')
    # the on-disk file must NOT contain the value in plaintext
    raw = open(b.enc_file, 'rb').read()
    assert b'VALOR-EN-CLARO-XYZ' not in raw
    assert b'shodan' not in raw


def test_without_key_no_puede_leer(tmp_path):
    b = Vault(str(tmp_path))
    b.save('shodan', 'SECRETO')
    # deleting the master key → the ciphertext is unreadable (no crash, returns empty)
    import os
    os.remove(b.key_file)
    b2 = Vault(str(tmp_path))
    assert b2.get('shodan') is None


def test_delete(tmp_path):
    b = Vault(str(tmp_path))
    b.save('x', 'k')
    assert b.delete('x') is True
    assert b.get('x') is None
    assert b.delete('x') is False
