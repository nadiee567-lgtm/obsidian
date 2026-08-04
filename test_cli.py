"""Tests del CLI (F7 paso 98). No tocan la red.

Correr:  ../.venv/bin/python -m pytest test_cli.py -q
"""
import obsidian_cli as cli


def test_parser_run():
    a = cli.construir_parser().parse_args(['run', 'dominio', 'x.com', 'dns_a', '-w', 'c1'])
    assert a.tipo == 'dominio' and a.valor == 'x.com' and a.transform == 'dns_a'
    assert a.workspace == 'c1' and a.fn is cli.cmd_run


def test_parser_recon_con_keys():
    a = cli.construir_parser().parse_args(['recon', 'ip', '1.1.1.1', '--con-keys'])
    assert a.con_keys is True and a.fn is cli.cmd_recon


def test_transforms_lista(capsys):
    assert cli.main(['transforms', 'dominio']) == 0
    out = capsys.readouterr().out
    assert 'dns_a' in out and '→' in out


def test_run_tipo_invalido():
    assert cli.main(['run', 'noexiste', 'x', 'dns_a']) == 1


def test_export_workspace_inexistente():
    assert cli.main(['export', 'json', '-w', 'no-existe-zzz-999']) == 1


def test_report_workspace_inexistente():
    assert cli.main(['report', '-w', 'no-existe-zzz-999']) == 1
