"""Tests for the CLI (F7 step 98). They don't touch the network.

Run:  ../.venv/bin/python -m pytest test_cli.py -q
"""
import obsidian_cli as cli


def test_parser_run():
    a = cli.build_parser().parse_args(['run', 'domain', 'x.com', 'dns_a', '-w', 'c1'])
    assert a.type == 'domain' and a.value == 'x.com' and a.transform == 'dns_a'
    assert a.workspace == 'c1' and a.fn is cli.cmd_run


def test_parser_recon_con_keys():
    a = cli.build_parser().parse_args(['recon', 'ip', '1.1.1.1', '--with-keys'])
    assert a.with_keys is True and a.fn is cli.cmd_recon


def test_transforms_lista(capsys):
    assert cli.main(['transforms', 'domain']) == 0
    out = capsys.readouterr().out
    assert 'dns_a' in out and '→' in out


def test_run_tipo_invalido():
    assert cli.main(['run', 'noexiste', 'x', 'dns_a']) == 1


def test_export_workspace_inexistente():
    assert cli.main(['export', 'json', '-w', 'no-exists-zzz-999']) == 1


def test_report_workspace_inexistente():
    assert cli.main(['report', '-w', 'no-exists-zzz-999']) == 1
