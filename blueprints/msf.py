"""Metasploit console GUI (msfrpcd RPC) — Flask blueprint.

Drives a real msfconsole via Metasploit's RPC. EXPLOITATION tool: gated to a loopback
bind + the app login, and only works once the operator has started msfrpcd and set its
password. Shared state/helpers are read from obsidian_web at request time (sys.modules),
same pattern as blueprints/export.py."""
from __future__ import annotations
import os
import sys
from flask import Blueprint, request, jsonify

bp = Blueprint('msf', __name__)
_MSF = {'client': None}


def _web():
    return sys.modules.get('obsidian_web') or sys.modules['__main__']


def _cfg():
    W = _web()
    return {
        'host': W._boveda.get('msf_host') or os.environ.get('MSF_HOST', '127.0.0.1'),
        'port': int(W._boveda.get('msf_port') or os.environ.get('MSF_PORT', '55553')),
        'password': W._rotating_key('msf_password') or os.environ.get('MSF_PASSWORD', ''),
        'ssl': (W._boveda.get('msf_ssl') or 'true') != 'false',
    }


def _client():
    from core.msf import MsfRpc
    cfg = _cfg()
    if not cfg['password']:
        return None
    if _MSF['client'] is None:
        _MSF['client'] = MsfRpc(host=cfg['host'], port=cfg['port'],
                                password=cfg['password'], ssl=cfg['ssl'])
    return _MSF['client']


@bp.route('/api/v2/msf/status')
def status():
    """Is the Metasploit RPC reachable? (loopback-gated). Reports version + module counts."""
    W = _web()
    if not W._terminal_allowed():
        return jsonify({'connected': False, 'gated': True,
                        'note': 'Metasploit is disabled when OBSIDIAN is network-exposed.'})
    cfg = _cfg()
    if not cfg['password']:
        return jsonify({'connected': False, 'configured': False,
                        'note': 'Start msfrpcd and set its password (vault: msf_password). '
                                'e.g. msfrpcd -P yourpass -S -a 127.0.0.1'})
    try:
        c = _client()
        return jsonify({'connected': True, 'version': c.version(), 'modules': c.module_stats()})
    except Exception as e:
        _MSF['client'] = None
        return jsonify({'connected': False, 'configured': True, 'error': str(e)})


@bp.route('/api/v2/msf/config', methods=['POST'])
def config():
    """Save msfrpcd connection settings (password stored in the encrypted vault)."""
    W = _web()
    if not W._terminal_allowed():
        return W._error('Metasploit disabled on a network-exposed instance', 403)
    d = request.json or {}
    if 'password' in d:
        W._boveda.save('msf_password', d['password'])
    if d.get('host'):
        W._boveda.save('msf_host', d['host'])
    if d.get('port'):
        W._boveda.save('msf_port', str(d['port']))
    if 'ssl' in d:
        W._boveda.save('msf_ssl', 'true' if d['ssl'] else 'false')
    _MSF['client'] = None
    return jsonify({'ok': True})


@bp.route('/api/v2/msf/console', methods=['POST'])
def console_create():
    W = _web()
    if not W._terminal_allowed():
        return W._error('Metasploit disabled on a network-exposed instance', 403)
    try:
        return jsonify(_client().console_create())
    except Exception as e:
        return W._error(f'msf: {e}', 502)


@bp.route('/api/v2/msf/console/write', methods=['POST'])
def console_write():
    W = _web()
    if not W._terminal_allowed():
        return W._error('Metasploit disabled on a network-exposed instance', 403)
    d = request.json or {}
    try:
        _client().console_write(d.get('id', '0'), d.get('cmd', ''))
        return jsonify({'ok': True})
    except Exception as e:
        return W._error(f'msf: {e}', 502)


@bp.route('/api/v2/msf/console/read')
def console_read():
    W = _web()
    if not W._terminal_allowed():
        return W._error('Metasploit disabled on a network-exposed instance', 403)
    try:
        return jsonify(_client().console_read(request.args.get('id', '0')))
    except Exception as e:
        return W._error(f'msf: {e}', 502)
