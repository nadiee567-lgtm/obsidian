"""Tests for the Metasploit RPC client + web endpoints (mocked msfrpcd)."""
import msgpack
from core.msf import MsfRpc, _d
import obsidian_web as ob


def test_decode_bytes():
    assert _d(b'hi') == 'hi'
    assert _d({b'k': b'v'}) == {'k': 'v'}
    assert _d([b'a', {b'x': b'y'}]) == ['a', {'x': 'y'}]


def test_login_and_call(monkeypatch):
    calls = {}

    class _R:
        def __init__(self, content): self.content = content

    def fake_post(url, data=None, headers=None, timeout=None, verify=None):
        req = msgpack.unpackb(data, raw=True)
        method = req[0].decode() if isinstance(req[0], bytes) else req[0]
        calls['last'] = method
        if method == 'auth.login':
            return _R(msgpack.packb({'result': 'success', 'token': 'TOK'}))
        if method == 'core.version':
            # token must be present as 2nd arg
            assert req[1] in (b'TOK', 'TOK')
            return _R(msgpack.packb({'version': '6.4.0'}))
        return _R(msgpack.packb({'ok': True}))

    monkeypatch.setattr('core.msf._S.post', fake_post)
    c = MsfRpc(password='pw')
    assert c.login() is True and c.token == 'TOK'
    assert c.version()['version'] == '6.4.0'


def test_status_not_configured(monkeypatch):
    # no password anywhere -> not configured, graceful
    monkeypatch.setattr(ob, '_rotating_key', lambda s: None)
    monkeypatch.setenv('MSF_PASSWORD', '')
    monkeypatch.setattr(ob._boveda, 'get', lambda k: None)
    c = ob.app.test_client()
    with c.session_transaction() as s:
        s['auth'] = True
    d = c.get('/api/v2/msf/status').get_json()
    assert d['connected'] is False and d.get('configured') is False


def test_full_http_msgpack_roundtrip():
    """End-to-end over real HTTP + msgpack against an in-process mock msfrpcd."""
    import msgpack, threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from core.msf import MsfRpc

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            req = msgpack.unpackb(self.rfile.read(int(self.headers.get('Content-Length', 0))), raw=True)
            m = req[0].decode() if isinstance(req[0], bytes) else req[0]
            if m == 'auth.login':
                resp = {'result': 'success', 'token': 'T'}
            elif m == 'core.version':
                resp = {'version': '6.4.0'}
            elif m == 'console.create':
                resp = {'id': '0', 'prompt': 'msf6 > '}
            elif m == 'console.write':
                resp = {'wrote': 5}
            elif m == 'console.read':
                resp = {'data': 'Matching Modules\n eternalblue\n', 'prompt': 'msf6 > '}
            else:
                resp = {'modules': []}
            body = msgpack.packb(resp, use_bin_type=True)
            self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass

    srv = HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        c = MsfRpc(host='127.0.0.1', port=port, password='x', ssl=False)
        assert c.login() and c.version()['version'] == '6.4.0'
        cid = c.console_create()['id']
        c.console_write(cid, 'search ms17_010')
        assert 'eternalblue' in c.console_read(cid)['data']
    finally:
        srv.shutdown()
