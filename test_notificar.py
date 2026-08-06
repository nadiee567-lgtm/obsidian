"""Tests for the ntfy notifications (F7 step 96).

Run:  ../.venv/bin/python -m pytest test_notificar.py -q
"""
from core.notificar import build_ntfy, send_ntfy


def test_construir_url_y_headers():
    url, headers, cuerpo = build_ntfy('my-topic', 'São Paulo alert',
                                          titulo='OBSIDIAN', prioridad='high', tags='warning')
    assert url == 'https://ntfy.sh/my-topic'
    assert headers['Title'] == 'OBSIDIAN'
    assert headers['Priority'] == 'high'
    assert headers['Tags'] == 'warning'
    assert cuerpo == 'São Paulo alert'.encode('utf-8')   # utf-8 body


def test_construir_respeta_server_propio():
    url, _, _ = build_ntfy('t', 'x', server='https://ntfy.mydomain.com/')
    assert url == 'https://ntfy.mydomain.com/t'


def test_enviar_sin_topic_no_hace_nada():
    assert send_ntfy('', 'x') is False


def test_enviar_con_fallo_de_red_no_lanza(monkeypatch):
    import core.notificar as n
    def boom(*a, **k):
        raise RuntimeError('no network')
    monkeypatch.setattr(n.requests, 'post', boom)
    assert send_ntfy('topic', 'x') is False        # does not raise, returns False
