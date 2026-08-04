"""Tests de las notificaciones ntfy (F7 paso 96).

Correr:  ../.venv/bin/python -m pytest test_notificar.py -q
"""
from core.notificar import construir_ntfy, enviar_ntfy


def test_construir_url_y_headers():
    url, headers, cuerpo = construir_ntfy('tiger-sebastian', 'algo cambió',
                                          titulo='OBSIDIAN', prioridad='high', tags='warning')
    assert url == 'https://ntfy.sh/tiger-sebastian'
    assert headers['Title'] == 'OBSIDIAN'
    assert headers['Priority'] == 'high'
    assert headers['Tags'] == 'warning'
    assert cuerpo == b'algo cambio'.replace(b'cambio', b'cambi\xc3\xb3')   # utf-8


def test_construir_respeta_server_propio():
    url, _, _ = construir_ntfy('t', 'x', server='https://ntfy.midominio.com/')
    assert url == 'https://ntfy.midominio.com/t'


def test_enviar_sin_topic_no_hace_nada():
    assert enviar_ntfy('', 'x') is False


def test_enviar_con_fallo_de_red_no_lanza(monkeypatch):
    import core.notificar as n
    def boom(*a, **k):
        raise RuntimeError('sin red')
    monkeypatch.setattr(n.requests, 'post', boom)
    assert enviar_ntfy('topic', 'x') is False        # no lanza, devuelve False
