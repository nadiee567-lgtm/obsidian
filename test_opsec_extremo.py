"""Extreme OPSEC: kill-switch (fail-closed) and paranoid mode."""
import pytest
import obsidian_web as ob


def _reset():
    ob._OPSEC['anonimo'] = False
    ob._OPSEC['killswitch'] = False
    ob._OPSEC['paranoid'] = False
    ob._PROXIES['pool'] = []
    ob._OPSEC_HIGIENE['on'] = False
    ob._OPSEC_JITTER['min'] = ob._OPSEC_JITTER['max'] = 0.0


def test_killswitch_off_never_blocks():
    _reset()
    ob._opsec_guard()          # no raise when the kill-switch is off
    _reset()


def test_killswitch_blocks_when_not_anonymous():
    _reset()
    ob._OPSEC['killswitch'] = True     # on, but anonymity is off
    with pytest.raises(ValueError):
        ob._opsec_guard()              # fails CLOSED -> would not leak the real IP
    _reset()


def test_killswitch_allows_when_anonymized_and_no_leak(monkeypatch):
    _reset()
    ob._OPSEC['killswitch'] = True
    ob._PROXIES['pool'] = ['socks5h://127.0.0.1:9050']   # anonymity engaged
    monkeypatch.setattr(ob, '_verify_anon',
                        lambda force=False: {'exit_ip': '1.2.3.4', 'real_ip': '9.9.9.9', 'leak': False})
    ob._opsec_guard()          # no raise: verified anonymous, no leak
    _reset()


def test_killswitch_blocks_on_detected_leak(monkeypatch):
    _reset()
    ob._OPSEC['killswitch'] = True
    ob._PROXIES['pool'] = ['socks5h://127.0.0.1:9050']
    monkeypatch.setattr(ob, '_verify_anon',
                        lambda force=False: {'exit_ip': '5.5.5.5', 'real_ip': '5.5.5.5', 'leak': True})
    with pytest.raises(ValueError):
        ob._opsec_guard()
    _reset()


def test_paranoid_engages_and_disengages_everything():
    _reset()
    ob._paranoid(True)
    assert ob._OPSEC['paranoid'] and ob._OPSEC['killswitch']
    assert ob._OPSEC_HIGIENE['on'] and ob._OPSEC_JITTER['max'] > 0
    ob._paranoid(False)
    assert not ob._OPSEC['paranoid'] and not ob._OPSEC['killswitch']
    assert not ob._OPSEC_HIGIENE['on'] and ob._OPSEC_JITTER['max'] == 0
    _reset()


def test_evaluate_leak_pure():
    # anonymous but exit IP == real IP -> leak
    assert ob._evaluate_leak(True, '1.1.1.1', '1.1.1.1') is True
    # anonymous and different IPs -> no leak
    assert ob._evaluate_leak(True, '1.1.1.1', '2.2.2.2') is False
    # not anonymous -> never counted as a leak
    assert ob._evaluate_leak(False, '1.1.1.1', '1.1.1.1') is False
