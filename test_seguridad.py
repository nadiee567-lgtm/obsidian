"""Tests for OBSIDIAN's security validators.

Goal: the closed vulnerabilities (command injection and argument injection) can
NOT come back without a test screaming. Roadmap F0 · step 12.

Run:  ../.venv/bin/python -m pytest test_seguridad.py -q
"""
import obsidian_web as ob


# ── argument injection: the exact exploit from the July 25 audit ─────────────
def test_argument_injection_nmap_bloqueada():
    # ip = "-oG/home/user/.bashrc" made nmap write files.
    assert ob._validate('-oG/home/user/.bashrc', 'ip') is False
    assert ob._validate('-oN/tmp/x', 'ip') is False
    assert ob._safe_target('-oG/algo') is False  # generic check too


# ── command injection: shell metacharacters ─────────────────────────────────
def test_command_injection_bloqueada():
    payloads = [
        'x; rm -rf ~', 'a && curl evil', 'b | nc attacker 1', '`id`',
        '$(whoami)', 'foo\nbar', 'a > /etc/passwd', "q' OR '1'='1",
    ]
    for p in payloads:
        assert ob._validate(p, 'domain') is False, p
        assert ob._validate(p, 'ip') is False, p
        assert ob._safe_target(p) is False, p


# ── allowlist: legitimate input DOES pass ───────────────────────────────────
def test_objetivos_validos_pasan():
    assert ob._validate('example.com', 'domain')
    assert ob._validate('sub.example.co.uk', 'domain')
    assert ob._validate('8.8.8.8', 'ip')
    assert ob._validate('2001:4860:4860::8888', 'ip')
    assert ob._validate('user_name-1.x', 'user')
    assert ob._validate('a@b.com', 'email')


# ── edge cases: empty, leading hyphen, spaces ───────────────────────────────
def test_bordes():
    assert ob._validate('', 'domain') is False
    assert ob._validate('   ', 'ip') is False
    assert ob._validate('-example.com', 'domain') is False   # leading hyphen
    assert ob._validate('exam ple.com', 'domain') is False   # space
    assert ob._validate('a' * 300, 'domain') is False         # too long
    assert ob._is_ip('999.999.999.999') is False


# ── the module→type map covers every module that touches the shell ──────────
def test_modulos_shell_tienen_tipo():
    for mod in ('user', 'domain', 'ip', 'email', 'ssl', 'typosquatting', 'takeover'):
        assert mod in ob._MODULO_TIPO


# ── SSRF (step 5): internal URLs blocked, public ones allowed ───────────────
def test_ssrf_urls_internas_bloqueadas():
    internas = [
        'http://127.0.0.1/', 'http://127.0.0.1:8767/api/status',
        'http://localhost/', 'http://169.254.169.254/latest/meta-data/',  # cloud metadata
        'http://10.0.0.1/', 'http://192.168.1.1/', 'http://172.16.0.5/',
        'http://[::1]/', 'http://0.0.0.0/',
        'file:///etc/passwd', 'ftp://internal/', 'gopher://x/',
    ]
    for u in internas:
        assert ob._public_url(u) is False, u

def test_ssrf_urls_publicas_ok():
    # public literal IPs: getaddrinfo needs no network to resolve them.
    assert ob._public_url('http://8.8.8.8/') is True
    assert ob._public_url('https://1.1.1.1/') is True


# ── path traversal (step 6): malicious case names neutralized ───────────────
def test_path_traversal_bloqueado():
    for malo in ['../../etc/passwd', '../../../home/user/.bashrc', '..', '.', '/etc/shadow',
                 'a/b', 'x\\y', '....//....//x']:
        assert ob._safe_case_path(malo) is None, malo

def test_valid_case_names_ok():
    for bueno in ['caso1', 'target.com', 'Investigacion 2026', 'mi_caso-01']:
        path = ob._safe_case_path(bueno)
        assert path is not None
        # and the path stays INSIDE CASES_DIR
        import os
        assert os.path.realpath(path).startswith(os.path.realpath(ob.CASES_DIR) + os.sep)
