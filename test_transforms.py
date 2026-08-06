"""Tests for the transform engine (F2, steps 26-28, 35, 38).

Run:  ../.venv/bin/python -m pytest test_transforms.py -q
"""
import pytest
from core.modelo import Store, Entity
from core.eventos import Bus, ENTIDAD_NUEVA
import core.transforms as tr


@pytest.fixture(autouse=True)
def _registro_aislado():
    """Each test starts with an empty registry, but RESTORES whatever was there
    before when done -- so it does not wipe the real transforms the app registers
    (independent of test order)."""
    prev_entrada = {k: list(v) for k, v in tr.REGISTRO._por_entrada.items()}
    prev_nombre = dict(tr.REGISTRO._por_nombre)
    tr.REGISTRO.limpiar()
    yield
    tr.REGISTRO._por_entrada = prev_entrada
    tr.REGISTRO._por_nombre = prev_nombre


# ── contract + registry + decorator (steps 26, 27) ──────────────────────────
def test_decorator_registra():
    @tr.transform(entrada='dominio', salidas=('ip',), nombre='dns')
    def _f(entidad, ctx):
        pass
    assert tr.REGISTRO.por_nombre('dns') is not None
    assert tr.REGISTRO.aplicables('dominio')[0].nombre == 'dns'

def test_tipo_entrada_o_salida_invalido_falla():
    with pytest.raises(ValueError):
        tr.Transform(nombre='x', entrada='inventado')
    with pytest.raises(ValueError):
        tr.Transform(nombre='y', entrada='dominio', salidas=('inventado',))

def test_no_duplicar_nombre():
    tr.Transform  # noqa
    @tr.transform(entrada='ip', nombre='dup')
    def _a(entidad, ctx): pass
    with pytest.raises(ValueError):
        @tr.transform(entrada='ip', nombre='dup')
        def _b(entidad, ctx): pass


# ── execution: input → outputs, related and with provenance (step 28) ──────
def test_ejecutar_emite_relaciona_y_anota_procedencia():
    @tr.transform(entrada='dominio', salidas=('ip', 'subdominio'), nombre='dns')
    def _dns(entidad, ctx):
        ctx.emitir('ip', '93.184.216.34', etiqueta='A')
        ctx.emitir('subdominio', 'www.' + entidad.valor, etiqueta='subdominio')

    alm = Store()
    dom = alm.crear('dominio', 'example.com')
    producidas = tr.ejecutar_por_nombre('dns', dom, alm)

    assert len(producidas) == 2
    ip = alm.buscar('ip', '93.184.216.34')
    assert ip is not None
    # provenance recorded
    assert any(p['transform'] == 'dns' and p['input'] == dom.id for p in ip.procedencia)
    # relation created domain -> ip
    assert len(alm.relaciones) == 2

def test_ejecutar_valida_tipo_de_entrada():
    @tr.transform(entrada='dominio', nombre='solo_dominio')
    def _f(entidad, ctx): pass
    alm = Store()
    ip = alm.crear('ip', '8.8.8.8')
    with pytest.raises(ValueError):
        tr.ejecutar_por_nombre('solo_dominio', ip, alm)


# ── failure isolation (step 38) ─────────────────────────────────────────────
def test_transform_que_revienta_no_propaga():
    @tr.transform(entrada='dominio', salidas=('ip',), nombre='medio_roto')
    def _f(entidad, ctx):
        ctx.emitir('ip', '1.1.1.1')       # this does get through
        raise RuntimeError("boom")         # crashes afterwards

    alm = Store()
    dom = alm.crear('dominio', 'example.com')
    producidas = tr.ejecutar_por_nombre('medio_roto', dom, alm)   # does NOT raise
    assert len(producidas) == 1
    assert alm.buscar('ip', '1.1.1.1') is not None

def test_emitir_valor_basura_se_ignora():
    @tr.transform(entrada='dominio', salidas=('ip',), nombre='sucio')
    def _f(entidad, ctx):
        assert ctx.emitir('ip', '   ') is None   # empty value -> None, no crash
        ctx.emitir('ip', '8.8.8.8')

    alm = Store()
    dom = alm.crear('dominio', 'example.com')
    producidas = tr.ejecutar_por_nombre('sucio', dom, alm)
    assert len(producidas) == 1


# ── the engine fires the bus events (integration with step 19) ──────────────
def test_transform_dispara_eventos_del_bus():
    nuevas = []
    bus = Bus()
    bus.suscribir(ENTIDAD_NUEVA, lambda e: nuevas.append(e))

    @tr.transform(entrada='dominio', salidas=('ip',), nombre='dns')
    def _f(entidad, ctx):
        ctx.emitir('ip', '9.9.9.9')

    alm = Store(bus=bus)
    dom = alm.crear('dominio', 'example.com')   # 1 event
    tr.ejecutar_por_nombre('dns', dom, alm)     # +1 event (the ip)
    assert len(nuevas) == 2


# ── cache: do not repeat the same (transform, entity) -- step 41 ────────────
def test_corredor_cachea():
    corridas = []
    @tr.transform(entrada='dominio', salidas=('ip',), nombre='dns')
    def _f(entidad, ctx):
        corridas.append(1)
        ctx.emitir('ip', '8.8.8.8')

    alm = Store()
    dom = alm.crear('dominio', 'example.com')
    corr = tr.Runner(alm)
    corr.ejecutar('dns', dom)
    corr.ejecutar('dns', dom)      # second time: cache, does not re-run
    assert len(corridas) == 1


# ── Machine: chain that cascades from one type to the next -- step 39 ───────
def test_machine_cascada():
    @tr.transform(entrada='dominio', salidas=('ip',), nombre='dns')
    def _dns(entidad, ctx):
        ctx.emitir('ip', '93.184.216.34', etiqueta='A')

    @tr.transform(entrada='ip', salidas=('puerto',), nombre='ports')
    def _ports(entidad, ctx):
        ctx.emitir('puerto', '443', etiqueta='open')

    alm = Store()
    dom = alm.crear('dominio', 'example.com')
    receta = tr.Machine(nombre='recon', pasos=('dns', 'ports'))
    producidas = tr.Runner(alm).ejecutar_machine(receta, dom)

    tipos = sorted(e.tipo for e in producidas)
    assert tipos == ['ip', 'puerto']              # cascade: domain→ip→port
    assert alm.buscar('puerto', '443') is not None


# ── plugins: load transforms from a directory -- step 42 ────────────────────
def test_cargar_plugins(tmp_path):
    plugin = tmp_path / "mi_transform.py"
    plugin.write_text(
        "import core.transforms as tr\n"
        "@tr.transform(entrada='dominio', salidas=('ip',), nombre='plugin_dns')\n"
        "def f(entidad, ctx):\n"
        "    ctx.emitir('ip', '1.2.3.4')\n"
    )
    cargados = tr.cargar_plugins(str(tmp_path))
    assert 'mi_transform' in cargados
    assert tr.REGISTRO.por_nombre('plugin_dns') is not None
