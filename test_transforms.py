"""Tests for the transform engine (F2, steps 26-28, 35, 38).

Run:  ../.venv/bin/python -m pytest test_transforms.py -q
"""
import pytest
from core.modelo import Store, Entity
from core.eventos import Bus, ENTITY_NEW
import core.transforms as tr


@pytest.fixture(autouse=True)
def _registro_aislado():
    """Each test starts with an empty registry, but RESTORES whatever was there
    before when done -- so it does not wipe the real transforms the app registers
    (independent of test order)."""
    prev_entrada = {k: list(v) for k, v in tr.REGISTRO._by_input.items()}
    prev_nombre = dict(tr.REGISTRO._by_name)
    tr.REGISTRO.clear()
    yield
    tr.REGISTRO._by_input = prev_entrada
    tr.REGISTRO._by_name = prev_nombre


# ── contract + registry + decorator (steps 26, 27) ──────────────────────────
def test_decorator_registra():
    @tr.transform(input='domain', outputs=('ip',), name='dns')
    def _f(entity, ctx):
        pass
    assert tr.REGISTRO.by_name('dns') is not None
    assert tr.REGISTRO.applicable('domain')[0].name == 'dns'

def test_invalid_input_or_output_type_fails():
    with pytest.raises(ValueError):
        tr.Transform(name='x', input='inventado')
    with pytest.raises(ValueError):
        tr.Transform(name='y', input='domain', outputs=('inventado',))

def test_no_duplicate_name():
    tr.Transform  # noqa
    @tr.transform(input='ip', name='dup')
    def _a(entity, ctx): pass
    with pytest.raises(ValueError):
        @tr.transform(input='ip', name='dup')
        def _b(entity, ctx): pass


# ── execution: input → outputs, related and with provenance (step 28) ──────
def test_run_emits_relates_notes_provenance():
    @tr.transform(input='domain', outputs=('ip', 'subdomain'), name='dns')
    def _dns(entity, ctx):
        ctx.emit('ip', '93.184.216.34', label='A')
        ctx.emit('subdomain', 'www.' + entity.value, label='subdomain')

    store = Store()
    dom = store.create('domain', 'example.com')
    produced = tr.run_by_name('dns', dom, store)

    assert len(produced) == 2
    ip = store.find('ip', '93.184.216.34')
    assert ip is not None
    # provenance recorded
    assert any(p['transform'] == 'dns' and p['input'] == dom.id for p in ip.provenance)
    # relation created domain -> ip
    assert len(store.relations) == 2

def test_run_validates_input_type():
    @tr.transform(input='domain', name='domain_only')
    def _f(entity, ctx): pass
    store = Store()
    ip = store.create('ip', '8.8.8.8')
    with pytest.raises(ValueError):
        tr.run_by_name('domain_only', ip, store)


# ── failure isolation (step 38) ─────────────────────────────────────────────
def test_transform_crashes_no_propagate():
    @tr.transform(input='domain', outputs=('ip',), name='medio_roto')
    def _f(entity, ctx):
        ctx.emit('ip', '1.1.1.1')       # this does get through
        raise RuntimeError("boom")         # crashes afterwards

    store = Store()
    dom = store.create('domain', 'example.com')
    produced = tr.run_by_name('medio_roto', dom, store)   # does NOT raise
    assert len(produced) == 1
    assert store.find('ip', '1.1.1.1') is not None

def test_emit_value_garbage_ignores():
    @tr.transform(input='domain', outputs=('ip',), name='sucio')
    def _f(entity, ctx):
        assert ctx.emit('ip', '   ') is None   # empty value -> None, no crash
        ctx.emit('ip', '8.8.8.8')

    store = Store()
    dom = store.create('domain', 'example.com')
    produced = tr.run_by_name('sucio', dom, store)
    assert len(produced) == 1


# ── the engine fires the bus events (integration with step 19) ──────────────
def test_transform_fires_eventos_bus():
    nuevas = []
    bus = Bus()
    bus.subscribe(ENTITY_NEW, lambda e: nuevas.append(e))

    @tr.transform(input='domain', outputs=('ip',), name='dns')
    def _f(entity, ctx):
        ctx.emit('ip', '9.9.9.9')

    store = Store(bus=bus)
    dom = store.create('domain', 'example.com')   # 1 event
    tr.run_by_name('dns', dom, store)     # +1 event (the ip)
    assert len(nuevas) == 2


# ── cache: do not repeat the same (transform, entity) -- step 41 ────────────
def test_runner_caches():
    runs = []
    @tr.transform(input='domain', outputs=('ip',), name='dns')
    def _f(entity, ctx):
        runs.append(1)
        ctx.emit('ip', '8.8.8.8')

    store = Store()
    dom = store.create('domain', 'example.com')
    corr = tr.Runner(store)
    corr.run('dns', dom)
    corr.run('dns', dom)      # second time: cache, does not re-run
    assert len(runs) == 1


# ── Machine: chain that cascades from one type to the next -- step 39 ───────
def test_machine_cascada():
    @tr.transform(input='domain', outputs=('ip',), name='dns')
    def _dns(entity, ctx):
        ctx.emit('ip', '93.184.216.34', label='A')

    @tr.transform(input='ip', outputs=('port',), name='ports')
    def _ports(entity, ctx):
        ctx.emit('port', '443', label='open')

    store = Store()
    dom = store.create('domain', 'example.com')
    recipe = tr.Machine(name='recon', steps=('dns', 'ports'))
    produced = tr.Runner(store).run_machine(recipe, dom)

    tipos = sorted(e.type for e in produced)
    assert tipos == ['ip', 'port']              # cascade: domain→ip→port
    assert store.find('port', '443') is not None


# ── plugins: load transforms from a directory -- step 42 ────────────────────
def test_load_plugins(tmp_path):
    plugin = tmp_path / "mi_transform.py"
    plugin.write_text(
        "import core.transforms as tr\n"
        "@tr.transform(input='domain', outputs=('ip',), name='plugin_dns')\n"
        "def f(entity, ctx):\n"
        "    ctx.emit('ip', '1.2.3.4')\n"
    )
    cargados = tr.load_plugins(str(tmp_path))
    assert 'mi_transform' in cargados
    assert tr.REGISTRO.by_name('plugin_dns') is not None
