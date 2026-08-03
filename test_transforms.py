"""Tests del motor de transforms (F2, pasos 26-28, 35, 38).

Correr:  ../.venv/bin/python -m pytest test_transforms.py -q
"""
import pytest
from core.modelo import Almacen, Entidad
from core.eventos import Bus, ENTIDAD_NUEVA
import core.transforms as tr


@pytest.fixture(autouse=True)
def _registro_limpio():
    """Cada test arranca con el registro vacío (aislamiento)."""
    tr.REGISTRO.limpiar()
    yield
    tr.REGISTRO.limpiar()


# ── contrato + registro + decorator (pasos 26, 27) ───────────────────────────
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


# ── ejecución: entrada → salidas, relacionadas y con procedencia (paso 28) ──
def test_ejecutar_emite_relaciona_y_anota_procedencia():
    @tr.transform(entrada='dominio', salidas=('ip', 'subdominio'), nombre='dns')
    def _dns(entidad, ctx):
        ctx.emitir('ip', '93.184.216.34', etiqueta='A')
        ctx.emitir('subdominio', 'www.' + entidad.valor, etiqueta='subdominio')

    alm = Almacen()
    dom = alm.crear('dominio', 'example.com')
    producidas = tr.ejecutar_por_nombre('dns', dom, alm)

    assert len(producidas) == 2
    ip = alm.buscar('ip', '93.184.216.34')
    assert ip is not None
    # procedencia registrada
    assert any(p['transform'] == 'dns' and p['input'] == dom.id for p in ip.procedencia)
    # relación creada dominio -> ip
    assert len(alm.relaciones) == 2

def test_ejecutar_valida_tipo_de_entrada():
    @tr.transform(entrada='dominio', nombre='solo_dominio')
    def _f(entidad, ctx): pass
    alm = Almacen()
    ip = alm.crear('ip', '8.8.8.8')
    with pytest.raises(ValueError):
        tr.ejecutar_por_nombre('solo_dominio', ip, alm)


# ── aislamiento de fallos (paso 38) ──────────────────────────────────────────
def test_transform_que_revienta_no_propaga():
    @tr.transform(entrada='dominio', salidas=('ip',), nombre='medio_roto')
    def _f(entidad, ctx):
        ctx.emitir('ip', '1.1.1.1')       # esto sí alcanza a pasar
        raise RuntimeError("boom")         # revienta después

    alm = Almacen()
    dom = alm.crear('dominio', 'example.com')
    producidas = tr.ejecutar_por_nombre('medio_roto', dom, alm)   # NO lanza
    assert len(producidas) == 1
    assert alm.buscar('ip', '1.1.1.1') is not None

def test_emitir_valor_basura_se_ignora():
    @tr.transform(entrada='dominio', salidas=('ip',), nombre='sucio')
    def _f(entidad, ctx):
        assert ctx.emitir('ip', '   ') is None   # valor vacío -> None, no crashea
        ctx.emitir('ip', '8.8.8.8')

    alm = Almacen()
    dom = alm.crear('dominio', 'example.com')
    producidas = tr.ejecutar_por_nombre('sucio', dom, alm)
    assert len(producidas) == 1


# ── el motor dispara los eventos del bus (integración con paso 19) ───────────
def test_transform_dispara_eventos_del_bus():
    nuevas = []
    bus = Bus()
    bus.suscribir(ENTIDAD_NUEVA, lambda e: nuevas.append(e))

    @tr.transform(entrada='dominio', salidas=('ip',), nombre='dns')
    def _f(entidad, ctx):
        ctx.emitir('ip', '9.9.9.9')

    alm = Almacen(bus=bus)
    dom = alm.crear('dominio', 'example.com')   # 1 evento
    tr.ejecutar_por_nombre('dns', dom, alm)     # +1 evento (la ip)
    assert len(nuevas) == 2
