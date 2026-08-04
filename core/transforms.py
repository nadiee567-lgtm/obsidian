"""Motor de transforms de OBSIDIAN — F2, pasos 26-28.

Diseño copiado de contratos REALES y probados, no inventado:
  - Maltego: "un transform toma UNA entidad de entrada y produce CERO O MÁS
    entidades de salida", declarado con un decorator con tipo de entrada/salida.
  - SpiderFoot: cada módulo declara watchedEvents (consume) / producedEvents
    (produce) / handleEvent (lógica).

Aquí: @transform(entrada=<tipo>, salidas=(<tipos>)) registra una función
fn(entidad, ctx). El Contexto (ctx) es la API ergonómica para el autor: emitir
entidades de salida que se agregan al almacén, se relacionan con la entrada y
registran procedencia — automático.

Módulo PURO: sin Flask, sin red. Los transforms concretos (con red/APIs) se
registran encima; el motor solo los orquesta y AÍSLA sus fallos (paso 38)."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable

from core.modelo import Almacen, Entidad, tipo_valido


@dataclass
class Transform:
    """Contrato de un transform (paso 26). entrada = tipo de entidad sobre el que
    corre; salidas = tipos que puede producir; requiere_key = necesita API key."""
    nombre: str
    entrada: str
    salidas: tuple = ()
    fn: Callable = None
    requiere_key: bool = False
    descripcion: str = ''

    def __post_init__(self):
        if not tipo_valido(self.entrada):
            raise ValueError(f"tipo de entrada desconocido: {self.entrada!r}")
        for s in self.salidas:
            if not tipo_valido(s):
                raise ValueError(f"tipo de salida desconocido: {s!r}")


class _Registro:
    """Catálogo central de transforms (paso 27). Indexado por tipo de entrada
    para responder rápido '¿qué transforms aplican a esta entidad?' (paso 35)."""
    def __init__(self):
        self._por_entrada: dict[str, list] = {}
        self._por_nombre: dict[str, Transform] = {}

    def registrar(self, t: Transform) -> Transform:
        if t.nombre in self._por_nombre:
            raise ValueError(f"transform duplicado: {t.nombre}")
        self._por_nombre[t.nombre] = t
        self._por_entrada.setdefault(t.entrada, []).append(t)
        return t

    def aplicables(self, tipo: str) -> list:
        """Transforms que corren sobre una entidad de este tipo (paso 35)."""
        return list(self._por_entrada.get(tipo, ()))

    def por_nombre(self, nombre: str) -> Transform | None:
        return self._por_nombre.get(nombre)

    def todos(self) -> list:
        return list(self._por_nombre.values())

    def limpiar(self):
        self._por_entrada.clear()
        self._por_nombre.clear()


# Registro global (los transforms concretos se registran al importarse).
REGISTRO = _Registro()


def transform(entrada: str, salidas=(), nombre=None, requiere_key=False, descripcion=''):
    """Decorator que registra una función como transform.

    @transform(entrada='dominio', salidas=('ip','subdominio'))
    def resolver(entidad, ctx):
        ctx.emitir('ip', '1.2.3.4', etiqueta='A')
    """
    def deco(fn):
        t = Transform(nombre=nombre or fn.__name__, entrada=entrada,
                      salidas=tuple(salidas), fn=fn,
                      requiere_key=requiere_key, descripcion=descripcion or (fn.__doc__ or '').strip())
        REGISTRO.registrar(t)
        return fn
    return deco


class Contexto:
    """API que recibe el autor del transform. `emitir` crea una entidad de salida,
    la agrega al almacén (dedup + eventos), la relaciona con la entrada y le pone
    la procedencia — todo automático."""
    def __init__(self, almacen: Almacen, entrada: Entidad, nombre_transform: str):
        self.almacen = almacen
        self.entrada = entrada
        self._nombre = nombre_transform
        self.emitidas: list = []

    def emitir(self, tipo, valor, etiqueta='', **propiedades) -> Entidad | None:
        try:
            ent = Entidad(tipo=tipo, valor=valor, propiedades=propiedades)
        except ValueError:
            return None   # valor basura: se ignora, no rompe el transform
        viva = self.almacen.agregar(ent)
        viva.anotar_procedencia(self._nombre, input_id=self.entrada.id)
        self.almacen.relacionar(self.entrada, viva, etiqueta)
        self.emitidas.append(viva)
        return viva


# ── Rate limiting por transform (paso 40) ────────────────────────────────────
# Un semáforo por transform limita cuántas ejecuciones concurrentes tocan su API,
# para no reventar a los terceros. Sin límite configurado = sin tope.
import threading as _threading

_SEMAFOROS: dict = {}
_LIMITES: dict = {}
_lock_lim = _threading.Lock()


def set_limite(nombre: str, max_concurrentes: int) -> None:
    """Configura la concurrencia máxima de un transform. <=0 quita el límite."""
    with _lock_lim:
        if max_concurrentes and max_concurrentes > 0:
            _LIMITES[nombre] = max_concurrentes
            _SEMAFOROS[nombre] = _threading.Semaphore(max_concurrentes)
        else:
            _LIMITES.pop(nombre, None)
            _SEMAFOROS.pop(nombre, None)


def limites() -> dict:
    return dict(_LIMITES)


def ejecutar(t: Transform, entidad: Entidad, almacen: Almacen) -> list:
    """Corre un transform sobre una entidad (paso 28). Devuelve las entidades
    producidas. AÍSLA fallos (paso 38): si el transform revienta, no propaga —
    devuelve lo que alcanzó a emitir. Respeta el rate limit del transform (paso 40)."""
    if entidad.tipo != t.entrada:
        raise ValueError(f"{t.nombre} espera '{t.entrada}', recibió '{entidad.tipo}'")
    ctx = Contexto(almacen, entidad, t.nombre)
    sem = _SEMAFOROS.get(t.nombre)
    try:
        if sem is not None:
            with sem:                       # no más de N concurrentes de este transform
                t.fn(entidad, ctx)
        else:
            t.fn(entidad, ctx)
    except Exception:
        pass   # el fallo de un transform no tumba el caso
    return ctx.emitidas


def ejecutar_por_nombre(nombre: str, entidad: Entidad, almacen: Almacen) -> list:
    t = REGISTRO.por_nombre(nombre)
    if t is None:
        raise KeyError(f"transform no registrado: {nombre}")
    return ejecutar(t, entidad, almacen)


def ejecutar_lote(tareas, almacen: Almacen, max_workers: int = 8, lock=None) -> list:
    """Corre varios transforms EN PARALELO (paso 102). Los transforms son I/O-bound
    (red), así que se lanzan concurrentemente — cada uno en un Almacen AISLADO, sin
    estado compartido durante el fetch. Al terminar, se fusionan los resultados en
    `almacen` (dedup por id determinista). Si se pasa `lock`, la fusión va bajo él.

    tareas: iterable de (tipo, valor, nombre_transform).
    Devuelve [(nombre, nº_producidas), ...]."""
    import contextlib
    from concurrent.futures import ThreadPoolExecutor

    tareas = list(tareas)
    if not tareas:
        return []

    def _uno(t):
        tipo, valor, nombre = t
        local = Almacen()
        n = 0
        try:
            semilla = local.crear(tipo, valor)
            n = len(ejecutar_por_nombre(nombre, semilla, local))
        except Exception:
            pass
        return nombre, n, local

    with ThreadPoolExecutor(max_workers=min(max_workers, len(tareas))) as ex:
        salidas = list(ex.map(_uno, tareas))    # la red corre en paralelo, sin lock

    resultados = []
    ctx = lock if lock is not None else contextlib.nullcontext()
    with ctx:                                    # fusión serializada (dedup consistente)
        for nombre, n, local in salidas:
            resultados.append((nombre, n))
            for e in local.entidades:
                almacen.agregar(e)
            for r in local.relaciones:
                almacen.relacionar(r.origen, r.destino, r.etiqueta)
    return resultados


# ── Paso 39: Machines (recetas = cadenas de transforms, estilo Maltego) ──────
@dataclass
class Machine:
    """Una receta: transforms en orden que cascada de un tipo al siguiente.
    Ej: ['dns_resolver','port_scan'] → dominio→ips, luego ips→puertos."""
    nombre: str
    pasos: tuple = ()
    descripcion: str = ''


# ── Paso 41: Corredor con caché (no repetir la misma consulta cara) ──────────
class Corredor:
    """Ejecuta transforms/machines sobre un almacén, recordando qué
    (transform, entidad) ya corrió para no repetirlo en la misma sesión."""
    def __init__(self, almacen: Almacen):
        self.almacen = almacen
        self._hechos: set = set()   # {(nombre_transform, entidad_id)}

    def ejecutar(self, nombre: str, entidad: Entidad) -> list:
        clave = (nombre, entidad.id)
        if clave in self._hechos:
            return []               # caché: ya se corrió sobre esta entidad
        self._hechos.add(clave)
        return ejecutar_por_nombre(nombre, entidad, self.almacen)

    def ejecutar_machine(self, machine: Machine, semilla: Entidad) -> list:
        """Corre la receta: cada paso corre sobre las entidades del tipo que
        espera (semilla + lo producido antes). El caché evita re-ejecutar."""
        pool = {semilla.id: semilla}
        producidas = []
        for paso in machine.pasos:
            t = REGISTRO.por_nombre(paso)
            if t is None:
                continue
            objetivos = [e for e in list(pool.values()) if e.tipo == t.entrada]
            for ent in objetivos:
                for nueva in self.ejecutar(paso, ent):
                    pool[nueva.id] = nueva
                    producidas.append(nueva)
        return producidas


# ── Paso 42: cargar transforms desde plugins (sin tocar el core) ─────────────
def cargar_plugins(directorio: str) -> list:
    """Importa cada .py de `directorio` (que se auto-registra con @transform).
    Extensible como el Transform Hub de Maltego. Devuelve los nombres cargados."""
    import importlib.util
    import os
    import glob
    cargados = []
    for ruta in sorted(glob.glob(os.path.join(directorio, '*.py'))):
        base = os.path.splitext(os.path.basename(ruta))[0]
        if base.startswith('_'):
            continue
        spec = importlib.util.spec_from_file_location(f"obsidian_plugin_{base}", ruta)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cargados.append(base)
    return cargados
