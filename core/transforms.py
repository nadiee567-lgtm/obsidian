"""OBSIDIAN transform engine -- F2, steps 26-28.

Design copied from REAL, proven contracts, not invented:
  - Maltego: "a transform takes ONE input entity and produces ZERO OR MORE
    output entities", declared with a decorator with input/output type.
  - SpiderFoot: each module declares watchedEvents (consumes) / producedEvents
    (produces) / handleEvent (logic).

Here: @transform(input=<type>, outputs=(<types>)) registers a function
fn(entidad, ctx). The Context (ctx) is the ergonomic API for the author: emit
output entities that are added to the store, related to the input and get
their provenance recorded -- automatic.

PURE module: no Flask, no network. Concrete transforms (with network/APIs) are
registered on top; the engine only orchestrates them and ISOLATES their
failures (step 38)."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable

from core.modelo import Store, Entity, valid_type


@dataclass
class Transform:
    """A transform's contract (step 26). input = entity type it runs on;
    outputs = types it can produce; requires_key = needs an API key."""
    name: str
    input: str
    outputs: tuple = ()
    fn: Callable = None
    requires_key: bool = False
    description: str = ''

    def __post_init__(self):
        if not valid_type(self.input):
            raise ValueError(f"unknown input type: {self.input!r}")
        for s in self.outputs:
            if not valid_type(s):
                raise ValueError(f"unknown output type: {s!r}")


class _Registry:
    """Central transform catalog (step 27). Indexed by input type to answer
    quickly 'which transforms apply to this entity?' (step 35)."""
    def __init__(self):
        self._by_input: dict[str, list] = {}
        self._by_name: dict[str, Transform] = {}

    def registrar(self, t: Transform) -> Transform:
        if t.name in self._by_name:
            raise ValueError(f"duplicate transform: {t.name}")
        self._by_name[t.name] = t
        self._by_input.setdefault(t.input, []).append(t)
        return t

    def applicable(self, type: str) -> list:
        """Transforms that run on an entity of this type (step 35)."""
        return list(self._by_input.get(type, ()))

    def by_name(self, name: str) -> Transform | None:
        return self._by_name.get(name)

    def all_transforms(self) -> list:
        return list(self._by_name.values())

    def clear(self):
        self._by_input.clear()
        self._by_name.clear()


# Global registry (concrete transforms register themselves on import).
REGISTRO = _Registry()


def transform(input: str, outputs=(), name=None, requires_key=False, description=''):
    """Decorator that registers a function as a transform.

    @transform(input='domain', outputs=('ip','subdomain'))
    def resolver(entidad, ctx):
        ctx.emit('ip', '1.2.3.4', label='A')
    """
    def deco(fn):
        t = Transform(name=name or fn.__name__, input=input,
                      outputs=tuple(outputs), fn=fn,
                      requires_key=requires_key, description=description or (fn.__doc__ or '').strip())
        REGISTRO.registrar(t)
        return fn
    return deco


class Context:
    """API the transform author receives. `emit` creates an output entity, adds
    it to the store (dedup + events), relates it to the input and sets its
    provenance -- all automatic."""
    def __init__(self, almacen: Store, input: Entity, nombre_transform: str):
        self.almacen = almacen
        self.input = input
        self._nombre = nombre_transform
        self.emitidas: list = []

    def emit(self, type, value, label='', **properties) -> Entity | None:
        try:
            ent = Entity(type=type, value=value, properties=properties)
        except ValueError:
            return None   # garbage value: ignored, does not break the transform
        viva = self.almacen.add(ent)
        viva.note_provenance(self._nombre, input_id=self.input.id)
        self.almacen.relate(self.input, viva, label)
        self.emitidas.append(viva)
        return viva


# ── Per-transform rate limiting (step 40) ────────────────────────────────────
# A semaphore per transform limits how many concurrent runs touch its API, so as
# not to hammer third parties. No configured limit = no cap.
import threading as _threading

_SEMAFOROS: dict = {}
_LIMITES: dict = {}
_lock_lim = _threading.Lock()


def set_limite(name: str, max_concurrentes: int) -> None:
    """Configures a transform's max concurrency. <=0 removes the limit."""
    with _lock_lim:
        if max_concurrentes and max_concurrentes > 0:
            _LIMITES[name] = max_concurrentes
            _SEMAFOROS[name] = _threading.Semaphore(max_concurrentes)
        else:
            _LIMITES.pop(name, None)
            _SEMAFOROS.pop(name, None)


def limites() -> dict:
    return dict(_LIMITES)


def run(t: Transform, entidad: Entity, almacen: Store) -> list:
    """Runs a transform on an entity (step 28). Returns the produced entities.
    ISOLATES failures (step 38): if the transform crashes, it does not propagate
    -- it returns whatever it managed to emit. Honors the transform's rate limit
    (step 40)."""
    if entidad.type != t.input:
        raise ValueError(f"{t.name} expects '{t.input}', got '{entidad.type}'")
    ctx = Context(almacen, entidad, t.name)
    sem = _SEMAFOROS.get(t.name)
    try:
        if sem is not None:
            with sem:                       # no more than N concurrent of this transform
                t.fn(entidad, ctx)
        else:
            t.fn(entidad, ctx)
    except Exception:
        pass   # a transform failure does not take down the case
    return ctx.emitidas


def run_by_name(name: str, entidad: Entity, almacen: Store) -> list:
    t = REGISTRO.by_name(name)
    if t is None:
        raise KeyError(f"transform not registered: {name}")
    return run(t, entidad, almacen)


def run_batch(tareas, almacen: Store, max_workers: int = 8, lock=None,
                  on_progreso=None) -> list:
    """Runs several transforms IN PARALLEL (step 102). Transforms are I/O-bound
    (network), so they are launched concurrently -- each in an ISOLATED Store, no
    shared state during the fetch. When done, results are merged into `almacen`
    (dedup by deterministic id). If `lock` is passed, the merge runs under it.

    on_progreso(name, n, hechas, total): optional callback called as EACH
    transform finishes (step 37, for progress streaming).

    tareas: iterable of (type, value, transform_name).
    Returns [(name, n_produced), ...]."""
    import contextlib
    from concurrent.futures import ThreadPoolExecutor, as_completed

    tareas = list(tareas)
    if not tareas:
        return []

    def _uno(t):
        type, value, name = t
        local = Store()
        n = 0
        try:
            semilla = local.create(type, value)
            n = len(run_by_name(name, semilla, local))
        except Exception:
            pass
        return name, n, local

    resultados, locales, total = [], [], len(tareas)
    with ThreadPoolExecutor(max_workers=min(max_workers, total)) as ex:
        futs = [ex.submit(_uno, t) for t in tareas]
        for i, fut in enumerate(as_completed(futs), 1):
            name, n, local = fut.result()
            resultados.append((name, n))
            locales.append(local)
            if on_progreso:
                try:
                    on_progreso(name, n, i, total)
                except Exception:
                    pass

    ctx = lock if lock is not None else contextlib.nullcontext()
    with ctx:                                    # serialized merge (consistent dedup)
        for local in locales:
            for e in local.entities:
                almacen.add(e)
            for r in local.relations:
                almacen.relate(r.source, r.target, r.label)
    return resultados


# ── Step 39: Machines (recipes = chains of transforms, Maltego-style) ────────
@dataclass
class Machine:
    """A recipe: transforms in order that cascade from one type to the next.
    E.g. ['dns_resolver','port_scan'] -> domain->ips, then ips->ports."""
    name: str
    pasos: tuple = ()
    description: str = ''


# ── Step 41: Runner with cache (don't repeat the same expensive query) ───────
class Runner:
    """Runs transforms/machines over a store, remembering which
    (transform, entity) pairs already ran to avoid repeating them in the same session."""
    def __init__(self, almacen: Store):
        self.almacen = almacen
        self._hechos: set = set()   # {(transform_name, entity_id)}

    def run(self, name: str, entidad: Entity) -> list:
        clave = (name, entidad.id)
        if clave in self._hechos:
            return []               # cache: already ran on this entity
        self._hechos.add(clave)
        return run_by_name(name, entidad, self.almacen)

    def run_machine(self, machine: Machine, semilla: Entity) -> list:
        """Runs the recipe: each step runs on the entities of the type it
        expects (seed + what was produced before). The cache avoids re-running."""
        pool = {semilla.id: semilla}
        producidas = []
        for paso in machine.pasos:
            t = REGISTRO.by_name(paso)
            if t is None:
                continue
            objetivos = [e for e in list(pool.values()) if e.type == t.input]
            for ent in objetivos:
                for nueva in self.run(paso, ent):
                    pool[nueva.id] = nueva
                    producidas.append(nueva)
        return producidas


# ── Step 42: load transforms from plugins (without touching the core) ────────
def load_plugins(directorio: str) -> list:
    """Imports each .py in `directorio` (which self-registers via @transform).
    Extensible like Maltego's Transform Hub. Returns the loaded names."""
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
