"""OBSIDIAN transform engine -- F2, steps 26-28.

Design copied from REAL, proven contracts, not invented:
  - Maltego: "a transform takes ONE input entity and produces ZERO OR MORE
    output entities", declared with a decorator with input/output type.
  - SpiderFoot: each module declares watchedEvents (consumes) / producedEvents
    (produces) / handleEvent (logic).

Here: @transform(input=<type>, outputs=(<types>)) registers a function
fn(entity, ctx). The Context (ctx) is the ergonomic API for the author: emit
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


REGISTRO = _Registry()


def transform(input: str, outputs=(), name=None, requires_key=False, description=''):
    """Decorator that registers a function as a transform.

    @transform(input='domain', outputs=('ip','subdomain'))
    def resolver(entity, ctx):
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
    def __init__(self, store: Store, input: Entity, nombre_transform: str):
        self.store = store
        self.input = input
        self._nombre = nombre_transform
        self.emitidas: list = []

    def emit(self, type, value, label='', **properties) -> Entity | None:
        try:
            ent = Entity(type=type, value=value, properties=properties)
        except ValueError:
            return None
        viva = self.store.add(ent)
        viva.note_provenance(self._nombre, input_id=self.input.id)
        self.store.relate(self.input, viva, label)
        self.emitidas.append(viva)
        return viva


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


def run(t: Transform, entity: Entity, store: Store) -> list:
    """Runs a transform on an entity (step 28). Returns the produced entities.
    ISOLATES failures (step 38): if the transform crashes, it does not propagate
    -- it returns whatever it managed to emit. Honors the transform's rate limit
    (step 40)."""
    if entity.type != t.input:
        raise ValueError(f"{t.name} expects '{t.input}', got '{entity.type}'")
    ctx = Context(store, entity, t.name)
    sem = _SEMAFOROS.get(t.name)
    try:
        if sem is not None:
            with sem:
                t.fn(entity, ctx)
        else:
            t.fn(entity, ctx)
    except Exception:
        pass
    return ctx.emitidas


def run_by_name(name: str, entity: Entity, store: Store) -> list:
    t = REGISTRO.by_name(name)
    if t is None:
        raise KeyError(f"transform not registered: {name}")
    return run(t, entity, store)


def run_batch(tasks, store: Store, max_workers: int = 8, lock=None,
                  on_progreso=None) -> list:
    """Runs several transforms IN PARALLEL (step 102). Transforms are I/O-bound
    (network), so they are launched concurrently -- each in an ISOLATED Store, no
    shared state during the fetch. When done, results are merged into `store`
    (dedup by deterministic id). If `lock` is passed, the merge runs under it.

    on_progreso(name, n, hechas, total): optional callback called as EACH
    transform finishes (step 37, for progress streaming).

    tasks: iterable of (type, value, transform_name).
    Returns [(name, n_produced), ...]."""
    import contextlib
    from concurrent.futures import ThreadPoolExecutor, as_completed

    tasks = list(tasks)
    if not tasks:
        return []

    def _uno(t):
        type, value, name = t
        local = Store()
        n = 0
        try:
            seed = local.create(type, value)
            n = len(run_by_name(name, seed, local))
        except Exception:
            pass
        return name, n, local

    results, locales, total = [], [], len(tasks)
    with ThreadPoolExecutor(max_workers=min(max_workers, total)) as ex:
        futs = [ex.submit(_uno, t) for t in tasks]
        for i, fut in enumerate(as_completed(futs), 1):
            name, n, local = fut.result()
            results.append((name, n))
            locales.append(local)
            if on_progreso:
                try:
                    on_progreso(name, n, i, total)
                except Exception:
                    pass

    ctx = lock if lock is not None else contextlib.nullcontext()
    with ctx:
        for local in locales:
            for e in local.entities:
                store.add(e)
            for r in local.relations:
                store.relate(r.source, r.target, r.label)
    return results


@dataclass
class Machine:
    """A recipe: transforms in order that cascade from one type to the next.
    E.g. ['dns_resolver','port_scan'] -> domain->ips, then ips->ports."""
    name: str
    steps: tuple = ()
    description: str = ''


class Runner:
    """Runs transforms/machines over a store, remembering which
    (transform, entity) pairs already ran to avoid repeating them in the same session."""
    def __init__(self, store: Store):
        self.store = store
        self._hechos: set = set()

    def run(self, name: str, entity: Entity) -> list:
        key = (name, entity.id)
        if key in self._hechos:
            return []
        self._hechos.add(key)
        return run_by_name(name, entity, self.store)

    def run_machine(self, machine: Machine, seed: Entity) -> list:
        """Runs the recipe: each step runs on the entities of the type it
        expects (seed + what was produced before). The cache avoids re-running."""
        pool = {seed.id: seed}
        produced = []
        for step in machine.steps:
            t = REGISTRO.by_name(step)
            if t is None:
                continue
            targets = [e for e in list(pool.values()) if e.type == t.input]
            for ent in targets:
                for new_one in self.run(step, ent):
                    pool[new_one.id] = new_one
                    produced.append(new_one)
        return produced


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
