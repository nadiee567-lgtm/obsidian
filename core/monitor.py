"""Continuous monitoring -- F7 step 95.

Periodically re-runs the case transforms and ALERTS when something changes: a new
entity (a subdomain/ip that appeared), a new relation, a changed property (an
expired cert, a port's service) or a new tag (takeover, vulnerable). It is what
turns a one-off scan into surveillance.

Testable design by INJECTION: the Monitor knows nothing about network or Flask.
It receives
  - snapshot_fn(): returns the store's current state (dict),
  - refrescar_fn(): re-runs the transforms (mutates the store),
  - on_alerta(cambios): optional callback (ntfy in step 96).
So tests inject fake functions and never touch the network. The thread only wraps
`ciclo()`, which is pure except for the callbacks."""
from __future__ import annotations
import datetime
import threading
from dataclasses import dataclass, field


def snapshot(almacen) -> dict:
    """Snapshot of the relevant state to detect changes."""
    ents = {}
    for e in almacen.entities:
        ents[e.id] = {
            'type': e.type,
            'value': e.value,
            'props': {k: str(v) for k, v in (e.properties or {}).items()},
            'tags': sorted(e.tags),
        }
    return {'ents': ents, 'rels': {r.id for r in almacen.relations}}


@dataclass
class Changes:
    """What changed between two snapshots."""
    nuevas_entidades: list = field(default_factory=list)   # dicts {type,value}  # noqa
    nuevas_relaciones: list = field(default_factory=list)  # ids
    cambios_prop: list = field(default_factory=list)       # {entidad,type,campo,antes,ahora}  # noqa

    def hay(self) -> bool:
        return bool(self.nuevas_entidades or self.nuevas_relaciones or self.cambios_prop)

    def summary(self) -> str:
        partes = []
        if self.nuevas_entidades:
            ej = ', '.join(e['value'] for e in self.nuevas_entidades[:3])
            mas = f' (+{len(self.nuevas_entidades) - 3} more)' if len(self.nuevas_entidades) > 3 else ''
            partes.append(f'{len(self.nuevas_entidades)} new entity(ies): {ej}{mas}')
        if self.cambios_prop:
            partes.append(f'{len(self.cambios_prop)} change(s) in existing data')
        if self.nuevas_relaciones:
            partes.append(f'{len(self.nuevas_relaciones)} new relation(s)')
        return ' · '.join(partes) or 'no changes'

    def to_dict(self) -> dict:
        return {'nuevas_entidades': self.nuevas_entidades,
                'nuevas_relaciones': self.nuevas_relaciones,
                'cambios_prop': self.cambios_prop}


def diff(antes: dict, despues: dict) -> Changes:
    """Compares two snapshots and returns the changes."""
    a, d = antes['ents'], despues['ents']
    nuevas = [{'type': d[i]['type'], 'value': d[i]['value']} for i in d if i not in a]
    nuevas_rel = sorted(despues['rels'] - antes['rels'])
    cambios = []
    for i in d:
        if i not in a:
            continue
        # properties that appeared or changed value
        for k, v in d[i]['props'].items():
            if a[i]['props'].get(k) != v:
                cambios.append({'entidad': d[i]['value'], 'type': d[i]['type'],
                                'campo': k, 'antes': a[i]['props'].get(k), 'ahora': v})
        # new tags (e.g. 'vulnerable', 'takeover' appear after a re-scan)
        for t in sorted(set(d[i]['tags']) - set(a[i]['tags'])):
            cambios.append({'entidad': d[i]['value'], 'type': d[i]['type'],
                            'campo': 'tag', 'antes': None, 'ahora': t})
    return Changes(nuevas, nuevas_rel, cambios)


def _ahora() -> str:
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


class Monitor:
    """Runs `ciclo()` every `intervalo` seconds in a daemon thread."""

    def __init__(self, snapshot_fn, refrescar_fn, on_alerta=None,
                 intervalo: int = 300, max_alertas: int = 100):
        self.snapshot_fn = snapshot_fn
        self.refrescar_fn = refrescar_fn
        self.on_alerta = on_alerta
        self.intervalo = intervalo
        self.max_alertas = max_alertas
        self.alertas: list = []          # history of detected changes (newest first)
        self.ultimo_ciclo: str | None = None
        self._hilo: threading.Thread | None = None
        self._parar = threading.Event()

    @property
    def activo(self) -> bool:
        return self._hilo is not None and self._hilo.is_alive()

    def ciclo(self) -> Changes:
        """One cycle: snapshot, refresh, snapshot, diff, alert. Never raises (isolates failures)."""
        antes = self.snapshot_fn()
        try:
            self.refrescar_fn()
        except Exception:
            pass                          # a network failure does not take down the monitor
        despues = self.snapshot_fn()
        cambios = diff(antes, despues)
        self.ultimo_ciclo = _ahora()
        if cambios.hay():
            alerta = {'ts': self.ultimo_ciclo, 'summary': cambios.summary(),
                      'cambios': cambios.to_dict()}
            self.alertas.insert(0, alerta)
            del self.alertas[self.max_alertas:]
            if self.on_alerta:
                try:
                    self.on_alerta(cambios)
                except Exception:
                    pass
        return cambios

    def _loop(self):
        # wait() returns True if stop was requested; False on timeout -> runs a cycle
        while not self._parar.wait(self.intervalo):
            self.ciclo()

    def iniciar(self):
        if self.activo:
            return
        self._parar.clear()
        self._hilo = threading.Thread(target=self._loop, daemon=True)
        self._hilo.start()

    def detener(self):
        self._parar.set()
        self._hilo = None
