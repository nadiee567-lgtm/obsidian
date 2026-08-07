"""Continuous monitoring -- F7 step 95.

Periodically re-runs the case transforms and ALERTS when something changes: a new
entity (a subdomain/ip that appeared), a new relation, a changed property (an
expired cert, a port's service) or a new tag (takeover, vulnerable). It is what
turns a one-off scan into surveillance.

Testable design by INJECTION: the Monitor knows nothing about network or Flask.
It receives
  - snapshot_fn(): returns the store's current state (dict),
  - refrescar_fn(): re-runs the transforms (mutates the store),
  - on_alerta(changes): optional callback (ntfy in step 96).
So tests inject fake functions and never touch the network. The thread only wraps
`cycle()`, which is pure except for the callbacks."""
from __future__ import annotations
import datetime
import threading
from dataclasses import dataclass, field


def snapshot(store) -> dict:
    """Snapshot of the relevant state to detect changes."""
    ents = {}
    for e in store.entities:
        ents[e.id] = {
            'type': e.type,
            'value': e.value,
            'props': {k: str(v) for k, v in (e.properties or {}).items()},
            'tags': sorted(e.tags),
        }
    return {'ents': ents, 'rels': {r.id for r in store.relations}}


@dataclass
class Changes:
    """What changed between two snapshots."""
    new_entities: list = field(default_factory=list)   # dicts {type,value}  # noqa
    new_relations: list = field(default_factory=list)  # ids
    prop_changes: list = field(default_factory=list)       # {entity,type,campo,before,now}  # noqa

    def has_changes(self) -> bool:
        return bool(self.new_entities or self.new_relations or self.prop_changes)

    def summary(self) -> str:
        parts = []
        if self.new_entities:
            sample = ', '.join(e['value'] for e in self.new_entities[:3])
            more_n = f' (+{len(self.new_entities) - 3} more)' if len(self.new_entities) > 3 else ''
            parts.append(f'{len(self.new_entities)} new entity(ies): {sample}{more_n}')
        if self.prop_changes:
            parts.append(f'{len(self.prop_changes)} change(s) in existing data')
        if self.new_relations:
            parts.append(f'{len(self.new_relations)} new relation(s)')
        return ' · '.join(parts) or 'no changes'

    def to_dict(self) -> dict:
        return {'new_entities': self.new_entities,
                'new_relations': self.new_relations,
                'prop_changes': self.prop_changes}


def diff(before: dict, after: dict) -> Changes:
    """Compares two snapshots and returns the changes."""
    a, d = before['ents'], after['ents']
    new_ents = [{'type': d[i]['type'], 'value': d[i]['value']} for i in d if i not in a]
    new_rels = sorted(after['rels'] - before['rels'])
    changes = []
    for i in d:
        if i not in a:
            continue
        # properties that appeared or changed value
        for k, v in d[i]['props'].items():
            if a[i]['props'].get(k) != v:
                changes.append({'entity': d[i]['value'], 'type': d[i]['type'],
                                'field': k, 'before': a[i]['props'].get(k), 'now': v})
        # new tags (e.g. 'vulnerable', 'takeover' appear after a re-scan)
        for t in sorted(set(d[i]['tags']) - set(a[i]['tags'])):
            changes.append({'entity': d[i]['value'], 'type': d[i]['type'],
                            'field': 'tag', 'before': None, 'now': t})
    return Changes(new_ents, new_rels, changes)


def _ahora() -> str:
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


class Monitor:
    """Runs `cycle()` every `interval` seconds in a daemon thread."""

    def __init__(self, snapshot_fn, refrescar_fn, on_alerta=None,
                 interval: int = 300, max_alertas: int = 100):
        self.snapshot_fn = snapshot_fn
        self.refrescar_fn = refrescar_fn
        self.on_alerta = on_alerta
        self.interval = interval
        self.max_alertas = max_alertas
        self.alerts: list = []          # history of detected changes (newest first)
        self.last_cycle: str | None = None
        self._hilo: threading.Thread | None = None
        self._parar = threading.Event()

    @property
    def active(self) -> bool:
        return self._hilo is not None and self._hilo.is_alive()

    def cycle(self) -> Changes:
        """One cycle: snapshot, refresh, snapshot, diff, alert. Never raises (isolates failures)."""
        before = self.snapshot_fn()
        try:
            self.refrescar_fn()
        except Exception:
            pass                          # a network failure does not take down the monitor
        after = self.snapshot_fn()
        changes = diff(before, after)
        self.last_cycle = _ahora()
        if changes.has_changes():
            alerta = {'ts': self.last_cycle, 'summary': changes.summary(),
                      'changes': changes.to_dict()}
            self.alerts.insert(0, alerta)
            del self.alerts[self.max_alertas:]
            if self.on_alerta:
                try:
                    self.on_alerta(changes)
                except Exception:
                    pass
        return changes

    def _loop(self):
        # wait() returns True if stop was requested; False on timeout -> runs a cycle
        while not self._parar.wait(self.interval):
            self.cycle()

    def start(self):
        if self.active:
            return
        self._parar.clear()
        self._hilo = threading.Thread(target=self._loop, daemon=True)
        self._hilo.start()

    def stop(self):
        self._parar.set()
        self._hilo = None
