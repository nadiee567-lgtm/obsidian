"""Background task queue + events for SSE -- F2 step 37.

A long task (recon of many transforms) must not block the HTTP request: it is
launched in a thread, returns an id immediately, and the client listens to live
progress via Server-Sent Events. PURE module (knows nothing of Flask): exposes
events as a queue that the SSE endpoint drains.

The job receives an `emit(event)` to publish progress. When it finishes an event
{'tipo':'fin'} is enqueued."""
from __future__ import annotations
import queue
import threading
import uuid


class TaskManager:
    def __init__(self):
        self._tareas: dict = {}
        self._lock = threading.Lock()

    def crear(self, trabajo) -> str:
        """Launches `trabajo(emit)` in a thread. Returns the task id."""
        tid = uuid.uuid4().hex[:12]
        est = {'id': tid, 'estado': 'corriendo', 'eventos': queue.Queue(), 'resultado': None}
        with self._lock:
            self._tareas[tid] = est

        def _run():
            try:
                est['resultado'] = trabajo(lambda ev: est['eventos'].put(ev))
                est['estado'] = 'hecho'
            except Exception as e:              # noqa: BLE001
                est['estado'] = 'error'
                est['resultado'] = {'error': str(e)}
            finally:
                est['eventos'].put({'tipo': 'fin', 'estado': est['estado']})

        threading.Thread(target=_run, daemon=True).start()
        return tid

    def estado(self, tid: str):
        with self._lock:
            return self._tareas.get(tid)

    def stream(self, tid: str):
        """Yields the task's events until 'fin' (blocking). Single consumer."""
        est = self.estado(tid)
        if not est:
            return
        q = est['eventos']
        while True:
            ev = q.get()
            yield ev
            if ev.get('tipo') == 'fin':
                break
