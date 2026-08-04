"""Cola de tareas en background + eventos para SSE — F2 paso 37.

Una tarea larga (recon de muchos transforms) no debe bloquear la request HTTP: se
lanza en un hilo, devuelve un id al instante, y el cliente escucha el progreso en
vivo por Server-Sent Events. Módulo PURO (no sabe de Flask): expone eventos como
una cola que el endpoint SSE drena.

El trabajo recibe un `emit(evento)` para publicar progreso. Al terminar se pone un
evento {'tipo':'fin'}."""
from __future__ import annotations
import queue
import threading
import uuid


class GestorTareas:
    def __init__(self):
        self._tareas: dict = {}
        self._lock = threading.Lock()

    def crear(self, trabajo) -> str:
        """Lanza `trabajo(emit)` en un hilo. Devuelve el id de la tarea."""
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
        """Genera los eventos de la tarea hasta el 'fin' (bloqueante). Un consumidor."""
        est = self.estado(tid)
        if not est:
            return
        q = est['eventos']
        while True:
            ev = q.get()
            yield ev
            if ev.get('tipo') == 'fin':
                break
