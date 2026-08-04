"""Monitoreo continuo — F7 paso 95.

Re-ejecuta periódicamente los transforms del caso y ALERTA cuando algo cambia:
una entidad nueva (subdominio/ip que apareció), una relación nueva, una propiedad
que cambió (cert que venció, servicio de un puerto) o un tag nuevo (takeover,
vulnerable). Es lo que convierte un escaneo puntual en vigilancia.

Diseño testeable por INYECCIÓN: el Monitor no sabe de red ni de Flask. Recibe
  - snapshot_fn(): devuelve el estado actual (dict) del almacén,
  - refrescar_fn(): re-ejecuta los transforms (muta el almacén),
  - on_alerta(cambios): callback opcional (ntfy en el paso 96).
Así los tests inyectan funciones falsas y no tocan la red. El hilo solo envuelve
`ciclo()`, que es puro salvo por los callbacks."""
from __future__ import annotations
import datetime
import threading
from dataclasses import dataclass, field


def snapshot(almacen) -> dict:
    """Foto del estado relevante para detectar cambios."""
    ents = {}
    for e in almacen.entidades:
        ents[e.id] = {
            'tipo': e.tipo,
            'valor': e.valor,
            'props': {k: str(v) for k, v in (e.propiedades or {}).items()},
            'tags': sorted(e.tags),
        }
    return {'ents': ents, 'rels': {r.id for r in almacen.relaciones}}


@dataclass
class Cambios:
    """Lo que cambió entre dos snapshots."""
    nuevas_entidades: list = field(default_factory=list)   # dicts {tipo,valor}
    nuevas_relaciones: list = field(default_factory=list)  # ids
    cambios_prop: list = field(default_factory=list)       # {entidad,tipo,campo,antes,ahora}

    def hay(self) -> bool:
        return bool(self.nuevas_entidades or self.nuevas_relaciones or self.cambios_prop)

    def resumen(self) -> str:
        partes = []
        if self.nuevas_entidades:
            ej = ', '.join(e['valor'] for e in self.nuevas_entidades[:3])
            mas = f' (+{len(self.nuevas_entidades) - 3} más)' if len(self.nuevas_entidades) > 3 else ''
            partes.append(f'{len(self.nuevas_entidades)} entidad(es) nueva(s): {ej}{mas}')
        if self.cambios_prop:
            partes.append(f'{len(self.cambios_prop)} cambio(s) en datos existentes')
        if self.nuevas_relaciones:
            partes.append(f'{len(self.nuevas_relaciones)} relación(es) nueva(s)')
        return ' · '.join(partes) or 'sin cambios'

    def to_dict(self) -> dict:
        return {'nuevas_entidades': self.nuevas_entidades,
                'nuevas_relaciones': self.nuevas_relaciones,
                'cambios_prop': self.cambios_prop}


def diff(antes: dict, despues: dict) -> Cambios:
    """Compara dos snapshots y devuelve los cambios."""
    a, d = antes['ents'], despues['ents']
    nuevas = [{'tipo': d[i]['tipo'], 'valor': d[i]['valor']} for i in d if i not in a]
    nuevas_rel = sorted(despues['rels'] - antes['rels'])
    cambios = []
    for i in d:
        if i not in a:
            continue
        # propiedades que aparecieron o cambiaron de valor
        for k, v in d[i]['props'].items():
            if a[i]['props'].get(k) != v:
                cambios.append({'entidad': d[i]['valor'], 'tipo': d[i]['tipo'],
                                'campo': k, 'antes': a[i]['props'].get(k), 'ahora': v})
        # tags nuevos (ej: 'vulnerable', 'takeover' aparecen tras un re-escaneo)
        for t in sorted(set(d[i]['tags']) - set(a[i]['tags'])):
            cambios.append({'entidad': d[i]['valor'], 'tipo': d[i]['tipo'],
                            'campo': 'tag', 'antes': None, 'ahora': t})
    return Cambios(nuevas, nuevas_rel, cambios)


def _ahora() -> str:
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


class Monitor:
    """Corre `ciclo()` cada `intervalo` segundos en un hilo daemon."""

    def __init__(self, snapshot_fn, refrescar_fn, on_alerta=None,
                 intervalo: int = 300, max_alertas: int = 100):
        self.snapshot_fn = snapshot_fn
        self.refrescar_fn = refrescar_fn
        self.on_alerta = on_alerta
        self.intervalo = intervalo
        self.max_alertas = max_alertas
        self.alertas: list = []          # historial de cambios detectados (nuevo primero)
        self.ultimo_ciclo: str | None = None
        self._hilo: threading.Thread | None = None
        self._parar = threading.Event()

    @property
    def activo(self) -> bool:
        return self._hilo is not None and self._hilo.is_alive()

    def ciclo(self) -> Cambios:
        """Un ciclo: foto, refresca, foto, diff, alerta. No lanza (aísla fallos)."""
        antes = self.snapshot_fn()
        try:
            self.refrescar_fn()
        except Exception:
            pass                          # un fallo de red no tumba el monitor
        despues = self.snapshot_fn()
        cambios = diff(antes, despues)
        self.ultimo_ciclo = _ahora()
        if cambios.hay():
            alerta = {'ts': self.ultimo_ciclo, 'resumen': cambios.resumen(),
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
        # wait() devuelve True si se pidió parar; False en timeout → corre ciclo
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
