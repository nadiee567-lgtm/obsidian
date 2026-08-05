"""OBSIDIAN event bus — F1 step 19.

SpiderFoot-style pub/sub: when the store creates a new entity, it publishes an
event; other components (correlation, monitor, UI) react without coupling. It's
the base the transform engine (F2) and correlation (F4) run on.

PURE module: no Flask, no network. A subscriber's failures are ISOLATED so a
broken callback cannot take down the others or the publisher."""

# Standard event names (constants so we don't scatter loose strings).
ENTIDAD_NUEVA        = 'entidad_nueva'
ENTIDAD_ACTUALIZADA  = 'entidad_actualizada'
RELACION_NUEVA       = 'relacion_nueva'


class Bus:
    """Minimal pub/sub. suscribir(event, callback) / publicar(event, *args)."""

    def __init__(self):
        self._subs: dict[str, list] = {}

    def suscribir(self, evento: str, callback) -> None:
        self._subs.setdefault(evento, []).append(callback)

    def publicar(self, evento: str, *args, **kwargs) -> list:
        """Calls each subscriber. Isolates failures: if a callback raises, it's
        caught and we continue with the rest. Returns the list of exceptions that
        occurred (empty if all fine) so the caller can log them."""
        errores = []
        for cb in list(self._subs.get(evento, ())):
            try:
                cb(*args, **kwargs)
            except Exception as e:   # noqa: BLE001 -- isolate by design
                errores.append(e)
        return errores
