"""OBSIDIAN event bus — F1 step 19.

SpiderFoot-style pub/sub: when the store creates a new entity, it publishes an
event; other components (correlation, monitor, UI) react without coupling. It's
the base the transform engine (F2) and correlation (F4) run on.

PURE module: no Flask, no network. A subscriber's failures are ISOLATED so a
broken callback cannot take down the others or the publisher."""

# Standard event names (constants so we don't scatter loose strings).
ENTITY_NEW        = 'entity_new'
ENTITY_UPDATED  = 'entity_updated'
RELATION_NEW       = 'relation_new'


class Bus:
    """Minimal pub/sub. subscribe(event, callback) / publish(event, *args)."""

    def __init__(self):
        self._subs: dict[str, list] = {}

    def subscribe(self, evento: str, callback) -> None:
        self._subs.setdefault(evento, []).append(callback)

    def publish(self, evento: str, *args, **kwargs) -> list:
        """Calls each subscriber. Isolates failures: if a callback raises, it's
        caught and we continue with the rest. Returns the list of exceptions that
        occurred (empty if all fine) so the caller can log them."""
        errors = []
        for cb in list(self._subs.get(evento, ())):
            try:
                cb(*args, **kwargs)
            except Exception as e:   # noqa: BLE001 -- isolate by design
                errors.append(e)
        return errors
