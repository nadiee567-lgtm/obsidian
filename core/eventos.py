"""Bus de eventos de OBSIDIAN — F1 paso 19.

Pub/sub estilo SpiderFoot: cuando el almacén crea una entidad nueva, publica un
evento; otros componentes (correlación, monitor, UI) reaccionan sin acoplarse.
Es la base sobre la que corre el motor de transforms (F2) y la correlación (F4).

Módulo PURO: sin Flask, sin red. Los fallos de un suscriptor se AÍSLAN para que
un callback roto no tumbe a los demás ni al que publica."""

# Nombres de eventos estándar (constantes para no escribir strings sueltos).
ENTIDAD_NUEVA        = 'entidad_nueva'
ENTIDAD_ACTUALIZADA  = 'entidad_actualizada'
RELACION_NUEVA       = 'relacion_nueva'


class Bus:
    """Pub/sub mínimo. suscribir(evento, callback) / publicar(evento, *args)."""

    def __init__(self):
        self._subs: dict[str, list] = {}

    def suscribir(self, evento: str, callback) -> None:
        self._subs.setdefault(evento, []).append(callback)

    def publicar(self, evento: str, *args, **kwargs) -> list:
        """Llama a cada suscriptor. Aísla fallos: si un callback lanza, se captura
        y se sigue con los demás. Devuelve la lista de excepciones ocurridas
        (vacía si todo bien) para que el llamador pueda loguearlas."""
        errores = []
        for cb in list(self._subs.get(evento, ())):
            try:
                cb(*args, **kwargs)
            except Exception as e:   # noqa: BLE001 — aislar por diseño
                errores.append(e)
        return errores
