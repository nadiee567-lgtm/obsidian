# ⬛ OBSIDIAN

**Framework de OSINT y reconocimiento — datos tipados, transforms, grafo interactivo y correlación de riesgos.**

> *La seguridad no debería tener un precio exorbitante.*

OBSIDIAN toma la idea de Maltego (entidades → transforms → grafo) y la de SpiderFoot
(eventos tipados + motor de correlación) y las junta en una herramienta local, sin
dependencias de nube y apoyada en fuentes **keyless** siempre que se puede. Corre un
transform sobre un objetivo, el grafo se expande solo, el motor busca riesgos y un
monitor te avisa al celular cuando algo cambia.

![Grafo interactivo](docs/img/grafo.jpg)

---

## Qué hace

- **Modelo de datos tipado** — 23 tipos de entidad (dominio, ip, email, subdominio,
  usuario, wallet…), IDs deterministas, dedup y merge automáticos, procedencia de cada dato.
- **Motor de transforms** — ~39 transforms: DNS, RDAP, Certificate Transparency,
  subdominios, HTTP probing, screenshots, nuclei, tech/CVE, brechas, infostealers,
  reputación de IP, favicon hash, wayback, WHOIS inverso, metadata EXIF y más.
- **Grafo interactivo** (`/v2`) — click-derecho en un nodo corre transforms, colores por
  tipo, filtros, pivoteo multi-entidad, cadenas de evidencia, timeline y export PNG.
- **Correlación de riesgos** — reglas deterministas (puerto sensible, cert vencido, IP
  maliciosa, email filtrado, takeover…) + un **segundo escudo** de IA que explica *por qué*
  algo es peligroso y atrapa falsos positivos.
- **Workspaces** — casos aislados en SQLite, autosave, historial, snapshots y bóveda
  cifrada (Fernet) para las API keys.
- **Monitoreo continuo** — re-escanea el objetivo cada N minutos y alerta los cambios
  (nuevo subdominio, puerto abierto, cert vencido) por **ntfy** al celular.
- **Reportes y export** — informe HTML autocontenido con el grafo embebido, y export
  JSON / CSV / PDF.
- **CLI** — todo lo anterior, scriptable desde la terminal.

![Reporte](docs/img/reporte.jpg)

---

## Arranque rápido

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# corre la web (bind local por defecto)
OBSIDIAN_PASSWORD=tu_clave python obsidian_web.py
# abre http://localhost:8767/v2
```

Herramientas de sistema opcionales que enriquecen algunos transforms: `dig`, `nmap`,
`whois`, `exiftool`, `nuclei`, y `playwright` (para screenshots).

### CLI

```bash
python obsidian_cli.py transforms dominio            # transforms de un tipo
python obsidian_cli.py run dominio github.com dns_a  # un transform
python obsidian_cli.py recon dominio github.com -w caso1   # todos los aplicables
python obsidian_cli.py report -w caso1 -o reporte.html
python obsidian_cli.py export json -w caso1 -o caso.json
```

---

## API keys (opcional) y alternativas gratis

**OBSIDIAN es keyless-first: sin ninguna API key ya obtienes ~90% del valor.** La mayoría
de los transforms (DNS, RDAP, Certificate Transparency, subdominios, HTTP, nuclei, brechas,
reputación de IP, favicon, wayback…) no necesitan nada. Solo unos pocos piden key, y son
**extras opcionales** — en la interfaz aparecen marcados con **⚿**.

Cada usuario pone **sus propias** keys (modelo *bring-your-own-key*) en la bóveda cifrada,
desde el panel **🔑 API keys** de la web. La key nunca sale de tu máquina.

**Transforms que piden key, y qué usar gratis si no la tienes:**

| Necesita key | Qué hace | Alternativa GRATIS (keyless) ya incluida |
|---|---|---|
| **Shodan / Censys / ZoomEye / FOFA / Quake / Hunter / Netlas / Criminal IP / BinaryEdge** | Buscadores de internet (puertos, servicios, infra de una IP) | `puertos` (nmap), `geo_ip`, `reputacion_ip`, `ip_blocklist`, `greynoise` |
| **HIBP** *(única de pago)* | Email en filtraciones de datos | `breaches_xon` (XposedOrNot), `stealer_hudsonrock` |
| **VirusTotal** (passivedns) | Historial de IPs de un dominio | `crtsh`, `subdominios_ht`, `rdap` |
| **ViewDNS** (reverse_whois) | Otros dominios del mismo dueño | — |

**Sobre las keys de pago:** casi todos los buscadores tienen **tier gratis** (Censys, FOFA,
Netlas). Shodan gratis es limitado; su Membership es un **pago único** (no suscripción), y es
gratis con el [GitHub Student Pack](https://education.github.com/pack) si eres estudiante.
No necesitas comprar nada para usar OBSIDIAN a fondo.

> *La seguridad no debería tener un precio exorbitante.*

---

## Arquitectura

```
obsidian_web.py     servidor Flask + los transforms (endpoints /api/v2/*)
obsidian_cli.py     el mismo motor desde terminal
web/                v2.html (grafo), app.html / login.html (UI clásica)
core/
  modelo.py         Entidad, Relacion, Almacen (dedup, eventos)
  transforms.py     @transform, Contexto.emitir, ejecutar, Machine, Corredor (caché)
  correlacion.py    @regla, correlacionar, score_riesgo
  reporte.py        reporte HTML autocontenido
  exportar.py       JSON / CSV (saneado anti-inyección de fórmulas)
  monitor.py        snapshot + diff + Monitor (hilo)
  notificar.py      push por ntfy.sh
  workspaces.py     Gestor de casos (SQLite, snapshots, historial)
  boveda.py         bóveda cifrada de API keys (Fernet)
  ia.py             puerta única a la IA local (Ollama)
  validacion.py     allowlist por tipo, anti-SSRF, anti-path-traversal
```

El núcleo (`core/`) no sabe de Flask: es lógica pura y testeable. La web y el CLI son
dos frentes sobre el mismo motor.

---

## Escribir un transform

Un transform toma **una** entidad de entrada y emite **cero o más** de salida. El decorador
lo registra; `ctx.emitir` crea la entidad, la deduplica, la relaciona con la entrada y le
anota la procedencia — todo automático.

```python
from core.transforms import transform

@transform(entrada='dominio', salidas=('ip',), descripcion='Resuelve el registro A')
def dns_a(entidad, ctx):
    for ip in resolver_A(entidad.valor):          # tu lógica
        ctx.emitir('ip', ip, etiqueta='resuelve')
```

- `entrada` — tipo de entidad sobre el que corre.
- `salidas` — tipos que puede producir (para el menú de la UI).
- `requiere_key=True` — si necesita una API key (se lee de la bóveda).
- Si el transform revienta, el motor **aísla el fallo**: devuelve lo que alcanzó a emitir,
  no tumba el caso.

Los transforms viven en `obsidian_web.py`; un plugin externo puede cargarse con
`cargar_plugins`.

---

## Seguridad

Diseñado asumiendo que **los datos del objetivo no son de confianza**:

- Validación por **allowlist** por tipo y ejecución de herramientas por `argv` (sin shell) —
  no hay inyección de argumentos.
- **Anti-SSRF**: se rechazan IPs privadas/loopback/link-local y se revalida cada redirect.
- **Anti-path-traversal** en nombres de caso.
- El grafo y el reporte **escapan** todo dato del objetivo (anti-XSS almacenado).
- El CSV **neutraliza inyección de fórmulas** (`=+-@`).
- API keys en **bóveda cifrada** (Fernet, archivo 0600), nunca en texto plano ni en el repo.

---

## Tests

```bash
python -m pytest -q      # 108 tests
```

Cubren el modelo, los transforms, la seguridad (con payloads reales), correlación,
workspaces, bóveda, reporte, export, monitor, notificaciones y CLI.
