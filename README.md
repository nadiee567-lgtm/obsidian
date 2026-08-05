# ⬛ OBSIDIAN

**OSINT & reconnaissance framework — typed data, transforms, interactive graph and risk correlation.**

> *Security should not come at an exorbitant price.*

OBSIDIAN takes the idea of Maltego (entities → transforms → graph) and SpiderFoot
(typed events + correlation engine) and combines them into a local tool with no cloud
dependencies, backed by **keyless** sources whenever possible. Run a transform on a
target, the graph expands on its own, the engine looks for risks, and a monitor pings
your phone when something changes.

![Interactive graph](docs/img/grafo.jpg)

---

## What it does

- **Typed data model** — 23 entity types (domain, ip, email, subdomain, username,
  wallet…), deterministic IDs, automatic dedup and merge, provenance for every datum.
- **Transform engine** — 89 transforms: DNS, RDAP, Certificate Transparency, subdomains,
  HTTP probing, screenshots, nuclei, tech/CVE, breaches, infostealers, IP reputation,
  favicon hash, wayback, reverse WHOIS, EXIF metadata, and much more.
- **Interactive graph** (`/v2`) — right-click a node to run transforms, per-type colors,
  filters, multi-entity pivoting, evidence chains, timeline and PNG export.
- **Risk correlation** — deterministic rules (sensitive port, expired cert, malicious IP,
  leaked email, takeover…) + an AI **second shield** that explains *why* something is
  dangerous and catches false positives.
- **Multi-engine search** — Shodan, Censys, ZoomEye, FOFA, Quake, Hunter, Netlas,
  Criminal IP, BinaryEdge behind one unified query that is translated to each engine's
  dialect (the Chinese engines see infra Shodan doesn't).
- **Crypto tracing** — extract wallets, transaction graph, common-input clustering,
  ransomware scoring (Ransomwhere), multi-chain (BTC + ETH).
- **EASM** — asset inventory, continuous discovery, infra clustering, exposure scoring,
  shadow IT, historical surface diff.
- **OPSEC** — sock puppets, global Tor routing, proxy rotation, UA hygiene, jitter,
  per-case network identity, IP-leak detection, API-key rotation, footprint log.
- **AI layer** — text entity extraction, foreign-source translation, natural-language
  query → plan, case chat, deepfake heuristic, NEXO-style model routing (Ollama, local).
- **Multilingual** — regional platforms (VK/Weibo), Cyrillic↔Latin transliteration,
  local engines (Yandex/Baidu), language detection, per-region dorks.
- **Workspaces** — isolated SQLite cases, autosave, history, snapshots and an encrypted
  vault (Fernet) for API keys.
- **Continuous monitoring** — re-scans the target every N minutes and alerts on changes
  (new subdomain, open port, expired cert) to your phone via **ntfy**.
- **Reports & export** — self-contained HTML report with the embedded graph, plus
  JSON / CSV / PDF export.
- **CLI** — everything above, scriptable from the terminal.

![Report](docs/img/reporte.jpg)

---

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# run the web UI (local bind by default)
OBSIDIAN_PASSWORD=your_password python obsidian_web.py
# open http://localhost:8767/v2
```

Optional system tools that enrich some transforms: `dig`, `nmap`, `whois`, `exiftool`,
`nuclei`, `tesseract`, `tor`, and `playwright` (for screenshots).

### CLI

```bash
python obsidian_cli.py transforms dominio            # transforms for a type
python obsidian_cli.py run dominio github.com dns_a  # a single transform
python obsidian_cli.py recon dominio github.com -w case1   # all applicable, in parallel
python obsidian_cli.py report -w case1 -o report.html
python obsidian_cli.py export json -w case1 -o case.json
```

---

## API keys (optional) and free alternatives

**OBSIDIAN is keyless-first: with no API key at all you already get ~90% of the value.**
Most transforms (DNS, RDAP, Certificate Transparency, subdomains, HTTP, nuclei, breaches,
IP reputation, favicon, wayback…) need nothing. Only a few ask for a key, and they are
**optional extras** — marked with **⚿** in the UI.

Each user supplies **their own** keys (*bring-your-own-key*) in the encrypted vault, from
the **🔑 API keys** panel. The key never leaves your machine.

**Transforms that need a key, and what to use for free if you don't have it:**

| Needs a key | What it does | FREE (keyless) alternative already included |
|---|---|---|
| **Shodan / Censys / ZoomEye / FOFA / Quake / Hunter / Netlas / Criminal IP / BinaryEdge** | Internet search engines (ports, services, IP infra) | `puertos` (nmap), `geo_ip`, `reputacion_ip`, `ip_blocklist`, `greynoise` |
| **HIBP** *(the only paid one)* | Email in data breaches | `breaches_xon` (XposedOrNot), `stealer_hudsonrock` |
| **VirusTotal** (passivedns) | IP history of a domain | `crtsh`, `subdominios_ht`, `rdap` |
| **ViewDNS** (reverse_whois) | Other domains of the same owner | — |

**About paid keys:** almost every search engine has a **free tier** (Censys, FOFA, Netlas).
Shodan's free tier is limited; its Membership is a **one-time payment** (not a subscription),
and it's free with the [GitHub Student Pack](https://education.github.com/pack) if you're a
student. You do not need to buy anything to use OBSIDIAN to the fullest.

> *Security should not come at an exorbitant price.*

---

## Architecture

```
obsidian_web.py     Flask server + the transforms (endpoints /api/v2/*)
obsidian_cli.py     the same engine from the terminal
web/                v2.html (graph), app.html / login.html (classic UI)
core/
  modelo.py         Entidad, Relacion, Almacen (dedup, events)
  transforms.py     @transform, Contexto.emitir, ejecutar, Machine, Corredor (cache)
  correlacion.py    @regla, correlacionar, score_riesgo
  reporte.py        self-contained HTML report
  exportar.py       JSON / CSV (sanitized against formula injection)
  monitor.py        snapshot + diff + Monitor (thread)
  notificar.py      push via ntfy.sh
  workspaces.py     case manager (SQLite, snapshots, history)
  boveda.py         encrypted API key vault (Fernet)
  ia.py             single door to the local AI (Ollama)
  validacion.py     per-type allowlist, anti-SSRF, anti-path-traversal
```

The core (`core/`) knows nothing about Flask: it's pure, testable logic. The web UI and
the CLI are two fronts over the same engine.

---

## Writing a transform

A transform takes **one** input entity and emits **zero or more** output entities. The
decorator registers it; `ctx.emitir` creates the entity, deduplicates it, relates it to the
input and records its provenance — all automatic.

```python
from core.transforms import transform

@transform(entrada='dominio', salidas=('ip',), descripcion='A records (dig)')
def dns_a(entidad, ctx):
    for ip in resolve_A(entidad.valor):           # your logic
        ctx.emitir('ip', ip, etiqueta='resolves')
```

- `entrada` — entity type it runs on.
- `salidas` — types it can produce (for the UI menu).
- `requiere_key=True` — if it needs an API key (read from the vault).
- If the transform crashes, the engine **isolates the failure**: it returns whatever it
  emitted, it does not take down the case.

Transforms live in `obsidian_web.py`; an external plugin can be loaded with `cargar_plugins`.

---

## Security

Designed assuming **the target's data is untrusted**:

- Per-type **allowlist** validation and tool execution via `argv` (no shell) —
  no argument injection.
- **Anti-SSRF**: private/loopback/link-local IPs are rejected and every redirect is
  revalidated.
- **Anti-path-traversal** in case names.
- The graph and the report **escape** all target data (stored XSS protection).
- The CSV **neutralizes formula injection** (`=+-@`).
- API keys in an **encrypted vault** (Fernet, 0600 file), never in plaintext or in the repo.

---

## Tests

```bash
python -m pytest -q      # 267 tests
```

They cover the model, the transforms, security (with real payloads), correlation,
workspaces, vault, report, export, monitor, notifications, OPSEC, AI, multilingual and CLI.
