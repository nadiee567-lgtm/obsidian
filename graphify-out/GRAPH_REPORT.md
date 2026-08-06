# Graph Report - .  (2026-08-06)

## Corpus Check
- 66 files · ~58,452 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1093 nodes · 2375 edges · 65 communities (59 shown, 6 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 57 edges (avg confidence: 0.59)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- obsidian web
- workspaces
- correlacion
- test backfill
- monitor
- multiidioma
- obsidian web
- test imagen
- obsidian web
- boveda
- test easm
- test darkweb
- test buscadores
- migracion
- obsidian cli
- test motores
- test opsec
- test ia
- test modelo
- obsidian web
- obsidian web
- test exportar
- obsidian web
- obsidian web
- modelo
- test transforms integracion
- test lote
- validacion
- transforms
- test transforms
- test estado
- obsidian web
- eventos
- transforms
- obsidian web
- test seguridad
- transforms
- obsidian web
- obsidian web
- obsidian web
- test cli
- obsidian web
- modelo
- modelo
- modelo
- obsidian web
- obsidian web
- obsidian web
- transforms
- obsidian web
- obsidian web
- obsidian web
- obsidian web
- imagen
- imagen
- imagen
- obsidian web
- obsidian web
- obsidian web
- obsidian web
- obsidian web
- obsidian install.sh
- obsidian web
- run.sh

## God Nodes (most connected - your core abstractions)
1. `Store` - 139 edges
2. `Entity` - 46 edges
3. `run_by_name()` - 43 edges
4. `correlate()` - 36 edges
5. `Manager` - 35 edges
6. `api_run()` - 29 edges
7. `_error()` - 28 edges
8. `Finding` - 27 edges
9. `_guardar_dato()` - 23 edges
10. `_almacen()` - 21 edges

## Surprising Connections (you probably didn't know these)
- `_Rj` --uses--> `Store`  [INFERRED]
  test_backfill.py → core/modelo.py
- `FakeResp` --uses--> `Store`  [INFERRED]
  test_buscadores.py → core/modelo.py
- `_R` --uses--> `Store`  [INFERRED]
  test_cripto.py → core/modelo.py
- `_RjD` --uses--> `Store`  [INFERRED]
  test_darkweb.py → core/modelo.py
- `_FakeStream` --uses--> `Store`  [INFERRED]
  test_imagen.py → core/modelo.py

## Import Cycles
- None detected.

## Communities (65 total, 6 thin omitted)

### Community 0 - "obsidian web"
Cohesion: 0.06
Nodes (70): api_timeline(), _build_timeline(), _cargar_blocklist(), _get_local_ip(), index(), _key_rotativa(), _pastes_github(), _pivote_ips() (+62 more)

### Community 1 - "workspaces"
Cohesion: 0.06
Nodes (47): _conectar(), load_store(), Typed-model persistence in SQLite -- F1 step 20. Saves a Store (entities +…, Records that a transform ran (what, when, how many results)., Case history, most recent first., Dumps the full store to the DB (upsert by id)., Rebuilds a Store from the DB. SILENT load (no bus): does not fire events,…, read_history() (+39 more)

### Community 2 - "correlacion"
Cohesion: 0.06
Nodes (56): _coincide_yaml(), _evaluar_yaml(), Finding, r_cert_vencido(), r_email_filtrado(), r_email_spoofable(), r_infra_compartida(), r_ip_listada() (+48 more)

### Community 3 - "test backfill"
Cohesion: 0.06
Nodes (45): correlate(), load_yaml_rules(), Parses YAML rules (text) and activates them. Returns how many loaded. Ignores…, Runs all rules (built-in + user YAML) and returns the findings ordered by…, Background task queue + events for SSE -- F2 step 37. A long task (recon of…, Launches `trabajo(emit)` in a thread. Returns the task id., Yields the task's events until 'fin' (blocking). Single consumer., TaskManager (+37 more)

### Community 4 - "monitor"
Cohesion: 0.07
Nodes (40): _ahora(), Changes, diff(), Monitor, Continuous monitoring -- F7 step 95. Periodically re-runs the case transforms…, One cycle: snapshot, refresh, snapshot, diff, alert. Never raises (isolates…, Snapshot of the relevant state to detect changes., What changed between two snapshots. (+32 more)

### Community 5 - "multiidioma"
Cohesion: 0.07
Nodes (37): cirilico_a_latino(), detectar_idioma(), dorks_por_idioma(), latino_a_cirilico(), motores_locales(), normalizar_telefono(), perfiles_regionales(), Multilingual and regional sources -- F15. A key datum may exist only in Chinese… (+29 more)

### Community 6 - "obsidian web"
Cohesion: 0.10
Nodes (38): _ai(), _ai_stream(), _analizar_password(), _analizar_todo(), api_run(), _check_url(), _cmd(), _cve_correlacion() (+30 more)

### Community 7 - "test imagen"
Cohesion: 0.10
Nodes (31): ela(), enlaces_facial(), enlaces_reverse(), parse_gps(), phash(), Image utilities for OSINT -- F9. Multi-engine reverse search (step 118): each…, {engine: {'url', 'modo'}} for facial search. Yandex is the best free one…, Converts exiftool GPS (DMS, '40 deg 26\\' 46\" N, 79 deg 58\\' 56\" W') to… (+23 more)

### Community 8 - "obsidian web"
Cohesion: 0.06
Nodes (35): api_blackarch_tools(), api_darkweb(), api_datos(), api_kali(), api_kali_tools(), api_keys(), api_netlas(), api_netlas_key() (+27 more)

### Community 9 - "boveda"
Cohesion: 0.11
Nodes (16): Encrypted API key vault -- F3 step 51. Encrypts keys with Fernet (AES-128, the…, Only the configured service NAMES -- never the values., Vault, OBSIDIAN central configuration -- roadmap step 9. Paths, ports and constants in…, get_logger(), OBSIDIAN central logging -- roadmap step 10. Replaces the print(...,…, Returns the OBSIDIAN logger, configured only once. File = DEBUG (everything,…, _cred() (+8 more)

### Community 10 - "test easm"
Cohesion: 0.11
Nodes (20): exposure_score(), Exposure score 0-100 (step 149): combines the SIZE of the surface (how many…, Holds a case's entities and relations. Deduplicates by id on add. If given a…, Store, api_v2_keys_probar(), Verifies a REAL key: runs its transform on a known target and reports whether…, test_cert_pivote(), test_favicon_pivote() (+12 more)

### Community 11 - "test darkweb"
Cohesion: 0.14
Nodes (23): coincidencias_leak(), Messages that mention leak/breach terms (step 131). PURE/testable., _correr(), Tests for F10 -- dark web / Tor. Run: OBSIDIAN_PASSWORD=x ../.venv/bin/python…, _RjD, test_breaches_agrega_y_dedup(), test_breaches_limpio(), test_canal_leaks() (+15 more)

### Community 12 - "test buscadores"
Cohesion: 0.16
Nodes (23): _con_key(), _correr(), FakeResp, Tests for the multi-engine search transforms (F8 steps 108-113). The APIs need…, Same host/port reported by 2 engines = 1 entity with 2 sources., The 9 engines in core.motores each have a registered transform., test_binaryedge(), test_censys() (+15 more)

### Community 13 - "migracion"
Cohesion: 0.14
Nodes (22): _mig_buckets(), _mig_dominio(), _mig_email(), _mig_favicon(), _mig_github_secrets(), _mig_ip(), _mig_passivedns(), _mig_takeover() (+14 more)

### Community 14 - "obsidian cli"
Cohesion: 0.20
Nodes (20): Score 0-100 aggregating severities (step 64)., risk_score(), _almacen(), cmd_export(), cmd_recon(), cmd_report(), cmd_run(), cmd_transforms() (+12 more)

### Community 15 - "test motores"
Cohesion: 0.16
Nodes (18): motores_disponibles(), Unified internet-search-engine layer -- F8 steps 106 and 117. The West uses…, The same query translated to EACH engine. {engine: query} (non-empty only)., Engine names. cn=True only Chinese, cn=False only Western, None all., Translates a unified query to `motor`'s dialect (step 117). campos: {field:…, traducir(), traducir_todos(), api_v2_buscar_traducir() (+10 more)

### Community 16 - "test opsec"
Cohesion: 0.13
Nodes (4): PersonaManager, Sock puppet vault -- F13 step 152. Manages non-attributable research personas…, Tests for F13 -- the tool's OPSEC. Run: OBSIDIAN_PASSWORD=x ../.venv/bin/python…, test_gestor_personas()

### Community 17 - "test ia"
Cohesion: 0.12
Nodes (11): extract_entities(), Typed entity extraction from free text -- F14 step 161. Paste an article/dump…, Returns [(type, value), ...] without duplicates. Domains that are clearly file…, pick_model(), Picks the local model based on the task (NEXO-style router). An explicit IP…, api_v2_extraer_texto(), Paste text -> typed entities into the graph (F14 step 161, deterministic regex)., Tests for F14 -- the AI layer. Run: OBSIDIAN_PASSWORD=x ../.venv/bin/python -m… (+3 more)

### Community 18 - "test modelo"
Cohesion: 0.15
Nodes (16): Entity, Atomic unit of data. The id derives from (type, normalized value), so two…, Tests for the typed data model (F1). Roadmap steps 13-17, 21-22. Run:…, test_almacen_de_tipo_y_buscar(), test_almacen_deduplica(), test_fusionar_distinto_id_falla(), test_fusionar_une_origenes_y_props(), test_id_deterministico_mismo_dato() (+8 more)

### Community 19 - "obsidian web"
Cohesion: 0.14
Nodes (18): build_ntfy(), Push notifications via ntfy.sh -- F7 step 96. When the monitor detects a…, Returns (url, headers, body_bytes) for the ntfy POST. Sends nothing., Sends the notification. Returns True if it went out, False otherwise (no raise)., send_ntfy(), api_v2_monitor(), api_v2_monitor_ntfy(), _monitor_alerta() (+10 more)

### Community 20 - "obsidian web"
Cohesion: 0.11
Nodes (19): errorhandler, api_v2_diff_historico(), api_v2_keys(), api_v2_personas(), api_v2_recon_async(), api_v2_tarea(), api_v2_tarea_stream(), api_v2_workspaces() (+11 more)

### Community 21 - "test exportar"
Cohesion: 0.18
Nodes (16): _celda(), exportar_csv(), exportar_json(), OBSIDIAN data exporters -- F7 step 94. Leaves the case in structured formats to…, Neutralizes formula injection in a CSV cell., Full case in JSON, re-importable with Store.from_dict()., One row per entity. Cells sanitized against formula injection., _demo() (+8 more)

### Community 22 - "obsidian web"
Cohesion: 0.14
Nodes (17): ask(), disponible(), OBSIDIAN's SINGLE AI layer -- one "head" that every feature uses. Instead of…, Is Ollama running? (to degrade gracefully if not)., The ONLY function that talks to the AI. Returns text (or raises if Ollama does…, api_v2_chat(), api_v2_consulta(), api_v2_deteccion_ia() (+9 more)

### Community 23 - "obsidian web"
Cohesion: 0.11
Nodes (18): _descargar_imagen(), _fetch_seguro(), _http_probe(), Probes a host over HTTP and enriches the entity. Uses _fetch_seguro: does not…, Lightweight technology fingerprint from the HTTP response (server, powered-by,…, GET that closes SSRF: validates that EVERY hop points to a public IP. It…, Downloads an image to a temp file (anti-SSRF). Returns the path or None., _t_ela() (+10 more)

### Community 24 - "modelo"
Cohesion: 0.14
Nodes (7): Records which transform (and on which input entity) created it., True if the value is well-formed for its type, using the SAME security…, Absorbs another entity of the same id (step 17): merges origins and properties,…, Adds or merges. Returns the live entity in the store (step 17)., Shortcut: builds an Entity and adds it (deduplicating)., test_roundtrip_almacen(), test_tags()

### Community 25 - "test transforms integracion"
Cohesion: 0.22
Nodes (14): _correr(), FakeResp, Integration tests for the main transforms, with the APIs MOCKED (F7 step 101).…, If the API blows up, the transform catches it and returns empty (isolation)., test_crtsh(), test_dns_a(), test_dns_a_ignora_basura(), test_dns_a_sin_resultados() (+6 more)

### Community 26 - "test lote"
Cohesion: 0.21
Nodes (13): Runs several transforms IN PARALLEL (step 102). Transforms are I/O-bound…, run_batch(), test_ejecutar_lote_progreso(), _fake_a(), _fake_b(), transform, Tests for the parallel transform executor (F7 step 102). Run:…, Many concurrent tasks: no output is lost in the merge. (+5 more)

### Community 27 - "validacion"
Cohesion: 0.16
Nodes (13): _es_ip(), _objetivo_seguro(), OBSIDIAN security validators and sanitizers -- step 8 (core/). PURE functions:…, True only if `arg` matches EXACTLY the expected shape of `tipo`. Allowlist:…, Generic check for targets with no fixed type (distrobox, shodan). Rejects…, _validar(), api_blackarch(), api_shodan() (+5 more)

### Community 28 - "transforms"
Cohesion: 0.17
Nodes (6): A transform's contract (step 26). entrada = entity type it runs on; salidas =…, Central transform catalog (step 27). Indexed by input type to answer quickly…, Transforms that run on an entity of this type (step 35)., Decorator that registers a function as a transform.…, _Registry, Transform

### Community 29 - "test transforms"
Cohesion: 0.15
Nodes (9): fixture, Tests for the transform engine (F2, steps 26-28, 35, 38). Run:…, Each test starts with an empty registry, but RESTORES whatever was there before…, _registro_aislado(), test_ejecutar_emite_relaciona_y_anota_procedencia(), test_ejecutar_valida_tipo_de_entrada(), test_emitir_valor_basura_se_ignora(), test_transform_dispara_eventos_del_bus() (+1 more)

### Community 30 - "test estado"
Cohesion: 0.33
Nodes (10): _e(), _punto(), System status page -- F7 step 105. PURE (testable) render of OBSIDIAN's health:…, render_estado(), _datos(), Tests for the status page (F7 step 105). Run: ../.venv/bin/python -m pytest…, test_render_escapa_xss(), test_render_ia_no_disponible() (+2 more)

### Community 31 - "obsidian web"
Cohesion: 0.17
Nodes (12): api_v2_run(), _correr_transform_interno(), _higiene_request(), _jitter(), Runs a transform and persists (autosave). Shared by /run and the monitor.…, Runs a transform on an entity {tipo, valor} (step 36)., Records which transform you ran on which target and whether it was anonymized…, Randomizes the User-Agent so it does not look like a bot (F13 step 155). (+4 more)

### Community 32 - "eventos"
Cohesion: 0.18
Nodes (7): Bus, OBSIDIAN event bus — F1 step 19. SpiderFoot-style pub/sub: when the store…, Minimal pub/sub. suscribir(event, callback) / publish(event, *args)., Calls each subscriber. Isolates failures: if a callback raises, it's caught and…, test_bus_aisla_fallos_de_suscriptor(), test_bus_publica_entidad_nueva_y_actualizada(), test_bus_publica_relacion_nueva()

### Community 33 - "transforms"
Cohesion: 0.18
Nodes (9): load_plugins(), OBSIDIAN transform engine -- F2, steps 26-28. Design copied from REAL, proven…, Configures a transform's max concurrency. <=0 removes the limit., Runs a transform on an entity (step 28). Returns the produced entities.…, Imports each .py in `directorio` (which self-registers via @transform).…, run(), set_limite(), test_rate_limit_concurrencia() (+1 more)

### Community 34 - "obsidian web"
Cohesion: 0.18
Nodes (11): True only if `url` is http/https to a host that resolves to PUBLIC IP(s).…, _url_publica(), _nuclei(), Web capture with a headless browser (step 68). Does not capture internal hosts…, Vulnerability scan with nuclei templates (step 69). Public hosts only. Runs via…, _screenshot(), _t_nuclei_dom(), _t_nuclei_sub() (+3 more)

### Community 36 - "transforms"
Cohesion: 0.24
Nodes (7): Machine, A recipe: transforms in order that cascade from one type to the next. E.g.…, Runs transforms/machines over a store, remembering which (transform, entity)…, Runs the recipe: each step runs on the entities of the type it expects (seed +…, Runner, test_corredor_cachea(), test_machine_cascada()

### Community 37 - "obsidian web"
Cohesion: 0.22
Nodes (10): api_v2_opsec_anonimo(), api_v2_opsec_perfil(), api_v2_workspace_abrir(), _aplicar_perfil_opsec(), _leer_perfiles(), Loads a workspace into memory and makes it the active one (F3 step 45)., Routes ALL of Obsidian's traffic over Tor so your IP is not exposed (F13 step…, Isolates the case with its own network identity: applies the workspace's OPSEC… (+2 more)

### Community 38 - "obsidian web"
Cohesion: 0.20
Nodes (10): Runs a tool WITHOUT a shell: argv is a list, not a string. Closes metacharacter…, run_tool(), _t_dns_a(), _t_dns_mx(), _t_dns_ns(), _t_dns_txt(), _t_email_spoofable(), _t_ptr() (+2 more)

### Community 39 - "obsidian web"
Cohesion: 0.22
Nodes (9): Path inside CASES_DIR for a sanitized case, or None if invalid or it would try…, _ruta_caso_segura(), api_cargar(), api_guardar(), api_reporte(), _db_guardar_caso(), _generar_reporte_html(), Mirror of the case in SQLite -- does not replace the JSON, only makes it… (+1 more)

### Community 40 - "test cli"
Cohesion: 0.31
Nodes (8): main(), Tests for the CLI (F7 step 98). They don't touch the network. Run:…, test_export_workspace_inexistente(), test_parser_recon_con_keys(), test_parser_run(), test_report_workspace_inexistente(), test_run_tipo_invalido(), test_transforms_lista()

### Community 41 - "obsidian web"
Cohesion: 0.22
Nodes (9): api_v2_export_csv(), api_v2_export_json(), api_v2_reporte(), _nombre_export(), _objetivo_del_almacen(), Best 'objetivo' candidate of the case for the report header. Prefers the SEED…, Self-contained HTML report of the active case (F7 step 93): risk summary,…, Full case in JSON, re-importable (F7 step 94). (+1 more)

### Community 42 - "modelo"
Cohesion: 0.25
Nodes (6): OBSIDIAN typed data model — F1, the heart of the framework. Every collected…, valid_type(), api_v2_entidad(), api_v2_recon(), Runs all transforms applicable to the seed in parallel (step 102)., Adds a seed entity to the graph WITHOUT running transforms (Maltego-style: you…

### Community 43 - "modelo"
Cohesion: 0.29
Nodes (4): normalize(), Looks up by (type, value) without adding -- respects normalization., Canonical form of a value, so two writes of the same datum yield the same id.…, test_normalizacion()

### Community 44 - "modelo"
Cohesion: 0.29
Nodes (3): Typed, directed edge between two entities (by id). Deterministic id from…, Connects two entities (by id or Entity object). Deduplicates., Relation

### Community 45 - "obsidian web"
Cohesion: 0.33
Nodes (6): api_v2_estado(), _estado_datos(), Collects system health (touches disk/processes)., System health in JSON (step 105)., System status page (step 105)., v2_estado()

### Community 46 - "obsidian web"
Cohesion: 0.40
Nodes (5): api_v2_nota(), api_v2_tag(), _autosave(), Analyst note on an entity (F6 step 88)., Toggle an analyst tag (interesante/descartado/falso-positivo).

### Community 47 - "obsidian web"
Cohesion: 0.50
Nodes (5): _fetch_tor(), GET over Tor (socks5h resolves .onion through Tor itself)., _t_haystak(), _t_onion_fetch(), _tor_disponible()

### Community 49 - "obsidian web"
Cohesion: 0.50
Nodes (4): api_monitor(), _monitor_loop(), _monitor_start(), _monitor_stop()

### Community 50 - "obsidian web"
Cohesion: 0.50
Nodes (4): api_v2_opsec_fuga(), _evaluar_fuga(), LEAK if anonymous mode is on but the IP seen by Obsidian == the real IP (i.e.…, IP/DNS leak detection before a sensitive transform (F13 step 158). (WebRTC only…

### Community 51 - "obsidian web"
Cohesion: 0.50
Nodes (4): _cargar_web(), Loads a UI file (HTML/JS/CSS) from web/. The front-end lives in files, not…, v2 engine demo page: run transforms and view the typed graph. Protected by the…, v2_page()

### Community 52 - "obsidian web"
Cohesion: 0.50
Nodes (4): Fetches the latest messages from a Telegram user/channel. Returns (True, (id,…, _t_canal_leaks(), _t_telegram(), _tg_mensajes()

### Community 53 - "imagen"
Cohesion: 0.67
Nodes (3): enlaces_cronolocalizacion(), Sun/shadow tools (Bellingcat technique). With coords if known., _t_cronolocalizacion()

### Community 54 - "imagen"
Cohesion: 0.67
Nodes (3): enlaces_landmark(), Landmark recognition (buildings/signs) by image., _t_landmarks()

### Community 55 - "imagen"
Cohesion: 0.67
Nodes (3): enlaces_satelital(), Satellite/aerial views to verify a location., _t_satelital()

### Community 56 - "obsidian web"
Cohesion: 0.67
Nodes (3): api_buscar(), _db_buscar(), Searches a term (email, domain, username...) across all saved cases.

### Community 57 - "obsidian web"
Cohesion: 0.67
Nodes (3): api_grafo(), _build_grafo(), Converts case['datos'] into nodes and edges for vis.js

### Community 58 - "obsidian web"
Cohesion: 0.67
Nodes (3): _hash_password(), _load_or_create_auth(), login()

### Community 59 - "obsidian web"
Cohesion: 0.67
Nodes (3): _ransom_addrs(), Known ransomware addresses (Ransomwhere, CC0). 6h cache., _t_riesgo_wallet()

## Knowledge Gaps
- **2 isolated node(s):** `obsidian_install.sh script`, `run.sh script`
  These have ≤1 connection - possible missing edges or undocumented components.
- **6 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Store` connect `test easm` to `obsidian web`, `workspaces`, `correlacion`, `test backfill`, `monitor`, `multiidioma`, `test imagen`, `test darkweb`, `test buscadores`, `migracion`, `obsidian cli`, `test modelo`, `obsidian web`, `test exportar`, `modelo`, `test transforms integracion`, `test lote`, `transforms`, `test transforms`, `eventos`, `transforms`, `transforms`, `modelo`, `modelo`, `modelo`, `transforms`?**
  _High betweenness centrality (0.192) - this node is a cross-community bridge._
- **Why does `Manager` connect `workspaces` to `obsidian web`, `test easm`, `obsidian cli`?**
  _High betweenness centrality (0.074) - this node is a cross-community bridge._
- **Why does `Entity` connect `test modelo` to `obsidian web`, `workspaces`, `transforms`, `eventos`, `transforms`, `test imagen`, `modelo`, `modelo`, `transforms`, `modelo`, `transforms`, `test transforms`, `obsidian web`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._
- **Are the 13 inferred relationships involving `Store` (e.g. with `Context` and `Machine`) actually correct?**
  _`Store` has 13 INFERRED edges - model-reasoned connections that need verification._
- **Are the 5 inferred relationships involving `Entity` (e.g. with `Context` and `Machine`) actually correct?**
  _`Entity` has 5 INFERRED edges - model-reasoned connections that need verification._
- **What connects `obsidian_install.sh script`, `run.sh script` to the rest of the system?**
  _2 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `obsidian web` be split into smaller, more focused modules?**
  _Cohesion score 0.05898021308980213 - nodes in this community are weakly interconnected._