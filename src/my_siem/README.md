# Commands and the dashboard

How the commands (`ssh/`, `http/`, `https/`, `dummy/`) and the dashboard (`web/`) fit together. For usage
and config keys, see the [main README](../../README.md). What each command reads, and how,
is in its own README: [`ssh`](ssh/README.md), [`http`](http/README.md),
[`https`](https/README.md), [`dummy`](dummy/README.md).

## How commands run

`main.py` holds the `COMMANDS` registry. Each `Command` bundles a config class, its flags,
a live state with a `snapshot()` method, and a `run()` function. `my_siem` runs every
command, or only the ones named on the command line (`split_commands` cuts argv at each
command name). Each selected command gets its own config file, log file and logger, and
its `run()` goes in its own thread. The API serves every running command's state from one
server. When all commands return, my_siem exits; if one raises, my_siem stops and
re-raises it.

The `ssh` command, for example:

```
 sshd log ──► log.py ─┐                         ┌──► logs/ LogManager ─┬─► logs/ssh/ssh.<hour>.jsonl
                      ├──► monitor.py ──────────┤     (writes, reads)  └─► logs/ssh/rollup.json
 network ───► net.py ─┘   (+ detect.py alerts)  └──► state.py (SshState)     │ counts(), recent()
                                                          │ snapshot()          │
                                          api.py ◄────────┴─────────────────────┘
                                           ├── GET /ssh            JSON
                                           └── web/  GET /ui/ssh   HTML, polled fragment
```

## `ssh/`: the `ssh` command

| Module       | Role |
| ------------ | ---- |
| `cli.py`     | The command's flags, applied over `config/ssh/config.json`. |
| `log.py`     | Parses sshd lines into `AuthEvent`s (login success/failure, invalid user, logout) and follows auth.log or journald. |
| `monitor.py` | `SshMonitorConfig`, and `run()`: one thread follows the logs, one sniffs with Scapy. Each event is written to the log, recorded in the state, and fed to a `RateDetector` that raises `ssh_bruteforce` or `ssh_conn_flood`. |
| `state.py`   | `SshState`, the live view: a `ConnState` (see below) plus the last 100 logins. |

The network side uses the shared modules:

| Module       | Role |
| ------------ | ---- |
| `net.py`     | `ConnTracker` turns TCP packets into `ConnEvent`s: a SYN to a watched port opens a connection, FIN or RST closes it; packets and bytes are counted in between. `run_sniffer` runs Scapy and reports the `network` source's status. |
| `live.py`    | `ConnState`, the base of the `ssh`, `http` and `https` states: source status, counters, open connections and the last 100 alerts. Lock-protected, because the command's threads write while the API thread reads `snapshot()`. |
| `clock.py`   | Paris time (`Europe/Paris`), where everything cuts time: whole minutes, hours, and days from Paris midnight (23 or 25 hours on DST changes). |
| `detect.py`  | `RateDetector` (N hits from one key within a window), and `raise_alert`/`rate_alert`, which record an alert in the state and log it. |

The monitor never talks to the web side. It only fills `SshState`, and everything shown
over HTTP comes from `snapshot()`.

## `http/` and `https/`: the `http` and `https` commands

Both only sniff. Each run has one `*Watcher` that feeds every packet to a `ConnTracker`
and reads its payload. Each `command.py` holds the config, the state, the flags and
`run()`, like `dummy`.

| Module             | Role |
| ------------------ | ---- |
| `http/wire.py`     | `parse_request` and `parse_response` read the start of a TCP payload. `match_rules` checks a request against `TARGET_RULES` (on the target, raw and URL-decoded) and `SCANNER_AGENT`. |
| `http/command.py`  | `HttpWatcher`: a payload to a watched port is a request, one from it a response. Raises `http_suspicious_request`, `http_request_flood` and `http_error_scan`. |
| `https/tls.py`     | `parse_client_hello` reads SNI, ALPN and supported versions (skipping GREASE). `HelloAssembler` buffers a connection's first bytes until its first TLS record is complete, and tells TLS from plaintext HTTP or anything else. |
| `https/command.py` | `HttpsWatcher`: reads only connections whose SYN it saw. Raises `https_conn_flood` and `https_legacy_tls`. |

## `dummy/`: the `dummy` command

`command.py` holds everything in one file: `DummyConfig`, `DummyState` (a seeded generator
of placeholder traffic), the `--interval` flag, `count_keys`, and `run()`, which logs one
`siem.dummy.tick` every `interval` seconds. It is the smallest complete command, so start a new one by copying it.

## `web/`: the dashboard

Pages are rendered by the server with Jinja2. A small script keeps them live by polling for
the section's fragment, and they still show the data as of the page load without JavaScript.

| File                  | Role |
| --------------------- | ---- |
| `__init__.py`         | `Dashboard`: one tab per running command then the admin tab, the routes (`/`, `/ui/<command>`, `/ui/<command>/fragment`, each taking the window as `unit` and `count`; `/ui/admin`, not polled, and `/ui/admin/usage` for a rescan), a `History` sampler for each section that keeps one, and the security headers. |
| `admin.py`            | `AdminPanel`: the scheduled jobs of each `LogManager` (the samplers' are added by `Dashboard.jobs`), the scan of the log folders, and the `Importer`. The JSON routes under `/admin/` are in `api.py`. |
| `sections.py`         | `SECTIONS`, one `Section` per command: `context()` turns a snapshot, its live samples and a `View` (the window, read through the command's `LogManager`) into template values; `metrics()`, if set, picks what the sampler keeps for the live charts. Also holds the formatting helpers. |
| `charts.py`           | Chart geometry in Python (line paths, ticks, bars, the flow diagram), so the templates only place what they are given. |
| `templates/`          | `base.html` (page shell and tabs), `section.html` (a command's tab: time range bar and panel), `_charts.html` (chart macros), one template per section; `admin.html` and its `admin_jobs.html` and `admin_usage.html` parts. |
| `static/live.js`      | Polls the section's fragment for the chosen window and swaps it in, keeping open `<details>` open; drives the time range bar and keeps it in the URL and tab links. |
| `static/admin.js`     | The log import: estimate, confirm in a `<dialog>`, start it, then follow it every second. Also swaps a rescanned log size card in. Everything from the server is set as text. |
| `static/style.css`    | Theme tokens (light and dark) and layout. |

How a page stays live:

1. `create_app` (in `api.py`) starts the samplers in the app's lifespan. Every 5 s each
   section that has `metrics()` records them, and the last 120 samples (10 minutes) are
   kept. That history feeds the live "Active connections" charts only, so it survives
   reloads but not restarts. Everything else comes from the logs, for the chosen window.
2. `GET /ui/ssh?unit=hour&count=3` renders the section into `base.html`.
3. Every 5 s `live.js` fetches `GET /ui/ssh/fragment?unit=hour&count=3`, the same section
   template re-rendered on its own, and swaps it in. Moving the slider or typing a number fetches it at once.

Security: sshd usernames are attacker-controlled, so templates are always autoescaped
and a Content-Security-Policy allows only same-origin scripts, never inline ones. The
server answers only to `api_allowed_hosts` (against DNS rebinding) and refuses every
method but `GET` and `HEAD`, except `POST /admin/import` (`WRITE_ROUTES` in `api.py`).
That one needs a JSON body and, from a browser, an `Origin` naming the host it was sent
to, or one listed by name in `api_allowed_hosts` (`_cross_site`; a `*` there lets any
`Host` in, never any `Origin`): a form or a script on another site cannot send either, so it
cannot start an import (CSRF). Through a proxy that forwards only `GET`, `admin.js`
falls back to `GET /admin/import/start` with `Importer.token`, a random value made at
startup and embedded in the admin page, which another site cannot read.

## `logs/`: where events are written and read back

Every write and read of a command's logs goes through its `LogManager` (`manager.py`),
made by `main.py` per command. Commands only use `logs.out.emit(...)` (and `mark`/`set_mark`
to resume a source); the API and dashboard only call `counts(window)` and
`recent(kinds, window)`.

| Module        | Role |
| ------------- | ---- |
| `manager.py`  | `LogManager`: builds the command's logger, writing to its hourly files (or, with `--no-log`, to memory), the stdout copy and the counts. `count_keys` decides what each event adds to the counts: its name, `alerts` for alerts, plus whatever the command breaks events down by (HTTP status class, attack rule, TLS version...). |
| `files.py`    | `HourlyLogExporter` writes records into one file per Paris hour, each opening with a resource line; `Retention` gzips closed hours and deletes the oldest past the age and size caps, in a background thread. |
| `rollup.py`   | `Rollup` keeps the counts per minute, hour and day (60, 24 and 100 buckets) and the sources' marks, saved together to `rollup.json`. |
| `reader.py`   | `FileReader` reads records back, newest first, from the hourly files that overlap a window: a gzipped hour is parsed once, the live one from where the last read stopped, and lines are skipped on their event name before any JSON parsing. `MemoryReader` does the same from memory. |
| `window.py`   | `Window`: the last N minutes, hours or days, in whole Paris buckets. |
| `importer.py` | The admin tab's log import. A command's `Source` replays the host's own logs over a span through an `EventLogger` whose records are collected, not logged; `import_logs` drops those already in the files (`_Logged`), then adds the rest to their closed hours (`add_to_closed_hour` in `files.py`, holding the writer's `maintenance` lock so a sweep cannot gzip the hour meanwhile) and to the counts. With `write` off, it only measures. `Importer` runs one import at a time, in a thread. |

## Adding a command

1. Create `my_siem/<name>/`, starting from a copy of `dummy/command.py`: a config class
   with `from_json`, a thread-safe state with `snapshot()`, `add_arguments`,
   `apply_flags`, and a `run(logs, cfg, state)` that blocks for as long as the command
   works and logs each event with `logs.out.emit`. If the dashboard should break events
   down by an attribute, add a `count_keys` like `dummy`'s.
2. Register it in `COMMANDS` in `main.py`, with its `count_keys` if any. If the host
   keeps logs of what it watches, give it a `source(cfg)` returning a `logs.importer.Source`
   (see `import_source` in `ssh/monitor.py`), and the admin tab can import them.
3. Give it a tab: write a `context(snapshot, samples, view)` function in
   `web/sections.py`, reading the window from `view` (`total`, `per_bucket`, `faceted`,
   `recent`), add a template in `web/templates/` that imports `_charts.html`, and register
   the `Section` in `SECTIONS` under the command's name, with the kinds of records its
   tables show. A test checks that every command has one.
4. Test it in `tests/test_<name>.py` and `tests/test_web.py`. Document its flags and config
   keys in the main README, and what it reads and how in `my_siem/<name>/README.md`.
