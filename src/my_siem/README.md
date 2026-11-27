# Commands and the dashboard

How the commands (`ssh/`, `http/`, `https/`, `dummy/`) and the dashboard (`web/`) fit together. For usage
and config keys, see the [main README](../../README.md).

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
 sshd log ──► log.py ─┐                         ┌──► telemetry.py ──► logs/ssh/ssh.jsonl
                      ├──► monitor.py ──────────┤
 network ───► net.py ─┘   (+ detect.py alerts)  └──► state.py (SshState)
                                                          │ snapshot()
                                          api.py ◄────────┘
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

`command.py` holds everything in one file: `DummyConfig`, `DummyState` (seeded placeholder
data), the `--interval` flag, and `run()`, which adds to the current hour every `interval`
seconds. It is the smallest complete command, so start a new one by copying it.

## `web/`: the dashboard

Pages are rendered by the server with Jinja2. A small script keeps them live through
Server-Sent Events, and they still show the data as of the page load without JavaScript.

| File                  | Role |
| --------------------- | ---- |
| `__init__.py`         | `Dashboard`: one tab per running command, the routes (`/`, `/ui/<command>`, `/ui/<command>/fragment`), a `History` sampler for each section that keeps one, and the security headers. |
| `sections.py`         | `SECTIONS`, one `Section` per command: `context()` turns a snapshot (plus its history) into template values, and `metrics()`, if set, picks what the sampler keeps for the charts. Also holds the formatting helpers. |
| `charts.py`           | Chart geometry in Python (line paths, ticks, bars, the flow diagram), so the templates only place what they are given. |
| `templates/`          | `base.html` (page shell and tabs), `_charts.html` (chart macros), one template per section. |
| `static/live.js`      | Opens the section's `EventSource` and swaps in each pushed fragment, keeping open `<details>` open. |
| `static/style.css`    | Theme tokens (light and dark) and layout. |

How a page stays live:

1. `create_app` (in `api.py`) starts the samplers in the app's lifespan. Every 5 s each
   section that has `metrics()` records them, and the last 120 samples (10 minutes) are
   kept. That history feeds the `ssh` line charts, so it survives reloads but not restarts.
2. `GET /ui/ssh` renders the section into `base.html`.
3. Every 5 s `live.js` fetches `GET /ui/ssh/fragment`, the same section template
   re-rendered on its own, and swaps it in.

Security: sshd usernames are attacker-controlled, so templates are always autoescaped
and a Content-Security-Policy allows only same-origin scripts, never inline ones. The
server answers only to `api_allowed_hosts` (against DNS rebinding) and refuses every
method but `GET` and `HEAD`.

## Adding a command

1. Create `my_siem/<name>/`, starting from a copy of `dummy/command.py`: a config class
   with `from_json`, a thread-safe state with `snapshot()`, `add_arguments`,
   `apply_flags`, and a `run()` that blocks for as long as the command works.
2. Register it in `COMMANDS` in `main.py`, and add an example `config/<name>/config.json`.
3. Give it a tab: write a `context(snapshot, samples)` function (plus `metrics()` for line
   charts over time) in `web/sections.py`, add a template in `web/templates/` that imports
   `_charts.html`, and register the `Section` in `SECTIONS` under the command's name.
   A test checks that every command has one.
4. Test it in `tests/test_<name>.py` and `tests/test_web.py`, and document it in the main README.
