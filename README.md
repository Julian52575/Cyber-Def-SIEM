# Siem

Security Information and Event Management, built in Python on top of [Scapy](https://scapy.net/).

## Quick start

### Prerequisites

- [uv](https://docs.astral.sh/uv/) (it installs Python 3.12 for you if needed)
- [just](https://github.com/casey/just)

Without them installed, run through Nix: `nix-shell -p uv just`.

### Setup

```sh
git clone <repo-url> && cd Cyber-Def-SIEM
just sync                   # create .venv and install dependencies, dev tools included
just set-githooks           # enable the repo's git hooks
just check                  # lint, type-check and test
just run --path . --stdout  # run every command, config and logs in the repo
just build                  # build a standalone binary at dist/my_siem
just install DEST           # build, then install it into DEST (a folder or user@host:/dir)
```

> Sniffing packets with Scapy needs root or the `CAP_NET_RAW` capability.

### Usage

```
my_siem [--stdout] [--no-log] [--path PATH] [--api [--api-host HOST] [--api-port PORT]] [COMMAND [command flags]]...
```

| Command | Description |
| ------- | ----------- |
| `ssh`   | Track SSH connections on this system (see [below](#tracking-ssh-connections)) |
| `http`  | Track HTTP requests and responses on the wire (see [below](#tracking-http-traffic)) |
| `https` | Track TLS handshakes on the wire (see [below](#tracking-https-traffic)) |
| `dummy` | Generate placeholder data, a template for new commands (see [below](#placeholder-data)) |

With no command, every command runs. Name one or more to run only those, each followed by
its own flags: `my_siem --api ssh --ports 22,2222 dummy --interval 2`. The commands run side
by side, each with its own config and log file; if one crashes, my_siem stops.

| Flag          | Description                                                     |
| ------------- | --------------------------------------------------------------- |
| `-h, --help`  | Show usage (`my_siem ssh --help` for the command's own flags)   |
| `--stdout`    | Also print events to stdout (default: off)                      |
| `--no-log`    | Do not write events to log files (default: off)                 |
| `--path PATH` | Root folder of `config/` and `logs/` (default: `/etc/my_siem`)  |
| `--api`       | Serve a live dashboard and the monitoring data over HTTP (see [API](#api)) |
| `--api-host HOST` | Address the API listens on (default: `127.0.0.1`)           |
| `--api-port PORT` | Port the API listens on (default: `8080`)                   |

General flags may go before or after the commands. Command-line flags override the config files.

### Configuration and logs

```
<path>/
├── config/
│   ├── config.json        general config
│   └── <command>/config.json
└── logs/
    └── <command>/<command>.jsonl
```

All config files are JSON and optional: a missing file (and its folders) is created with
the built-in defaults, with a warning, and later runs read it from there. If it cannot be
created (e.g. no write access), the defaults are used for that run. Keys left out of a
file keep their default; unknown keys are warned about; a malformed file or wrong value type stops my_siem with an error.
Run once with `--path .` to get every config file, each key at its default, under `config/`.

`config/config.json`:

| Key      | Default | Description                       |
| -------- | ------- | --------------------------------- |
| `stdout` | `false` | Also print events to stdout       |
| `log`    | `true`  | Write events to the log file      |
| `api`    | `false` | Serve the API (as `--api`)        |
| `api_host` | `"127.0.0.1"` | Address the API listens on |
| `api_port` | `8080`  | Port the API listens on         |
| `api_allowed_hosts` | `["localhost", "127.0.0.1", "::1"]` | Host names the API answers to, besides `api_host` (against DNS rebinding) |

### API

With `--api`, my_siem also runs a read-only HTTP server (FastAPI) while it monitors: a
dashboard rendered by the server, and the same data as JSON. Any method other than `GET`
or `HEAD` gets `405`, on every path:

```sh
sudo .venv/bin/my_siem --api
xdg-open http://localhost:8080/   # dashboard
curl localhost:8080/ssh           # JSON
```

| Endpoint                | Returns                                                         |
| ----------------------- | --------------------------------------------------------------- |
| `GET /`                 | Redirects to the first running command's dashboard              |
| `GET /ui/<command>`     | The command's dashboard tab                                     |
| `GET /ui/<command>/fragment` | The tab's content alone, polled by the page every 5 s       |
| `GET /<command>`        | The command's live state as JSON (below)                        |
| `GET /healthz`          | `{"status": "ok", "commands": ["ssh", "dummy"]}`                |
| `GET /docs`             | Interactive OpenAPI docs                                        |

| Command | Dashboard tab and JSON state |
| ------- | ---------------------------- |
| `ssh`   | Effective config, source status, event counts, active connections, last 100 logins and alerts |
| `http`  | Same base, plus responses by status class, matches per attack rule, last 100 requests |
| `https` | Same base, plus TLS versions offered, last 100 connection openings (server name, version, ALPN) |
| `dummy` | Config, allowed and blocked events per hour of the day, detections per rule |

Only the running commands' endpoints exist (no `/ssh` under `my_siem dummy`). The dashboard
works without JavaScript (it then shows the data as of the page load); with it,
`static/live.js` re-fetches the fragment every 5 s and swaps it in. It polls rather than
streams because proxies that only forward finished responses would hold a stream forever.
Chart history is sampled by the
server every 5 s and kept for 10 minutes, so it survives reloads but not restarts.

The server listens on all interfaces by default. It exposes users and addresses, so use
`--api-host 127.0.0.1` to keep it local. To reach it from another machine, add the name or
address you browse to to `api_allowed_hosts`; other `Host` headers get `400`.

Log folders are created when missing. An existing log file is appended to, never
overwritten, so history from earlier runs stays in the same file (the run's first event,
`siem.log.opened`, has `siem.log.resumed: true`). Log files are created with mode `0640`.

### Tracking SSH connections

```sh
sudo .venv/bin/my_siem ssh --ports 22,221-229
```

`config/ssh/config.json` (each key also has a flag, shown in `my_siem ssh --help`):

| Key              | Default  | Description                                                    |
| ---------------- | -------- | -------------------------------------------------------------- |
| `ports`          | `"22"`   | SSH ports, as a list (`[22, 2222]`) or a string (`"22,221-229"`) |
| `interface`      | `null`   | Interface to sniff on (`null`: all)                            |
| `auth_log`       | `"auto"` | `"auto"` (auth.log, else journald), `"journald"`, or a file path |
| `read_auth_log`  | `true`   | Read sshd logs (`--no-auth-log` to disable)                    |
| `sniff_traffic`  | `true`   | Sniff network traffic (`--no-sniff-traffic` to disable)        |
| `fail_threshold` | `5`      | Failed logins from one IP that raise an alert                  |
| `conn_threshold` | `20`     | New connections from one IP that raise an alert                |
| `window`         | `60`     | Alert window, in seconds                                       |

Two sources run side by side:

- **sshd logs** (`/var/log/auth.log`, or journald when it is missing or with `--journal`):
  successful and failed logins, invalid users and logouts, with user and source address.
- **network** (Scapy): every TCP connection to the given ports, with duration, packets
  and bytes. It also sees SSH daemons whose logs are not on this host, such as containers.

Alerts are raised when one IP makes `fail_threshold` failed logins
or `conn_threshold` new connections within `window` seconds.

### Tracking HTTP traffic

```sh
sudo .venv/bin/my_siem http --ports 80,801-809,8010-8015
```

`http` sniffs plaintext HTTP/1.x on the given ports. From each request it reads the
method, target, `Host` and `User-Agent`; from each response, the status code. Every
request and response is logged. Requests split across TCP segments, HTTP/2 and anything
inside TLS are not seen (see `https`, or the web server's own logs).

`config/http/config.json` (each key also has a flag, shown in `my_siem http --help`):

| Key                 | Default | Description                                          |
| ------------------- | ------- | ---------------------------------------------------- |
| `ports`             | `"80"`  | HTTP ports, as a list or a string, like `ssh`'s      |
| `interface`         | `null`  | Interface to sniff on (`null`: all)                  |
| `request_threshold` | `100`   | Requests from one IP that raise an alert             |
| `error_threshold`   | `20`    | 4xx responses to one IP that raise an alert          |
| `window`            | `60`    | Alert window, in seconds                             |

Alerts:

- `http_suspicious_request`, on every request matching an attack pattern: path
  traversal, SQL injection, XSS, command injection, Log4Shell, probes for sensitive
  files (`.env`, `.git/`, `/etc/passwd`, …) or admin pages (`wp-login.php`,
  `phpmyadmin`, …), and scanner user agents (sqlmap, nikto, Nmap, gobuster, …).
  Patterns are checked on the target both as sent and URL-decoded.
- `http_request_flood`, when one IP sends `request_threshold` requests within `window`.
- `http_error_scan`, when one IP gets `error_threshold` 4xx responses within `window`:
  it is guessing paths.

### Tracking HTTPS traffic

```sh
sudo .venv/bin/my_siem https --ports 443,8443
```

The traffic is encrypted, so `https` reads only the TLS ClientHello that opens each
connection: the server name asked for (SNI), the highest TLS version offered and the
application protocols (ALPN). A ClientHello split over several TCP segments is put back
together. A connection that opens with something other than TLS is logged too, as
plaintext HTTP or as non-TLS traffic. Connections already open when my_siem starts are
skipped.

`config/https/config.json` (each key also has a flag, shown in `my_siem https --help`):

| Key              | Default | Description                                     |
| ---------------- | ------- | ----------------------------------------------- |
| `ports`          | `"443"` | HTTPS ports, as a list or a string              |
| `interface`      | `null`  | Interface to sniff on (`null`: all)             |
| `conn_threshold` | `100`   | New connections from one IP that raise an alert |
| `window`         | `60`    | Alert window, in seconds                        |

Alerts:

- `https_conn_flood`, when one IP opens `conn_threshold` connections within `window`.
- `https_legacy_tls`, when a client offers nothing newer than TLS 1.1 (at most once
  per IP per `window`); old clients and scanners do.

### Placeholder data

```sh
.venv/bin/my_siem --path . --api dummy --interval 2
```

`dummy` needs no privileges and reads nothing from the system. It starts from seeded
placeholder data (24 hours of allowed and blocked events, detections per rule), then every
`interval` seconds adds a little to the current hour, so its dashboard tab moves. It logs
only its startup events. Copy it to start a new command.

`config/dummy/config.json` (`--interval` also exists as a flag):

| Key        | Default | Description                                  |
| ---------- | ------- | -------------------------------------------- |
| `interval` | `5`     | Seconds between updates                      |
| `seed`     | `42`    | Random seed of the starting data             |

### Output format

Every event is written as one JSON line following the
[OpenTelemetry log data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
(`timestamp`, `severity_number`, `severity_text`, `body`, `attributes`, `resource`, `event_name`).
Attributes use the OTel semantic conventions (`client.address`, `server.port`, `user.name`,
`process.pid`, …); SIEM-specific ones are namespaced under `siem.`.

| `event_name`                                        | Severity |
| --------------------------------------------------- | -------- |
| `siem.ssh.login_success`, `siem.ssh.logout`         | INFO     |
| `siem.ssh.login_failure`, `siem.ssh.invalid_user`   | WARN     |
| `siem.ssh.connection.opened`, `.closed`             | INFO     |
| `siem.alert.ssh_bruteforce`, `siem.alert.ssh_conn_flood` | ERROR |
| `siem.http.request`                                 | INFO (WARN if it matches an attack pattern) |
| `siem.http.response`                                | INFO (WARN for 4xx and 5xx) |
| `siem.alert.http_suspicious_request`, `.http_request_flood`, `.http_error_scan` | ERROR |
| `siem.https.client_hello`                           | INFO (WARN below TLS 1.2) |
| `siem.https.plaintext_http`, `siem.https.not_tls`   | WARN     |
| `siem.alert.https_conn_flood`, `.https_legacy_tls`  | ERROR    |
| `siem.source.started` / `siem.source.failed`        | INFO / ERROR |
| `siem.log.opened`, `siem.api.started`              | INFO     |
| `siem.config.created`, `siem.config.missing`, `siem.config.unknown_key` | WARN     |

```sh
jq 'select(.severity_text == "ERROR")' /etc/my_siem/logs/ssh/ssh.jsonl   # only alerts and failures
```

### Project layout

How the commands and the dashboard work inside, and how to add a command: [src/my_siem/README.md](src/my_siem/README.md). What each command reads, and how: [ssh](src/my_siem/ssh/README.md), [http](src/my_siem/http/README.md), [https](src/my_siem/https/README.md), [dummy](src/my_siem/dummy/README.md).

```
src/my_siem/   the package (entry point: my_siem.main:main)
  ssh/         the `ssh` command: sshd log parsing, monitor, flags
  http/        the `http` command: HTTP parsing, attack patterns, watcher, flags
  https/       the `https` command: TLS ClientHello parsing, watcher, flags
  net.py       TCP connection tracking and the sniffer, shared by ssh, http and https
  dummy/       the `dummy` command: placeholder data, a template for new commands
  web/         the dashboard: Jinja2 templates, SVG chart geometry, polled fragments
config/        configs written when run with --path . (git-ignored)
logs/          log output when run with --path . (git-ignored)
tests/         pytest suite
.githooks/     local git hooks
.github/       CI workflows, issue/PR templates, rulesets
```

### Justfile bindings

| Command                | Description                                         |
| ---------------------- | --------------------------------------------------- |
| `just`                 | List available recipes                              |
| `just sync`            | Install dependencies (incl. dev group) into `.venv` |
| `just run [args...]`   | Run the SIEM CLI, forwarding any arguments          |
| `just fmt`             | Format `src` and `tests` with ruff                  |
| `just lint`            | Lint `src` and `tests` with ruff                    |
| `just check`           | Run every check below, in order                     |
| `just check-lint`      | Lint `src` and `tests` with ruff, auto-fixing       |
| `just check-typecheck` | Type-check `src` with mypy                          |
| `just check-test`      | Run the pytest suite                                |
| `just set-githooks`    | Use `.githooks/` as the git hooks directory         |
| `just build`           | Build a standalone binary at `dist/my_siem`, skipped when no source changed |
| `just install DEST`    | Build, then install the binary into `DEST`: a local folder or an ssh target like `user@host:/opt/bin` |

### Quality Assurance

Run `just check` before every commit. It runs three checks in order and stops at the
first failure, so fix that one and run it again. Each check can also be run on its own.

| Check | Tool | What it catches |
| ----- | ---- | --------------- |
| `just check-lint` | [ruff](https://docs.astral.sh/ruff/) | Syntax errors, undefined names, unused imports and variables |
| `just check-typecheck` | [mypy](https://mypy.readthedocs.io/) | Type mismatches, wrong call arguments, missing attributes |
| `just check-test` | [pytest](https://docs.pytest.org/) | Code that runs but does the wrong thing |

**Why**: lint catches mistakes cheaply before anything runs; type-checking catches
whole classes of bugs that tests might miss; tests prove the behaviour.

#### Fixing errors

**`check-lint`** fixes what it safely can and edits files in place, so review the diff.
Each remaining error names a rule, e.g. `F841 Local variable 'x' is assigned to but never used`.
Look the code up with `uv run ruff rule F841`, then fix the code.
Silence a deliberate exception on that line only, with `# noqa: F841`.
Run `just fmt` for formatting; lint does not reformat.

**`check-typecheck`** reports `file:line: error: message [code]`:

- `Incompatible types` / `Argument 1 has incompatible type`: the value does not match
  the annotation. Fix the value or the annotation, whichever is wrong.
- `Module "x" has no attribute "y"` on a third-party import: the library re-exports it
  dynamically. Import from the module that defines it
  (e.g. `scapy.layers.inet`, not `scapy.all`).
- `Skipping analyzing "x": module is installed, but missing library stubs`: install
  the stubs (`uv add --dev types-x`) if they exist, otherwise add
  `# type: ignore[import-untyped]` on that import.

Use `# type: ignore[code]` only as a last resort, always with the specific code.

**`check-test`** prints the failing assertion with the values on each side.
Rerun just that test with `uv run pytest tests/test_x.py::test_name -x`, and add `-s`
to see `print` output. Fix the code, not the test, unless the expected
behaviour changed. Exit code 5 means no test was collected: check file and function
names start with `test_`. See [tests/README.md](tests/README.md) for writing tests.

## Contributing

Once `just set-githooks` has run, the hooks check every commit and push:

- **Quality checks**: every commit runs `just check` and is rejected if it fails, or if
  ruff auto-fixed files (stage the fixes and commit again). It checks the working tree,
  so unstaged changes count. Opt out with `git config hooks.runChecks false`.
- **Conventional Commits**: messages must look like `type(scope): subject`, where type is one of
  `feat fix docs style refactor perf test build ci chore revert`.
- **Signed commits**: commit with `git commit -sS` (sign-off trailer plus a signature).
  Opt out locally with `git config hooks.requireSignature false`; the `main` ruleset still requires signatures.
- **No shadow merges**: pushing a branch that carries another open PR's commits is rejected.
  Opt out with `git config hooks.preventShadowMerge false`.

Hooks give local feedback only; CI and the branch rulesets are the real gates.
