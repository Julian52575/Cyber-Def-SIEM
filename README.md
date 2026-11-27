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
    └── <command>/
        ├── <command>.<YYYY-MM-DDTHH±hhmm>.jsonl     raw events of the current hour
        ├── <command>.<YYYY-MM-DDTHH±hhmm>.jsonl.gz  raw events of a closed hour
        └── rollup.json                          event counts per minute, hour and day
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
| `log_max_age_days` | `100` | Raw log files older than this are deleted (per command) |
| `log_max_size_mb` | `1024` | Past this total, the oldest raw log files are deleted (per command) |

### API

With `--api`, my_siem also runs an HTTP server (FastAPI) while it monitors: a
dashboard rendered by the server, and the same data as JSON. It is read-only but for
`POST /admin/import` (see [Admin tab](#admin-tab)): any other method than `GET` or `HEAD`
gets `405`, on every path:

```sh
sudo .venv/bin/my_siem --api
xdg-open http://localhost:8080/   # dashboard
curl localhost:8080/ssh                      # JSON, last 60 minutes
curl 'localhost:8080/ssh?unit=day&count=7'    # JSON, last 7 days
```

| Endpoint                | Returns                                                         |
| ----------------------- | --------------------------------------------------------------- |
| `GET /`                 | Redirects to the first running command's dashboard              |
| `GET /ui/<command>`     | The command's dashboard tab                                     |
| `GET /ui/<command>/fragment` | The tab's content alone, polled by the page every 5 s       |
| `GET /<command>`        | The command's live state, and what it logged in a window, as JSON (below) |
| `GET /healthz`          | `{"status": "ok", "commands": ["ssh", "dummy"]}`                |
| `GET /ui/admin`         | The admin tab (see [Admin tab](#admin-tab))                     |
| `GET /admin/jobs`       | Every service's scheduled jobs: frequency, last run             |
| `GET /admin/logs`       | Size of each folder under `logs/`                               |
| `GET /admin/import/estimate?command=ssh&unit=day&count=7` | What an import would read and write, writing nothing |
| `POST /admin/import`    | Start an import: `{"commands": ["ssh"], "unit": "day", "count": 7}`; `409` while one runs |
| `GET /admin/import/start?command=ssh&unit=day&count=7&token=...` | Start an import through a proxy that only forwards `GET` (token below) |
| `GET /admin/import`     | The last import, as it goes (`{"state": "idle"}` before any)    |
| `GET /docs`             | Interactive OpenAPI docs                                        |

Every page, fragment and `GET /<command>` takes a time window: `unit` (`minute`, `hour` or
`day`) and `count` (1 to 60 minutes, 24 hours or 100 days; default: 60 minutes). It counts
whole Paris buckets, the current one included: "3 hours" at 14:20 starts at 12:00, and
"2 days" starts at yesterday's midnight. On the dashboard it is the **Time range** bar: pick
a unit, then drag the slider or type the number (a typed value applies after a short
pause, or on Enter, and is clamped to the unit's range). The window is kept in the URL and the tab links, so a reload or a
tab switch keeps it. Pages forgive a bad window (they clamp it); the JSON API answers `422`.

| Command | Dashboard tab and JSON (`window`: from the logs; the rest: live) |
| ------- | ---------------------------- |
| `ssh`   | Window: login outcomes, failed logins, alerts and new connections per bucket, the last 100 logins and alerts. Live: config, source status, uptime, active connections |
| `http`  | Window: requests, responses by status class, matches per attack rule, the last 100 requests and alerts. Live: as `ssh` |
| `https` | Window: TLS versions offered, missing SNI, legacy TLS, the last 100 connection openings (server name, version, ALPN) and alerts. Live: as `ssh` |
| `dummy` | Window: allowed and blocked events, detections per rule. Live: config |

In the JSON, `window` holds `unit`, `count`, `since`, `totals` (the window's counts by key),
`buckets` (each one's start and counts) and `events` (the newest 100 records of each kind,
as logged, newest first). Counts come from `rollup.json` and records from the hourly log
files (see [Configuration and logs](#configuration-and-logs)), so the window reaches back
past restarts. With `--no-log` both live in memory, for the current run only.

Only the running commands' endpoints exist (no `/ssh` under `my_siem dummy`). The dashboard
works without JavaScript (it then shows the data as of the page load); with it,
`static/live.js` re-fetches the fragment every 5 s and swaps it in. It polls rather than
streams because proxies that only forward finished responses would hold a stream forever.
Active connections are not logged, only sampled: their chart stays live whatever the
window, sampled by the server on every 5 s of the clock (:00, :05, ...) and kept for 10
minutes, so it survives reloads but not restarts.

The server listens on all interfaces by default. It exposes users and addresses, so use
`--api-host 127.0.0.1` to keep it local. To reach it from another machine, add the name or
address you browse to to `api_allowed_hosts`; other `Host` headers get `400`.

All time is cut in Paris time (`Europe/Paris`), whatever the host's time zone: log file
hours, count buckets (a day starts at Paris midnight, so it lasts 23 or 25 hours on DST
changes), the dashboard's clock and the API's timestamps. Event timestamps in the logs stay
in UTC (`...Z`), as OpenTelemetry writes them.

Log folders are created when missing. Raw events go to one file per hour, named after the
Paris hour they were written in and its UTC offset (`ssh.2026-11-27T15+0100.jsonl`), so the
hour repeated when DST ends gets two files (`T02+0200`, then `T02+0100`). A run that starts within an hour that already has a file
appends to it, never overwriting it (the run's first event, `siem.log.opened`, then has
`siem.log.resumed: true`). Log files are created with mode `0640`.

Retention runs in the background at startup and whenever a new hour starts: closed hours
are gzipped (about 10 to 50 times smaller), files past `log_max_age_days` are deleted, then
the oldest files until the folder fits in `log_max_size_mb`. The file being written is
never touched, so one very busy hour can exceed the size cap until the next hour.
Files left over from older versions (`<command>.jsonl`) are not managed; move or delete them.

Alongside, `rollup.json` keeps how many events of each name happened per minute (last
60 minutes), per hour (last 24 hours) and per day (last 100 days). It stays a few KB
whatever the traffic, outlives the raw logs, and is saved every minute and on exit (a crash
loses at most the last minute). With `--no-log` the counts are kept in memory only.

### Admin tab

The dashboard's last tab, **Admin** (`/ui/admin`), has three parts:

- **Scheduled jobs**: what each service runs on its own, how often, and when it last ran
  (as of the page load: this tab is not polled, reload it to update). Each command's log manager starts a new hourly
  file and sweeps (gzip, retention) on the first event of each hour, and saves
  `rollup.json` on the first event of each minute: a quiet command waits for its next
  event. The dashboard samples active connections every 5 s. A log import shows up too.
- **Log size**: every folder under `logs/`, running command or not, from the file sizes:
  files of hours not gzipped yet, gzipped ones, the rest (`rollup.json`, leftovers), and
  how much of `log_max_size_mb` the log files take. **Rescan** reads the sizes again.
- **Log importer**: reads the host's own logs again into the commands' log folders. Tick
  the commands, pick the last N hours (up to 24) or days (up to 100, and no more than
  `log_max_age_days`), then **Estimate…**: it reads everything and says how many records
  are new and how much they take gzipped, warning when a folder would pass its size cap.
  **Import** then runs it in the background. It needs JavaScript and log files.

| Command | Imports from |
| ------- | ------------ |
| `ssh`   | sshd's logs, where `auth_log` points: the file and its rotated copies (`auth.log.1`, `auth.log.2.gz`...), or journald |
| `http`  | The web server's access log, where `access_log` points (nginx's or Apache's combined or common format), and its rotated copies |

Imported lines go through the command's own code, so they are logged, counted and alerted
on as live ones would be (the alerts of a replay start from a clean slate at the span's
start). Each imported record carries `siem.import.source`, the file it came from. Only
closed hours are written, up to the start of the current one: the running command covers
that one. Each goes into its own hour's file, as one more gzip member, so retention ages it
like the rest. Records already logged are skipped, so an import can be run again:

- `ssh` reads the same lines as the running command, so a record already logged (by
  the startup catch-up, or an earlier import) is matched exactly and left out. An alert
  within `window` seconds of a logged one of the same name and address is that alert.
- `http`'s live source is the sniffer, which sees the same requests differently (with
  ports, at another moment): an hour in which `http` already logged requests live is
  skipped whole, and the estimate says how many were.

Only running commands that write log files can import. Starting an import is the API's
one write: it must send a JSON body, and a browser's `Origin` must name the host the
request went to (or one listed by name in `api_allowed_hosts`, for a proxy that rewrites
`Host`), so a page on another site cannot start one, even with `api_allowed_hosts: ["*"]`.

Behind a proxy that only forwards `GET`, the POST gets `405` from the proxy, and the admin
tab retries with `GET /admin/import/start`, carrying a token embedded in the admin page.
The token is random, new on each run, and only that page holds it: another site can link
to the URL but cannot read the page, so it cannot start an import. A token from before a
restart is refused (`403`): reload the tab. The token travels in the URL, so a proxy that
logs URLs keeps it until the next restart.

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
| `access_log`        | `"auto"` | Access log the [log import](#admin-tab) reads: `"auto"` (nginx's, else Apache's) or a file path |

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
(`timestamp`, `severity_number`, `severity_text`, `event_name`, `body`, `attributes`).
Fields that are always empty here are left out: the trace fields (no tracing) and the
observed time (a few µs after `timestamp`). They appear only if a record carries them.

Who wrote the events (`resource`: host, version, run instance) is not repeated on each
line. A log file starts with a `{"resource": {...}}` line, and each later run appending to it
writes its own; it applies to the records below it. On stdout, several commands share the
stream, so each line carries its `resource` instead.
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
zcat -f /etc/my_siem/logs/ssh/ssh.*.jsonl* | jq 'select(.severity_text == "ERROR")'   # only alerts and failures
zcat -f /etc/my_siem/logs/ssh/ssh.*.jsonl* | jq -c 'select(.event_name)'               # events, without resource lines
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
  logs/        log files, counts and the reading back of both; the log import
  web/         the dashboard: Jinja2 templates, SVG chart geometry, polled fragments, admin tab
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
| `just codetags`        | List the code's [annotations](#code-annotations) (`TODO`, `FIXME`, `HACK`, `PERF`, `SECURITY`) |
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

### Code annotations

Code that will need more work says so where it lives, with a tag comment that names the
kind of work, so `just codetags` lists everything that is pending:

```python
# HACK(import): a GET can start an import, for a proxy that forwards GET only.
# Ends when the proxy forwards POST; then drop this route and the token. #42
```

- **Shape**: `TAG(scope): what is wrong or missing.` then why it is so, and **what would
  end it** (the condition to remove the comment). Add an issue number (`#42`) when one exists.
- **Scope** is the area (`import`, `api`, `logs`, `ssh`...), not a person: `git blame`
  already names the author.
- **One tag per comment**, on the line above the code it is about. The same tags go in
  JavaScript, CSS and templates, in their own comment syntax (`//`, `/* */`, `{# #}`).
- Fix the cause or delete the tag in the change that ends it; a tag no longer true is a bug.

| Tag        | Means | Typical next step |
| ---------- | ----- | ----------------- |
| `TODO`     | Planned work not done yet: a missing case, feature or test | Implement |
| `FIXME`    | Known wrong behaviour, left for now | Fix the bug |
| `HACK`     | Works, but is a workaround or temporary: shaped by a constraint outside the code, or by haste | Refactor once the constraint is gone |
| `PERF`     | Known performance limit, fine at today's scale | Optimize when it shows |
| `SECURITY` | Accepted security trade-off, to revisit | Remove the trade-off |

These are the codetags most tools know: editors highlight them (VS Code's Todo Tree,
JetBrains' TODO view), and the scope-in-parentheses form is Google's style guide one.
A plain comment still explains *why* code is the way it is; tags are only for work left.
