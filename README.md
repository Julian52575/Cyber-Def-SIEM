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
just sync          # create .venv and install dependencies, dev tools included
just set-githooks  # enable the repo's git hooks
just check         # lint, type-check and test
just run --path . --stdout ssh   # track SSH connections, config and logs in the repo
```

> Sniffing packets with Scapy needs root or the `CAP_NET_RAW` capability.

### Usage

```
my_siem [--stdout] [--no-log] [--path PATH] [--api [--api-host HOST] [--api-port PORT]] COMMAND [command flags]
```

| Flag          | Description                                                     |
| ------------- | --------------------------------------------------------------- |
| `-h, --help`  | Show usage (`my_siem ssh --help` for the command's own flags)   |
| `--stdout`    | Also print events to stdout (default: off)                      |
| `--no-log`    | Do not write events to log files (default: off)                 |
| `--path PATH` | Root folder of `config/` and `logs/` (default: `/etc/my_siem`)  |
| `--api`       | Serve live monitoring data over HTTP (see [API](#api))          |
| `--api-host HOST` | Address the API listens on (default: `127.0.0.1`)           |
| `--api-port PORT` | Port the API listens on (default: `12125`)                  |

General flags may go before or after the command. Command-line flags override the config files.

### Configuration and logs

```
<path>/
├── config/
│   ├── config.json        general config
│   └── <command>/config.json
└── logs/
    └── <command>/<command>.jsonl
```

All config files are JSON and optional: a missing file prints a warning and the built-in
defaults are used. Keys left out of a file keep their default; unknown keys are warned
about; a malformed file or wrong value type stops my_siem with an error.
Examples with every key at its default are in [`config/`](config/).

`config/config.json`:

| Key      | Default | Description                       |
| -------- | ------- | --------------------------------- |
| `stdout` | `false` | Also print events to stdout       |
| `log`    | `true`  | Write events to the log file      |
| `api`    | `false` | Serve the API (as `--api`)        |
| `api_host` | `"127.0.0.1"` | Address the API listens on |
| `api_port` | `12125` | Port the API listens on         |
| `api_cors_origins` | `["http://localhost:3000", "http://127.0.0.1:3000"]` | Browser origins allowed to call the API (the frontend) |

### API

With `--api`, my_siem also runs a read-only HTTP API (FastAPI) while it monitors. Any
method other than `GET`, `HEAD` or `OPTIONS` (CORS preflight) gets `405`, on every path:

```sh
sudo .venv/bin/my_siem --api ssh
curl localhost:12125/ssh
```

| Endpoint        | Returns                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| `GET /healthz`  | `{"status": "ok", "command": "ssh"}`                                    |
| `GET /ssh`      | Effective config, source status, event counts, active connections, last 100 logins and alerts |
| `GET /docs`     | Interactive OpenAPI docs                                                |

Only the running command's endpoint exists (`/ssh` under `my_siem ssh`). The API listens
on loopback by default because it exposes users and addresses; use `--api-host 0.0.0.0`
to reach it from another machine, and add the frontend's origin to `api_cors_origins`.

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
| `iface`          | `null`   | Interface to sniff on (`null`: all)                            |
| `auth_log`       | `"auto"` | `"auto"` (auth.log, else journald), `"journald"`, or a file path |
| `read_auth_log`  | `true`   | Read sshd logs (`--no-auth-log` to disable)                    |
| `sniff`          | `true`   | Sniff network traffic (`--no-sniff` to disable)                |
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
| `siem.source.started` / `siem.source.failed`        | INFO / ERROR |
| `siem.log.opened`                                   | INFO     |
| `siem.config.missing`, `siem.config.unknown_key`    | WARN     |

```sh
jq 'select(.severity_text == "ERROR")' /etc/my_siem/logs/ssh/ssh.jsonl   # only alerts and failures
```

### Project layout

```
src/my_siem/   the package (entry point: my_siem.main:main)
  ssh/         the `ssh` command: sshd log parsing, network tracking, monitor, flags
config/        example configs, all values at their defaults
logs/          log output when run with --path . (git-ignored)
frontend/      React + Vite + TypeScript UI (oxlint, vitest)
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
| `just check`           | Run every check below, in order                     |
| `just check-lint`      | Lint `src` and `tests` with ruff, auto-fixing       |
| `just check-typecheck` | Type-check `src` with mypy                          |
| `just check-test`      | Run the pytest suite                                |
| `just frontend-install` | Install the frontend dependencies (needs Node 24)  |
| `just frontend-dev`    | Start the Vite dev server on port 3000              |
| `just frontend-check`  | Lint, test and build the frontend, as CI does       |
| `just set-githooks`    | Use `.githooks/` as the git hooks directory         |

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
