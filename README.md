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
just run           # run the SIEM
```

> Sending packets with Scapy may need root or the `CAP_NET_RAW` capability.

### Project layout

```
src/my_siem/   the package (entry point: my_siem.main:main)
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
