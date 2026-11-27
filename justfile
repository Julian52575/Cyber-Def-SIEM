version := `python3 -c 'import json; print(json.load(open(".release-please-manifest.json"))["."])'`

# List available recipes
default:
    @just --list

# Install dependencies (incl. dev group) into .venv
sync:
    uv sync

# Run the SIEM CLI, forwarding any arguments
run *args: write-version
    uv run my_siem {{args}}

# Format the source with ruff
fmt:
    uv run ruff format src tests

# Lint the source with ruff
lint:
    uv run ruff check src tests 


# Run all checks (lint, typecheck, test)
check: check-lint check-typecheck check-test

# Lint the source with ruff
check-lint:
    uv run ruff check src tests 

# Type-check the source with mypy
check-typecheck:
    uv run mypy src

# Run the test suite
check-test:
    uv run pytest

# Use the repo's .githooks as git hooks
set-githooks:
    git config core.hooksPath .githooks

# Build a standalone ELF binary at dist/my_siem, skipped when no source changed since the last build
build: write-version
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -f dist/my_siem ]] && [[ -z "$(find src pyproject.toml uv.lock -newer dist/my_siem -not -path '*/__pycache__/*' -print -quit)" ]]; then
        echo "dist/my_siem is up to date"
        exit 0
    fi
    uv run --with pyinstaller pyinstaller --onefile --clean --noconfirm \
        --name my_siem --paths src --collect-data my_siem \
        --specpath build src/my_siem/main.py

# Build, then install the binary into DEST: a local folder or an ssh target like user@host:/opt/bin
install dest: build
    #!/usr/bin/env bash
    set -euo pipefail
    dest='{{dest}}'
    if [[ "$dest" == *:* ]]; then
        host="${dest%%:*}"
        dir="${dest#*:}"
        dir="${dir:-.}"
        ssh "$host" "mkdir -p '$dir'"
        # Upload to a temp name, then rename: scp fails writing over an existing (busy or read-only) my_siem
        scp dist/my_siem "$host:$dir/.my_siem.new"
        ssh "$host" "chmod 755 '$dir/.my_siem.new' && mv -f '$dir/.my_siem.new' '$dir/my_siem'"
    else
        install -Dm755 dist/my_siem "$dest/my_siem"
    fi
    echo "Installed my_siem to $dest"

# Write the version from .release-please-manifest.json into the package, plus
# the ref name and commit hash unless HEAD is the matching release tag; only when it changed
# so the file's mtime does not force a rebuild
[private]
write-version:
    #!/usr/bin/env bash
    v='{{version}}'
    if ! git tag --points-at HEAD | grep -qx "v$v"; then
        v="$v $(git rev-parse --abbrev-ref HEAD)-$(git rev-parse HEAD)"
    fi
    line="VERSION = \"$v\""
    f=src/my_siem/_version.py
    [[ "$(cat "$f" 2>/dev/null)" == "$line" ]] || echo "$line" > "$f"
