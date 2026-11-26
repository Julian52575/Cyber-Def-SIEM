# List available recipes
default:
    @just --list

# Install dependencies (incl. dev group) into .venv
sync:
    uv sync

# Run the SIEM CLI, forwarding any arguments
run *args:
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
