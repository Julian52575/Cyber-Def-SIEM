# Tests

Tests use [pytest](https://docs.pytest.org/). Run them with `just check-test`.
To run only some of them: `uv run pytest tests/test_dummy.py`, or `uv run pytest -k add`.

## Writing a test

1. Create a file named `test_<module>.py` in `tests/`, one per module under test.
2. Import from the installed package: `from my_siem.<module> import <name>`.
   Never import from `src.` or change `sys.path`.
3. Write functions named `test_<behaviour>` that use a plain `assert`.

```python
from my_siem.dummy import add


def test_add() -> None:
    assert add(2, 3) == 5
```

pytest only collects files matching `test_*.py` and functions matching `test_*`;
anything else is silently ignored.

## Useful patterns

Expect an exception:

```python
import pytest


def test_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        parse("not a packet")
```

Run the same test on several inputs:

```python
@pytest.mark.parametrize(("a", "b", "expected"), [(1, 2, 3), (0, 0, 0), (-1, 1, 0)])
def test_add(a: int, b: int, expected: int) -> None:
    assert add(a, b) == expected
```

Use a temporary file (the `tmp_path` fixture gives a fresh directory per test):

```python
def test_reads_log(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("Failed password for root\n")
    assert count_failures(log) == 1
```

Share setup between tests with a fixture. Put it in `tests/conftest.py`
and pytest makes it available to every test file:

```python
@pytest.fixture
def ping_packet():
    from scapy.layers.inet import ICMP, IP

    return IP(dst="10.0.0.1") / ICMP()
```

## Guidelines

- Keep tests offline and unprivileged. Build Scapy packets in memory
  (`IP(...) / TCP(...)`) instead of sending or sniffing on the network.
- One behaviour per test, and a test name that says what it checks.
- Make a test fail once before trusting it.
