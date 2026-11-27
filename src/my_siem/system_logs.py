"""The host's own log files (auth.log, web server access logs) and their rotated copies."""

import gzip
from collections.abc import Iterator
from pathlib import Path


def rotated(path: Path) -> list[Path]:
    """`path`'s rotated copies (auth.log.1, auth.log.2.gz...), oldest first."""
    found = []
    for p in path.parent.glob(f"{path.name}.*"):
        n = p.name[len(path.name) + 1 :].removesuffix(".gz")
        if n.isdigit():
            found.append((int(n), p))
    return [p for _, p in sorted(found, reverse=True)]


def read_lines(path: Path) -> Iterator[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        yield from f


def history(path: Path, since: float) -> Iterator[str]:
    """Every line of `path` and its rotated copies, oldest first, skipping copies last
    written before `since`."""
    for p in [*rotated(path), path]:
        if p.stat().st_mtime >= since:
            yield from read_lines(p)
