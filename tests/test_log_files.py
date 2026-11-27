import gzip
import json
import time
from pathlib import Path

from my_siem.clock import hour_start
from my_siem.logs.files import (
    DAY,
    HOUR,
    MB,
    HourlyLogExporter,
    Retention,
    list_logs,
    log_name,
)
from my_siem.telemetry import INFO, event_logger, make_provider

T0 = 1_764_252_000  # 2025-11-27T14:00Z, 15:00 in Paris
KEEP_ALL = Retention(max_age_days=1000, max_size_mb=1000)


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def wait_for(check: object, timeout: float = 5) -> None:
    end = time.monotonic() + timeout
    while not check():  # type: ignore[operator]
        assert time.monotonic() < end, "sweep did not finish"
        time.sleep(0.01)


def events(lines: list[str]) -> list[str]:
    """Event names, past the resource lines."""
    return [json.loads(line)["event_name"] for line in lines if "event_name" in line]


def test_names_are_paris_hours_with_their_offset() -> None:
    assert hour_start(T0 + 3599) == T0
    assert log_name("ssh", T0) == "ssh.2025-11-27T15+0100.jsonl"
    assert log_name("ssh", 1_782_560_000) == "ssh.2026-06-27T13+0200.jsonl"


def test_the_hour_repeated_when_dst_ends_gets_two_files(tmp_path: Path) -> None:
    first = 1_792_886_400  # 2026-10-25T00:00Z: 02:00 summer time, then 02:00 winter
    names = [log_name("ssh", first), log_name("ssh", first + HOUR)]
    assert names == ["ssh.2026-10-25T02+0200.jsonl", "ssh.2026-10-25T02+0100.jsonl"]
    for n in names:
        (tmp_path / n).write_text("")
    assert [f.hour for f in list_logs(tmp_path, "ssh")] == [first, first + HOUR]


def test_records_go_to_the_file_of_the_hour_and_closed_hours_get_gzipped(
    tmp_path: Path,
) -> None:
    clock = Clock(T0 + 10)
    exporter = HourlyLogExporter(tmp_path, "ssh", KEEP_ALL, clock)
    out = event_logger(make_provider([exporter]), "test")
    out.emit(INFO, "first", "a")
    clock.now = T0 + HOUR + 10
    out.emit(INFO, "second", "b")

    current = tmp_path / log_name("ssh", T0 + HOUR)
    closed = tmp_path / (log_name("ssh", T0) + ".gz")
    wait_for(closed.exists)
    exporter.shutdown()

    with gzip.open(closed, "rt") as f:
        assert events(f.read().splitlines()) == ["first"]
    assert events(current.read_text().splitlines()) == ["second"]
    assert closed.stat().st_mode & 0o777 == 0o640
    assert [f.hour for f in list_logs(tmp_path, "ssh")] == [T0, T0 + HOUR]


def test_resumes_the_current_hour_after_a_cut_short_record(tmp_path: Path) -> None:
    (tmp_path / log_name("ssh", T0)).write_text('{"event_name": "old"}')
    exporter = HourlyLogExporter(tmp_path, "ssh", KEEP_ALL, Clock(T0 + 60))
    assert exporter.resumed
    event_logger(make_provider([exporter]), "test").emit(INFO, "new", "b")
    exporter.shutdown()

    lines = (tmp_path / log_name("ssh", T0)).read_text().splitlines()
    assert events(lines) == ["old", "new"]


def test_each_file_names_its_resource_once_then_holds_compact_records(
    tmp_path: Path,
) -> None:
    exporter = HourlyLogExporter(tmp_path, "ssh", KEEP_ALL, Clock(T0))
    out = event_logger(make_provider([exporter]), "test")
    out.emit(INFO, "one", "a", {"client.address": "203.0.113.4"})
    out.emit(INFO, "two", "b")
    exporter.shutdown()

    header, one, two = map(
        json.loads, (tmp_path / log_name("ssh", T0)).read_text().splitlines()
    )
    assert header["resource"]["attributes"]["service.name"] == "my_siem"
    assert set(one) == {
        "timestamp",
        "severity_number",
        "severity_text",
        "event_name",
        "body",
        "attributes",
    }
    assert one["attributes"] == {"client.address": "203.0.113.4"}
    assert two["event_name"] == "two"


def test_sweep_drops_files_past_the_age(tmp_path: Path) -> None:
    for hours_ago in (49, 47, 0):
        (tmp_path / log_name("ssh", T0 - hours_ago * HOUR)).write_text("x\n")
    (tmp_path / "other.txt").write_text("not ours")

    Retention(max_age_days=2, max_size_mb=1000).sweep(tmp_path, "ssh", T0, T0)

    left = list_logs(tmp_path, "ssh")
    assert [(f.hour, f.compressed) for f in left] == [
        (T0 - 47 * HOUR, True),
        (T0, False),
    ]
    assert (tmp_path / "other.txt").exists()


def test_sweep_drops_the_oldest_past_the_size_but_never_the_current(
    tmp_path: Path,
) -> None:
    def big(hour: int) -> None:
        (tmp_path / (log_name("ssh", hour) + ".gz")).write_bytes(b"x" * MB)

    for h in (3, 2, 1):
        big(T0 - h * HOUR)
    (tmp_path / log_name("ssh", T0)).write_bytes(b"x" * 3 * MB)

    Retention(max_age_days=1, max_size_mb=4).sweep(tmp_path, "ssh", T0, T0 + DAY / 2)

    assert [f.hour for f in list_logs(tmp_path, "ssh")] == [T0 - HOUR, T0]
