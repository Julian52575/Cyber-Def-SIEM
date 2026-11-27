import json
from pathlib import Path

import pytest

from my_siem.clock import add_days
from my_siem.rollup import Bucket, Rollup, RollupExporter
from my_siem.telemetry import INFO, event_logger, make_provider

T0 = 1_764_198_000  # 2025-11-27 00:00 in Paris (23:00Z the day before)
DAY = 86400


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_counts_events_in_every_tier() -> None:
    r = Rollup(clock=Clock(T0 + 3 * 3600 + 150))
    r.add("login", T0 + 3 * 3600 + 130)
    r.add("login", T0 + 3 * 3600 + 140)
    r.add("alert", T0 + 3 * 3600 + 30)

    tier, minutes = r.series(T0 + 3 * 3600)
    assert tier.name == "minute"
    assert [b.counts for b in minutes] == [{"alert": 1}, {}, {"login": 2}]

    tier, hours = r.series(T0)
    assert tier.name == "hour"
    assert [b.start for b in hours] == [T0 + h * 3600 for h in range(4)]
    assert hours[3].counts == {"login": 2, "alert": 1}

    tier, days = r.series(T0 - 10 * 86400)
    assert tier.name == "day"
    assert len(days) == 11
    assert days[-1].counts == {"login": 2, "alert": 1}


def test_longest_range_is_capped_to_what_is_kept() -> None:
    _, days = Rollup(clock=Clock(T0)).series(T0 - 1000 * 86400)
    assert len(days) == 101  # 100 complete days and today


def test_old_buckets_are_dropped_per_tier(tmp_path: Path) -> None:
    path = tmp_path / "rollup.json"
    clock = Clock(T0)
    r = Rollup(path, clock)
    r.add("x", T0)
    clock.now = T0 + 2 * 3600  # past the minute tier, inside the hour tier
    r.add("y", clock.now)

    saved = json.loads(path.read_text())
    assert saved["minute"] == {str(T0 + 2 * 3600): {"y": 1}}
    assert saved["hour"][str(T0)] == {"x": 1}


def test_counts_survive_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "rollup.json"
    clock = Clock(T0 + 5)
    exporter = RollupExporter(Rollup(path, clock))
    event_logger(make_provider([exporter]), "test").emit(INFO, "login", "a", at=T0 + 1)
    exporter.shutdown()
    assert path.stat().st_mode & 0o777 == 0o640

    again = Rollup(path, clock)
    again.load()
    _, minutes = again.series(T0)
    assert minutes[-1].counts == {"login": 1}


def test_saves_when_a_minute_ends(tmp_path: Path) -> None:
    path = tmp_path / "rollup.json"
    clock = Clock(T0 + 5)
    r = Rollup(path, clock)
    r.add("x", clock.now)
    assert not path.exists()
    clock.now = T0 + 65
    r.add("x", clock.now)
    assert json.loads(path.read_text())["minute"] == {
        str(T0): {"x": 1},
        str(T0 + 60): {"x": 1},
    }


def test_a_day_starts_at_paris_midnight() -> None:
    r = Rollup(clock=Clock(T0 + 3600))
    r.add("before", T0 - 1)  # 23:59:59 in Paris, though already the 27th in UTC
    r.add("after", T0)

    _, days = r.series(T0 - 5 * DAY)
    assert days[-2:] == [Bucket(T0 - DAY, {"before": 1}), Bucket(T0, {"after": 1})]


@pytest.mark.parametrize(
    ("midnight", "hours"),
    [
        (1_774_738_800, 23),  # 2026-03-29, summer time starts
        (1_792_879_200, 25),  # 2026-10-25, summer time ends
    ],
)
def test_dst_days_last_23_or_25_hours(midnight: int, hours: int) -> None:
    assert add_days(midnight, 1) - midnight == hours * 3600
    r = Rollup(clock=Clock(midnight + DAY + 7200))
    r.add("x", midnight + hours * 3600 - 1)  # the last second of the long or short day

    _, days = r.series(midnight)
    assert [b.start for b in days] == [midnight, midnight + hours * 3600]
    assert days[0].counts == {"x": 1}


def test_unknown_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "rollup.json"
    path.write_text('{"format": 99}')
    with pytest.raises(ValueError, match="format"):
        Rollup(path).load()
