"""Time filters: the last N minutes, hours or days, counted in whole Paris buckets."""

from collections.abc import Callable
from dataclasses import dataclass

from my_siem.clock import HOUR, MINUTE, add_days, day_start, hour_start, minute_start


@dataclass(frozen=True)
class Tier:
    name: str
    keep: int  # complete buckets kept, besides the current one
    start: Callable[[float], int]  # start of the bucket holding an epoch
    shift: Callable[[int, int], int]  # a bucket start moved by n buckets

    def oldest(self, now: float) -> int:
        return self.shift(self.start(now), -self.keep)


TIERS = {
    t.name: t
    for t in (
        Tier("minute", 60, minute_start, lambda s, n: s + n * MINUTE),
        Tier("hour", 24, hour_start, lambda s, n: s + n * HOUR),
        # Not a fixed width: DST days last 23 or 25 hours.
        Tier("day", 100, day_start, add_days),
    )
}


@dataclass(frozen=True)
class Window:
    """The current bucket and the `count - 1` before it: "3 hours" at 14:20 is from 12:00.

    Whole buckets, so a day starts at Paris midnight and an hour at minute 00.
    """

    unit: str
    count: int

    def __post_init__(self) -> None:
        if self.unit not in TIERS:
            raise ValueError(
                f"unit must be one of {', '.join(TIERS)}, got {self.unit!r}"
            )
        if not 1 <= self.count <= self.max:
            raise ValueError(f"count must be 1 to {self.max} {self.unit}s")

    @property
    def tier(self) -> Tier:
        return TIERS[self.unit]

    @property
    def max(self) -> int:
        return TIERS[self.unit].keep

    def since(self, now: float) -> int:
        return self.tier.shift(self.tier.start(now), 1 - self.count)

    def label(self) -> str:
        return f"Last {self.count} {self.unit}{'s' if self.count > 1 else ''}"

    def to_json(self) -> dict[str, object]:
        return {"unit": self.unit, "count": self.count}


DEFAULT_WINDOW = Window("minute", 60)
# How far back any filter reaches, and so how far back history is worth reading.
LONGEST = Window("day", TIERS["day"].keep)
