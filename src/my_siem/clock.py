"""Paris time, whatever the host's zone: where log files, counts and the dashboard cut time."""

from datetime import date, datetime, timedelta
from datetime import time as daytime
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Europe/Paris")
MINUTE = 60
HOUR = 3600


def local(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, TZ)


def minute_start(epoch: float) -> int:
    return int(epoch // MINUTE * MINUTE)


def hour_start(epoch: float) -> int:
    # Paris is always a whole number of hours from UTC, DST included, so its hours are UTC's.
    return int(epoch // HOUR * HOUR)


def midnight(day: date) -> int:
    # DST changes at 02:00 or 03:00, so midnight always exists and is unique.
    return int(datetime.combine(day, daytime(), TZ).timestamp())


def day_start(epoch: float) -> int:
    return midnight(local(epoch).date())


def add_days(start: int, n: int) -> int:
    """Midnight `n` days after the day starting at `start`: days last 23 to 25 hours."""
    return midnight(local(start).date() + timedelta(days=n))
