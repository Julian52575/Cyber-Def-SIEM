import gzip
import json
from datetime import UTC, datetime
from pathlib import Path

from my_siem.clock import HOUR
from my_siem.logs.files import log_name
from my_siem.logs.reader import FileReader

T0 = 1_764_252_000  # 2025-11-27T14:00Z
LOGINS = ("siem.ssh.login_",)


def line(name: str, at: float, user: str = "") -> str:
    stamp = datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    record = {"timestamp": stamp, "event_name": name, "attributes": {"user": user}}
    return json.dumps(record, separators=(",", ":")) + "\n"


def users(records: list[dict[str, object]]) -> list[object]:
    return [r["attributes"]["user"] for r in records]  # type: ignore[index]


def test_reads_the_kinds_asked_for_newest_first_across_hours(tmp_path: Path) -> None:
    with gzip.open(tmp_path / (log_name("ssh", T0 - HOUR) + ".gz"), "wt") as f:
        f.write('{"resource":{}}\n')
        f.write(line("siem.ssh.login_failure", T0 - HOUR + 10, "a"))
    (tmp_path / log_name("ssh", T0)).write_text(
        line("siem.ssh.login_success", T0 + 10, "b")
        + line("siem.ssh.connection.opened", T0 + 20, "not a login")
        + line("siem.ssh.login_failure", T0 + 30, "c")
    )
    reader = FileReader(tmp_path, "ssh")

    assert users(reader.recent(LOGINS, T0 - HOUR)) == ["c", "b", "a"]
    assert users(reader.recent(LOGINS, T0 + 15)) == ["c"]
    assert users(reader.recent(LOGINS, T0 - HOUR, limit=2)) == ["c", "b"]


def test_the_hour_being_written_is_read_on_from_where_it_stopped(
    tmp_path: Path,
) -> None:
    path = tmp_path / log_name("ssh", T0)
    path.write_text(line("siem.ssh.login_success", T0 + 1, "a"))
    reader = FileReader(tmp_path, "ssh")
    assert users(reader.recent(LOGINS, T0)) == ["a"]

    full = line("siem.ssh.login_success", T0 + 2, "b")
    with path.open("a") as f:
        f.write(full[:20])  # still being written
    assert users(reader.recent(LOGINS, T0)) == ["a"]
    with path.open("a") as f:
        f.write(full[20:])
    assert users(reader.recent(LOGINS, T0)) == ["b", "a"]


def test_older_events_written_late_are_still_ordered_by_when_they_happened(
    tmp_path: Path,
) -> None:
    # Read back from sshd's history at startup: written now, timed hours ago.
    (tmp_path / log_name("ssh", T0 - 3 * HOUR)).write_text(
        line("siem.ssh.login_success", T0 - 3 * HOUR + 5, "old file")
    )
    (tmp_path / log_name("ssh", T0)).write_text(
        line("siem.ssh.login_success", T0 - 2 * HOUR, "history")
        + line("siem.ssh.login_success", T0 + 5, "live")
    )
    reader = FileReader(tmp_path, "ssh")

    assert users(reader.recent(LOGINS, T0 - 4 * HOUR)) == [
        "live",
        "history",
        "old file",
    ]
    assert users(reader.recent(LOGINS, T0 - 2 * HOUR - 1)) == ["live", "history"]
