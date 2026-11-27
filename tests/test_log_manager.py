import io
import json
import time
from pathlib import Path

from my_siem.http.command import count_keys
from my_siem.logs import LogManager, Retention, Window
from my_siem.logs.files import list_logs
from my_siem.telemetry import ERROR, INFO, JsonLinesExporter

KEEP = Retention(max_age_days=100, max_size_mb=100)
HOUR = Window("hour", 1)


def test_writes_files_counts_and_stdout_and_reads_them_back(tmp_path: Path) -> None:
    stdout = io.StringIO()
    logs = LogManager("http", tmp_path, KEEP, count_keys, JsonLinesExporter(stdout))
    logs.out.emit(INFO, "siem.http.response", "404", {"http.response.status_code": 404})
    logs.out.emit(ERROR, "siem.alert.http_error_scan", "scan", {"client.address": "x"})

    [bucket] = logs.counts(HOUR)
    assert bucket.counts == {
        "siem.http.response": 1,
        "status:4xx": 1,
        "siem.alert.http_error_scan": 1,
        "alerts": 1,
    }
    [alert] = logs.recent(("siem.alert.",), HOUR)
    assert alert["attributes"] == {"client.address": "x"}
    assert len(stdout.getvalue().splitlines()) == 2
    [f] = list_logs(tmp_path, "http")
    assert f.path == logs.log_file
    logs.close()
    assert (tmp_path / "rollup.json").is_file()


def test_counts_and_marks_come_back_after_a_restart(tmp_path: Path) -> None:
    logs = LogManager("ssh", tmp_path, KEEP)
    logs.out.emit(INFO, "siem.ssh.login_success", "in")
    logs.set_mark("sshd_log", 123.5)
    logs.close()

    again = LogManager("ssh", tmp_path, KEEP)
    assert again.resumed
    assert again.mark("sshd_log") == 123.5
    assert again.counts(HOUR)[-1].counts == {"siem.ssh.login_success": 1}
    assert (
        again.recent(("siem.ssh.",), HOUR)[0]["event_name"] == "siem.ssh.login_success"
    )
    again.close()


def test_a_broken_counts_file_only_loses_the_counts(tmp_path: Path) -> None:
    (tmp_path / "rollup.json").write_text("{broken")

    logs = LogManager("ssh", tmp_path, KEEP)

    assert logs.counts(HOUR)[-1].counts == {}
    logs.close()


def test_without_a_folder_everything_stays_in_memory(tmp_path: Path) -> None:
    logs = LogManager("ssh", None)
    logs.out.emit(INFO, "siem.ssh.logout", "bye", at=time.time() - 5)

    assert logs.log_file is None and not logs.resumed
    assert logs.counts(HOUR)[-1].counts == {"siem.ssh.logout": 1}
    [record] = logs.recent(("siem.ssh.",), HOUR)
    assert json.dumps(record)  # plain JSON, as the API serves it
    logs.close()
    assert list(tmp_path.iterdir()) == []
