import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from my_siem import main as cli
from my_siem.ssh.monitor import SshMonitorConfig
from my_siem.ssh.state import SshState
from my_siem.telemetry import INFO, EventLogger


@pytest.fixture
def ran(monkeypatch: pytest.MonkeyPatch) -> list[SshMonitorConfig]:
    """Replace the ssh monitor with a stub that records its config and logs once."""
    configs: list[SshMonitorConfig] = []

    def fake_run(out: EventLogger, cfg: SshMonitorConfig, state: SshState) -> None:
        configs.append(cfg)
        out.emit(INFO, "test.ran", "ran")

    monkeypatch.setitem(cli.COMMANDS, "ssh", replace(cli.COMMANDS["ssh"], run=fake_run))
    return configs


def records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_without_configs_it_warns_uses_defaults_and_creates_log_folders(
    tmp_path: Path, ran: list[SshMonitorConfig], capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["--path", str(tmp_path), "ssh"])

    assert ran == [SshMonitorConfig()]
    err = capsys.readouterr().err
    assert err.count("warning: no config at") == 2
    log = tmp_path / "logs" / "ssh" / "ssh.jsonl"
    names = [r["event_name"] for r in records(log)]
    assert names == [
        "siem.log.opened",
        "siem.config.missing",
        "siem.config.missing",
        "test.ran",
    ]


def test_appends_to_previous_log(tmp_path: Path, ran: list[SshMonitorConfig]) -> None:
    log = tmp_path / "logs" / "ssh" / "ssh.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text('{"event_name": "old"}')  # last record cut short, no newline

    cli.main(["--path", str(tmp_path), "ssh"])

    recs = records(log)
    assert recs[0] == {"event_name": "old"}
    assert recs[1]["event_name"] == "siem.log.opened"
    assert recs[1]["attributes"]["siem.log.resumed"] is True


def test_reads_general_and_command_configs_and_flags_win(
    tmp_path: Path, ran: list[SshMonitorConfig], capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "config" / "ssh").mkdir(parents=True)
    (tmp_path / "config" / "config.json").write_text('{"stdout": true}')
    (tmp_path / "config" / "ssh" / "config.json").write_text(
        '{"ports": [2222], "fail_threshold": 3}'
    )

    cli.main(["ssh", "--path", str(tmp_path), "--fail-threshold", "9"])

    assert ran[0].ports == frozenset({2222})
    assert ran[0].fail_threshold == 9
    out, err = capsys.readouterr()
    assert "warning" not in err
    assert '"test.ran"' in out  # stdout enabled by the general config


@pytest.mark.parametrize("position", ["before", "after"])
def test_general_flags_work_on_either_side_of_the_command(
    tmp_path: Path,
    ran: list[SshMonitorConfig],
    capsys: pytest.CaptureFixture[str],
    position: str,
) -> None:
    flags = ["--path", str(tmp_path), "--stdout", "--no-log"]
    cli.main(flags + ["ssh"] if position == "before" else ["ssh"] + flags)

    assert '"test.ran"' in capsys.readouterr().out
    assert not (tmp_path / "logs").exists()


def test_no_log_without_stdout_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--path", str(tmp_path), "--no-log", "ssh"])
    assert exc.value.code == 2


def test_bad_config_stops_with_an_error(
    tmp_path: Path, ran: list[SshMonitorConfig]
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.json").write_text('{"stdout": "yes"}')

    with pytest.raises(SystemExit, match="'stdout' must be bool"):
        cli.main(["--path", str(tmp_path), "ssh"])
    assert ran == []


def test_help_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--stdout", "--no-log", "--path", "ssh"):
        assert flag in out
