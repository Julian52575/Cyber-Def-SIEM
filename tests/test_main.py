import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from my_siem import main as cli
from my_siem.dummy.command import DummyConfig
from my_siem.http.command import HttpConfig
from my_siem.https.command import HttpsConfig
from my_siem.ssh.monitor import SshMonitorConfig
from my_siem.telemetry import INFO, EventLogger


@pytest.fixture
def ran_all(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Replace every command's run with a stub that records its config and logs once."""
    configs: dict[str, list[Any]] = {name: [] for name in cli.COMMANDS}

    for name in cli.COMMANDS:

        def fake_run(out: EventLogger, cfg: Any, state: Any, name: str = name) -> None:
            configs[name].append(cfg)
            out.emit(INFO, "test.ran", "ran")

        monkeypatch.setitem(
            cli.COMMANDS, name, replace(cli.COMMANDS[name], run=fake_run)
        )
    return configs


@pytest.fixture
def ran(ran_all: dict[str, list[Any]]) -> list[SshMonitorConfig]:
    return ran_all["ssh"]


def records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_without_configs_it_creates_them_uses_defaults_and_creates_log_folders(
    tmp_path: Path, ran: list[SshMonitorConfig], capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["--path", str(tmp_path), "ssh"])

    assert ran == [SshMonitorConfig()]
    err = capsys.readouterr().err
    assert err.count("warning: no config at") == 2
    assert (tmp_path / "config" / "config.json").is_file()
    assert (tmp_path / "config" / "ssh" / "config.json").is_file()
    log = tmp_path / "logs" / "ssh" / "ssh.jsonl"
    names = [r["event_name"] for r in records(log)]
    assert names == [
        "siem.log.opened",
        "siem.config.created",
        "siem.config.created",
        "siem.started",
        "test.ran",
        "siem.stopped",
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


def test_without_a_command_every_command_runs(
    tmp_path: Path, ran_all: dict[str, list[Any]]
) -> None:
    cli.main(["--path", str(tmp_path)])

    assert ran_all == {
        "ssh": [SshMonitorConfig()],
        "http": [HttpConfig()],
        "https": [HttpsConfig()],
        "dummy": [DummyConfig()],
    }
    for name in cli.COMMANDS:
        log = tmp_path / "logs" / name / f"{name}.jsonl"
        assert "test.ran" in [r["event_name"] for r in records(log)]


def test_only_the_given_commands_run_each_with_its_flags(
    tmp_path: Path, ran_all: dict[str, list[Any]]
) -> None:
    cli.main(["--path", str(tmp_path), "dummy", "--interval", "2"])

    assert ran_all == {
        "ssh": [],
        "http": [],
        "https": [],
        "dummy": [DummyConfig(interval=2.0)],
    }
    assert not (tmp_path / "logs" / "ssh").exists()


def test_several_commands_with_their_own_flags(
    tmp_path: Path, ran_all: dict[str, list[Any]]
) -> None:
    # "dummy" right after --interface is the interface name, not the command.
    cli.main(
        [
            "ssh",
            "--interface",
            "dummy",
            "--path",
            str(tmp_path),
            "dummy",
            "--interval",
            "3",
        ]
    )

    assert ran_all["ssh"][0].interface == "dummy"
    assert ran_all["dummy"] == [DummyConfig(interval=3.0)]


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["ssh", "ssh"], "command 'ssh' given twice"),
        (["sshh"], "unknown command 'sshh'"),
        (["dummy", "--ports", "22"], "unrecognized arguments: --ports"),
    ],
)
def test_bad_command_lines_are_rejected(
    tmp_path: Path,
    ran_all: dict[str, list[Any]],
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    message: str,
) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--path", str(tmp_path), *argv])

    assert exc.value.code == 2
    assert message in capsys.readouterr().err
    assert all(configs == [] for configs in ran_all.values())


def test_a_failing_command_stops_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(out: EventLogger, cfg: Any, state: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setitem(cli.COMMANDS, "ssh", replace(cli.COMMANDS["ssh"], run=crash))

    # dummy never returns on its own; the run must still end.
    with pytest.raises(RuntimeError, match="boom"):
        cli.main(["--path", str(tmp_path)])


def test_help_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--stdout", "--no-log", "--path", "ssh", "http", "https", "dummy"):
        assert flag in out


def test_http_and_https_are_told_apart(
    tmp_path: Path, ran_all: dict[str, list[Any]]
) -> None:
    cli.main(
        ["--path", str(tmp_path), "https", "--ports", "8443", "http", "--ports", "8080"]
    )

    assert ran_all["http"] == [HttpConfig(ports=frozenset({8080}))]
    assert ran_all["https"] == [HttpsConfig(ports=frozenset({8443}))]
    assert ran_all["ssh"] == ran_all["dummy"] == []
