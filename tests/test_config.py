import json
import os
from pathlib import Path

import pytest

from my_siem.config import (
    ConfigError,
    ConfigWarning,
    GeneralConfig,
    Layout,
    load_config,
)
from my_siem.ssh.monitor import SshMonitorConfig


def write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


def test_layout_puts_each_command_in_its_own_folders() -> None:
    layout = Layout(Path("/etc/my_siem"))
    assert layout.general_config == Path("/etc/my_siem/config/config.json")
    assert layout.command_config("ssh") == Path("/etc/my_siem/config/ssh/config.json")
    assert layout.log_dir("ssh") == Path("/etc/my_siem/logs/ssh")
    assert layout.rollup_file("ssh") == Path("/etc/my_siem/logs/ssh/rollup.json")


def test_missing_config_is_created_with_the_defaults(tmp_path: Path) -> None:
    warnings: list[ConfigWarning] = []
    path = tmp_path / "config" / "ssh" / "config.json"

    cfg = load_config(path, SshMonitorConfig.from_json, SshMonitorConfig(), warnings)

    assert cfg == SshMonitorConfig()
    assert [(w.event_name, w.path) for w in warnings] == [("siem.config.created", path)]
    assert json.loads(path.read_text()) == SshMonitorConfig().to_json()


def test_created_config_is_read_back_on_the_next_run(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    load_config(path, GeneralConfig.from_json, GeneralConfig(), [])
    warnings: list[ConfigWarning] = []

    cfg = load_config(path, GeneralConfig.from_json, GeneralConfig(), warnings)

    assert cfg == GeneralConfig()
    assert warnings == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores folder permissions")
def test_unwritable_config_folder_falls_back_to_defaults(tmp_path: Path) -> None:
    tmp_path.chmod(0o500)
    path = tmp_path / "config" / "config.json"
    warnings: list[ConfigWarning] = []

    cfg = load_config(path, GeneralConfig.from_json, GeneralConfig(), warnings)

    assert cfg == GeneralConfig()
    assert [w.event_name for w in warnings] == ["siem.config.missing"]


def test_partial_config_keeps_defaults_for_the_rest(tmp_path: Path) -> None:
    path = write(tmp_path / "ssh.json", {"ports": [22, 2222], "window": 30})

    cfg = load_config(path, SshMonitorConfig.from_json, SshMonitorConfig(), [])

    assert cfg.ports == frozenset({22, 2222})
    assert cfg.window == 30.0
    assert cfg.fail_threshold == SshMonitorConfig().fail_threshold


def test_ports_accept_a_range_string(tmp_path: Path) -> None:
    path = write(tmp_path / "ssh.json", {"ports": "22,221-223"})
    cfg = load_config(path, SshMonitorConfig.from_json, SshMonitorConfig(), [])
    assert cfg.ports == frozenset({22, 221, 222, 223})


def test_unknown_keys_are_warned_about(tmp_path: Path) -> None:
    warnings: list[ConfigWarning] = []
    path = write(tmp_path / "config.json", {"stdout": True, "colour": "red"})

    cfg = load_config(path, GeneralConfig.from_json, GeneralConfig(), warnings)

    assert cfg.stdout
    assert [w.event_name for w in warnings] == ["siem.config.unknown_key"]
    assert "'colour'" in warnings[0].message


@pytest.mark.parametrize(
    "data",
    [
        {"fail_threshold": "5"},
        {"fail_threshold": True},
        {"fail_threshold": 0},
        {"ports": [22, "ssh"]},
        {"ports": "0"},
        {"sniff_traffic": 1},
        {"sniff_traffic": False, "read_auth_log": False},
        {"auth_log": None},
    ],
)
def test_invalid_values_are_errors(tmp_path: Path, data: dict[str, object]) -> None:
    path = write(tmp_path / "ssh.json", data)
    with pytest.raises(ConfigError, match="ssh.json"):
        load_config(path, SshMonitorConfig.from_json, SshMonitorConfig(), [])


@pytest.mark.parametrize("text", ["{not json", "[1, 2]"])
def test_malformed_file_is_an_error(tmp_path: Path, text: str) -> None:
    path = tmp_path / "config.json"
    path.write_text(text)
    with pytest.raises(ConfigError):
        load_config(path, GeneralConfig.from_json, GeneralConfig(), [])
