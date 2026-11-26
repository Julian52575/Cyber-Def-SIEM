import json
from pathlib import Path

import pytest

from my_siem.config import ConfigError, load_config
from my_siem.dummy import add
from my_siem.dummy.command import DummyConfig, DummyState


def test_add() -> None:
    assert add(2, 3) == 5


def test_same_seed_same_starting_data() -> None:
    a = DummyState(DummyConfig()).snapshot()
    b = DummyState(DummyConfig()).snapshot()
    c = DummyState(DummyConfig(seed=7)).snapshot()

    assert a == b
    assert a["allowed"] != c["allowed"]
    assert len(a["allowed"]) == len(a["blocked"]) == 24


def test_tick_only_grows_the_given_hour() -> None:
    state = DummyState(DummyConfig())
    before = state.snapshot()

    for _ in range(20):
        state.tick(hour=3)
    after = state.snapshot()

    assert after["allowed"][3] > before["allowed"][3]
    others = [h for h in range(24) if h != 3]
    assert [after["allowed"][h] for h in others] == [
        before["allowed"][h] for h in others
    ]
    assert sum(after["rules"].values()) >= sum(before["rules"].values())


def test_config_file_and_validation(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"interval": 1}))

    cfg = load_config(path, DummyConfig.from_json, DummyConfig(), [])

    assert cfg == DummyConfig(interval=1.0)
    path.write_text(json.dumps({"interval": 0}))
    with pytest.raises(ConfigError, match="'interval' must be positive"):
        load_config(path, DummyConfig.from_json, DummyConfig(), [])
