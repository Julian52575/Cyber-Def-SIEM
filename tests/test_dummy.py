import json
from pathlib import Path

import pytest

from my_siem.config import ConfigError, load_config
from my_siem.dummy import add
from my_siem.dummy.command import DummyConfig, DummyState, count_keys


def test_add() -> None:
    assert add(2, 3) == 5


def ticks(seed: int, n: int = 20) -> list[dict[str, object]]:
    state = DummyState(DummyConfig(seed=seed))
    return [state.tick() for _ in range(n)]


def test_same_seed_same_made_up_traffic() -> None:
    assert ticks(42) == ticks(42)
    assert ticks(42) != ticks(7)


def test_a_tick_counts_its_traffic_and_rule() -> None:
    attributes = {
        "siem.dummy.allowed": 4,
        "siem.dummy.blocked": 1,
        "siem.dummy.rule": "Port scan",
    }
    assert count_keys("siem.dummy.tick", attributes) == {
        "siem.dummy.tick": 1,
        "allowed": 4,
        "blocked": 1,
        "rule:Port scan": 1,
    }
    assert count_keys("siem.source.started", {}) == {"siem.source.started": 1}


def test_config_file_and_validation(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"interval": 1}))

    cfg = load_config(path, DummyConfig.from_json, DummyConfig(), [])

    assert cfg == DummyConfig(interval=1.0)
    path.write_text(json.dumps({"interval": 0}))
    with pytest.raises(ConfigError, match="'interval' must be positive"):
        load_config(path, DummyConfig.from_json, DummyConfig(), [])
