"""Generate placeholder traffic and detections, one logged tick every `interval` seconds."""

import argparse
import math
import random
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from my_siem.clock import local
from my_siem.config import Fields
from my_siem.logs import LogManager, event_keys
from my_siem.telemetry import INFO

RULES = ("Port scan", "Brute force", "Malware beacon", "Data exfiltration")


@dataclass(frozen=True)
class DummyConfig:
    """Settings of the `dummy` command, read from config/dummy/config.json."""

    interval: float = 5.0
    # Same seed, same made-up traffic across runs.
    seed: int = 42

    def __post_init__(self) -> None:
        if self.interval <= 0:
            raise ValueError("'interval' must be positive")

    @classmethod
    def from_json(cls, f: Fields) -> "DummyConfig":
        d = cls()
        return cls(
            interval=f.get("interval", float, d.interval),
            seed=f.get("seed", int, d.seed),
        )

    def to_json(self) -> dict[str, Any]:
        return {"interval": self.interval, "seed": self.seed}


class DummyState:
    """Thread-safe: the command thread ticks while the API thread reads."""

    def __init__(self, cfg: DummyConfig) -> None:
        self._lock = threading.Lock()
        self._config = cfg.to_json()
        self._rand = random.Random(cfg.seed)
        self._ticks = 0

    def tick(self) -> dict[str, Any]:
        """Make up one interval of traffic, as the attributes of its event."""
        with self._lock:
            self._ticks += 1
            r = self._rand
            # Busier by day than by night, like real traffic.
            hour = local(time.time()).hour
            busy = 1 + math.sin((hour - 6) / 3.8)
            attributes: dict[str, Any] = {
                "siem.dummy.allowed": round(r.randint(0, 6) * busy),
                "siem.dummy.blocked": r.randint(0, 2),
            }
            if r.random() < 0.3:
                attributes["siem.dummy.rule"] = r.choice(RULES)
            return attributes

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"config": self._config, "ticks": self._ticks}


def new_state(cfg: DummyConfig) -> DummyState:
    return DummyState(cfg)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    # None so that only a flag actually given overrides the config.
    parser.add_argument("--interval", type=float, help="seconds between updates")


def apply_flags(cfg: DummyConfig, args: argparse.Namespace) -> DummyConfig:
    return cfg if args.interval is None else replace(cfg, interval=args.interval)


def count_keys(name: str, attributes: Mapping[str, Any]) -> dict[str, int]:
    """A tick counts its allowed and blocked events, and the rule it triggered."""
    keys = event_keys(name, attributes)
    if name == "siem.dummy.tick":
        keys["allowed"] = int(attributes.get("siem.dummy.allowed", 0))
        keys["blocked"] = int(attributes.get("siem.dummy.blocked", 0))
        if rule := attributes.get("siem.dummy.rule"):
            keys[f"rule:{rule}"] = 1
    return keys


def run(logs: LogManager, cfg: DummyConfig, state: DummyState) -> None:
    logs.out.emit(
        INFO,
        "siem.source.started",
        f"generating placeholder data every {cfg.interval:g}s",
        {"siem.source": "dummy"},
    )
    while True:
        time.sleep(cfg.interval)
        attributes = state.tick()
        logs.out.emit(
            INFO,
            "siem.dummy.tick",
            f"{attributes['siem.dummy.allowed']} allowed, "
            f"{attributes['siem.dummy.blocked']} blocked",
            attributes,
        )
