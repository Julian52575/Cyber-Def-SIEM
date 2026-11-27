"""Generate placeholder traffic and detections, nudged every `interval` seconds."""

import argparse
import math
import random
import threading
import time
from dataclasses import dataclass, replace
from typing import Any

from my_siem.clock import local
from my_siem.config import Fields
from my_siem.telemetry import INFO, EventLogger

RULES = ("Port scan", "Brute force", "Malware beacon", "Data exfiltration")


@dataclass(frozen=True)
class DummyConfig:
    """Settings of the `dummy` command, read from config/dummy/config.json."""

    interval: float = 5.0
    # Same seed, same starting data across runs.
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
        r = self._rand
        self._allowed = [
            round(120 + 80 * math.sin((h - 6) / 3.8) + r.random() * 30)
            for h in range(24)
        ]
        self._blocked = [round(10 + r.random() * 25) for _ in range(24)]
        self._rules = {
            "Port scan": round(40 + r.random() * 60),
            "Brute force": round(20 + r.random() * 40),
            "Malware beacon": round(5 + r.random() * 20),
            "Data exfiltration": round(r.random() * 10),
        }

    def tick(self, hour: int) -> None:
        with self._lock:
            self._allowed[hour] += self._rand.randint(0, 6)
            self._blocked[hour] += self._rand.randint(0, 2)
            if self._rand.random() < 0.3:
                self._rules[self._rand.choice(RULES)] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "config": self._config,
                "allowed": list(self._allowed),
                "blocked": list(self._blocked),
                "rules": dict(self._rules),
            }


def new_state(cfg: DummyConfig) -> DummyState:
    return DummyState(cfg)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    # None so that only a flag actually given overrides the config.
    parser.add_argument("--interval", type=float, help="seconds between updates")


def apply_flags(cfg: DummyConfig, args: argparse.Namespace) -> DummyConfig:
    return cfg if args.interval is None else replace(cfg, interval=args.interval)


def run(out: EventLogger, cfg: DummyConfig, state: DummyState) -> None:
    out.emit(
        INFO,
        "siem.source.started",
        f"generating placeholder data every {cfg.interval:g}s",
        {"siem.source": "dummy"},
    )
    while True:
        time.sleep(cfg.interval)
        state.tick(local(time.time()).hour)
