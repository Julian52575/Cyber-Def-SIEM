"""On-disk layout (config/ and logs/ under one root) and JSON config loading."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path("/etc/my_siem")
CONFIG_FILE = "config.json"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Layout:
    root: Path

    @property
    def general_config(self) -> Path:
        return self.root / "config" / CONFIG_FILE

    def command_config(self, command: str) -> Path:
        return self.root / "config" / command / CONFIG_FILE

    def log_file(self, command: str) -> Path:
        return self.root / "logs" / command / f"{command}.jsonl"


@dataclass(frozen=True)
class ConfigWarning:
    event_name: str
    message: str
    path: Path


class Fields:
    """Typed, consuming access to a config object, so leftover keys can be reported."""

    def __init__(self, data: dict[str, Any], path: Path) -> None:
        self._data = dict(data)
        self.path = path

    def get[T](self, key: str, kind: type[T], default: T) -> T:
        if key not in self._data:
            return default
        value = self.optional(key, kind)
        if value is None:
            raise ConfigError(f"{self.path}: {key!r} cannot be null")
        return value

    def optional[T](self, key: str, kind: type[T]) -> T | None:
        value = self._data.pop(key, None)
        if value is None:
            return None
        if kind is float and type(value) is int:
            value = float(value)
        # bool is a subclass of int, but true is not a valid port or threshold.
        if not isinstance(value, kind) or (type(value) is bool and kind is not bool):
            raise ConfigError(
                f"{self.path}: {key!r} must be {kind.__name__}, got {value!r}"
            )
        return value

    def raw(self, key: str) -> Any:
        return self._data.pop(key, None)

    def leftover(self) -> list[str]:
        return sorted(self._data)


def load_config[C](
    path: Path,
    from_json: Callable[[Fields], C],
    default: C,
    warnings: list[ConfigWarning],
) -> C:
    """Load `path`, falling back to `default` with a warning when it does not exist."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        warnings.append(
            ConfigWarning(
                "siem.config.missing", f"no config at {path}, using defaults", path
            )
        )
        return default
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e}") from e

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a JSON object")

    fields = Fields(data, path)
    try:
        config = from_json(fields)
    except ValueError as e:
        raise ConfigError(f"{path}: {e}") from e
    for key in fields.leftover():
        warnings.append(
            ConfigWarning(
                "siem.config.unknown_key", f"{path}: ignoring unknown key {key!r}", path
            )
        )
    return config


def check_port(port: int) -> int:
    if not 0 <= port <= 65535:
        raise ValueError(f"invalid port: {port}")
    return port


@dataclass(frozen=True)
class GeneralConfig:
    stdout: bool = False
    log: bool = True
    api: bool = False
    # Loopback by default: the API exposes users and addresses.
    api_host: str = "127.0.0.1"
    api_port: int = 12125
    api_cors_origins: tuple[str, ...] = (
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    )

    def __post_init__(self) -> None:
        check_port(self.api_port)

    @classmethod
    def from_json(cls, f: Fields) -> "GeneralConfig":
        origins = f.raw("api_cors_origins")
        if origins is None:
            origins = cls.api_cors_origins
        elif isinstance(origins, list) and all(isinstance(o, str) for o in origins):
            origins = tuple(origins)
        else:
            raise ValueError(
                f"'api_cors_origins' must be a list of strings, got {origins!r}"
            )
        return cls(
            stdout=f.get("stdout", bool, cls.stdout),
            log=f.get("log", bool, cls.log),
            api=f.get("api", bool, cls.api),
            api_host=f.get("api_host", str, cls.api_host),
            api_port=f.get("api_port", int, cls.api_port),
            api_cors_origins=origins,
        )
