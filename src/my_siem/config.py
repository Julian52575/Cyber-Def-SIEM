"""On-disk layout (config/ and logs/ under one root) and JSON config loading."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

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


class Defaults(Protocol):
    def to_json(self) -> dict[str, Any]: ...


def write_default_config(path: Path, default: Defaults) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # "x": never clobber a file created between the read and this write.
    with path.open("x", encoding="utf-8") as out:
        json.dump(default.to_json(), out, indent=2)
        out.write("\n")


def load_config[C: Defaults](
    path: Path,
    from_json: Callable[[Fields], C],
    default: C,
    warnings: list[ConfigWarning],
) -> C:
    """Load `path`; when it does not exist, write `default` there and use it."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        try:
            write_default_config(path, default)
        except OSError as e:
            # Still runnable (e.g. no write access to /etc): defaults, not a crash.
            message = f"no config at {path} and cannot create it ({e}), using defaults"
            warnings.append(ConfigWarning("siem.config.missing", message, path))
        else:
            message = f"no config at {path}, created it with the defaults"
            warnings.append(ConfigWarning("siem.config.created", message, path))
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
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    # Names the browser may use to reach the API; `api_host` is always allowed too.
    api_allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")

    def __post_init__(self) -> None:
        check_port(self.api_port)

    @classmethod
    def from_json(cls, f: Fields) -> "GeneralConfig":
        hosts = f.raw("api_allowed_hosts")
        if hosts is None:
            hosts = cls.api_allowed_hosts
        elif isinstance(hosts, list) and all(isinstance(h, str) for h in hosts):
            hosts = tuple(hosts)
        else:
            raise ValueError(
                f"'api_allowed_hosts' must be a list of strings, got {hosts!r}"
            )
        return cls(
            stdout=f.get("stdout", bool, cls.stdout),
            log=f.get("log", bool, cls.log),
            api=f.get("api", bool, cls.api),
            api_host=f.get("api_host", str, cls.api_host),
            api_port=f.get("api_port", int, cls.api_port),
            api_allowed_hosts=hosts,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "stdout": self.stdout,
            "log": self.log,
            "api": self.api,
            "api_host": self.api_host,
            "api_port": self.api_port,
            "api_allowed_hosts": list(self.api_allowed_hosts),
        }
