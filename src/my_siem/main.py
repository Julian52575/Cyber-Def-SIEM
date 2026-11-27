"""Entry point: parse the general flags and commands, then run the commands side by side."""

import argparse
import queue
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, Protocol

from my_siem.api import ApiServer, create_app
from my_siem.clock import local
from my_siem.config import (
    DEFAULT_ROOT,
    ConfigError,
    ConfigWarning,
    Fields,
    GeneralConfig,
    Layout,
    check_port,
    load_config,
)
from my_siem.dummy import command as dummy
from my_siem.http import command as http
from my_siem.https import command as https
from my_siem.logs import CountKeys, LogManager, Retention, event_keys
from my_siem.ssh import cli as ssh_cli
from my_siem.ssh.monitor import SshMonitorConfig, new_state
from my_siem.ssh.monitor import run as run_ssh
from my_siem.telemetry import INFO, WARN, JsonLinesExporter
from my_siem.version import VERSION


class LiveState(Protocol):
    """What a command is doing right now, served by the API at /<command>."""

    def snapshot(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Command[C, S: LiveState]:
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    from_json: Callable[[Fields], C]
    default: C
    # Command-line flags win over the config file.
    apply_flags: Callable[[C, argparse.Namespace], C]
    new_state: Callable[[C], S]
    run: Callable[[LogManager, C, S], None]
    # What each event adds to the counts the time filters read.
    count_keys: CountKeys = event_keys


COMMANDS: dict[str, Command[Any, Any]] = {
    "ssh": Command(
        help="track SSH connections on this system",
        add_arguments=ssh_cli.add_arguments,
        from_json=SshMonitorConfig.from_json,
        default=SshMonitorConfig(),
        apply_flags=ssh_cli.apply_flags,
        new_state=new_state,
        run=run_ssh,
    ),
    "http": Command(
        help="track HTTP requests and responses on the wire",
        add_arguments=http.add_arguments,
        from_json=http.HttpConfig.from_json,
        default=http.HttpConfig(),
        apply_flags=http.apply_flags,
        new_state=http.new_state,
        run=http.run,
        count_keys=http.count_keys,
    ),
    "https": Command(
        help="track TLS handshakes (server name, version) on the wire",
        add_arguments=https.add_arguments,
        from_json=https.HttpsConfig.from_json,
        default=https.HttpsConfig(),
        apply_flags=https.apply_flags,
        new_state=https.new_state,
        run=https.run,
        count_keys=https.count_keys,
    ),
    "dummy": Command(
        help="generate placeholder data (a template for new commands)",
        add_arguments=dummy.add_arguments,
        from_json=dummy.DummyConfig.from_json,
        default=dummy.DummyConfig(),
        apply_flags=dummy.apply_flags,
        new_state=dummy.new_state,
        run=dummy.run,
        count_keys=dummy.count_keys,
    ),
}


def _port(value: str) -> int:
    try:
        return check_port(int(value))
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def _add_general_flags(parser: argparse.ArgumentParser, with_defaults: bool) -> None:
    """The flags every command accepts, before or after its name.

    Under a command they default to SUPPRESS, so that leaving them out there
    keeps what was given before the command instead of resetting it.
    """

    def default(value: object) -> object:
        return value if with_defaults else argparse.SUPPRESS

    parser.add_argument(
        "--stdout",
        action="store_true",
        default=default(False),
        help="also print events to stdout",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        default=default(False),
        help="do not write events to log files",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=default(DEFAULT_ROOT),
        help=f"root folder of config/ and logs/ (default: {DEFAULT_ROOT})",
    )
    parser.add_argument(
        "--api",
        action="store_true",
        default=default(False),
        help="serve a live dashboard and the monitoring data over HTTP",
    )
    # None so that only a flag actually given overrides the config.
    parser.add_argument(
        "--api-host",
        default=default(None),
        help=f"address the API listens on (default: {GeneralConfig.api_host})",
    )
    parser.add_argument(
        "--api-port",
        type=_port,
        default=default(None),
        help=f"port the API listens on (default: {GeneralConfig.api_port})",
    )


def build_parsers() -> tuple[
    argparse.ArgumentParser, dict[str, argparse.ArgumentParser]
]:
    """The general parser, and one parser per command for the flags after its name."""
    listing = "\n".join(f"  {name:<8}{c.help}" for name, c in COMMANDS.items())
    parser = argparse.ArgumentParser(
        prog="my_siem",
        usage="%(prog)s [general flags] [COMMAND [command flags]]...",
        description="Security Information and Event Management",
        epilog=f"commands:\n{listing}\n\n"
        "With no COMMAND, every command runs. "
        "Run `my_siem COMMAND --help` for a command's own flags.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    _add_general_flags(parser, with_defaults=True)
    commands = {}
    for name, command in COMMANDS.items():
        sub = argparse.ArgumentParser(prog=f"my_siem {name}", description=command.help)
        _add_general_flags(sub, with_defaults=False)
        command.add_arguments(sub)
        commands[name] = sub
    return parser, commands


def _takes_value(parser: argparse.ArgumentParser, token: str) -> bool:
    if not token.startswith("-") or "=" in token:
        return False
    action = parser._option_string_actions.get(token)
    return action is not None and action.nargs != 0


def split_commands(
    argv: list[str],
    parser: argparse.ArgumentParser,
    commands: dict[str, argparse.ArgumentParser],
) -> tuple[list[str], dict[str, list[str]]]:
    """Cut argv at each command name: the general flags, then each command's flags.

    A token right after a flag that takes a value is that value, never a command,
    so `--interface dummy` still names an interface.
    """
    general: list[str] = []
    selected: dict[str, list[str]] = {}
    tokens, current = general, parser
    value_next = False
    for token in argv:
        if value_next:
            value_next = False
        elif token in commands:
            if token in selected:
                parser.error(f"command {token!r} given twice")
            tokens = selected[token] = []
            current = commands[token]
            continue
        elif current is parser and not token.startswith("-"):
            parser.error(
                f"unknown command {token!r} (choose from {', '.join(commands)})"
            )
        else:
            value_next = _takes_value(current, token)
        tokens.append(token)
    return general, selected


def _fail(message: str) -> NoReturn:
    sys.exit(f"my_siem: error: {message}")


@dataclass
class Running:
    """A command set up to run: its config, state, and where its events go."""

    name: str
    command: Command[Any, Any]
    cfg: Any
    state: Any
    warnings: list[ConfigWarning]
    logs: LogManager | None = None


def _announce(logs: LogManager, warnings: list[ConfigWarning]) -> None:
    if logs.log_file is not None:
        verb = "appending to existing log" if logs.resumed else "writing log to"
        logs.out.emit(
            INFO,
            "siem.log.opened",
            f"{verb} {logs.log_file}",
            {"log.file.path": str(logs.log_file), "siem.log.resumed": logs.resumed},
        )
    for w in warnings:
        logs.out.emit(WARN, w.event_name, w.message, {"siem.config.path": str(w.path)})


def _run_all(running: list[Running]) -> None:
    """Run every command in its own thread until all return, one fails, or Ctrl-C."""
    done: queue.Queue[BaseException | None] = queue.Queue()

    def target(r: Running) -> None:
        assert r.logs is not None
        try:
            r.command.run(r.logs, r.cfg, r.state)
            done.put(None)
        except BaseException as e:  # noqa: BLE001 -- re-raised in the main thread
            done.put(e)

    for r in running:
        threading.Thread(
            target=target, args=(r,), name=f"my_siem.{r.name}", daemon=True
        ).start()
    try:
        for _ in running:
            error = done.get()
            if error is not None:
                raise error
    except KeyboardInterrupt:
        pass


def main(argv: list[str] | None = None) -> None:
    parser, command_parsers = build_parsers()
    general_argv, selected_argv = split_commands(
        sys.argv[1:] if argv is None else argv, parser, command_parsers
    )
    args = parser.parse_args(general_argv)
    if not selected_argv:
        selected_argv = {name: [] for name in COMMANDS}
    command_args: dict[str, argparse.Namespace] = {}
    for name, tokens in selected_argv.items():
        ns = command_parsers[name].parse_args(tokens)
        # General flags given after a command apply to the whole run.
        for key, value in vars(ns).items():
            if hasattr(args, key):
                setattr(args, key, value)
        command_args[name] = ns
    layout = Layout(args.path)

    general_warnings: list[ConfigWarning] = []
    running: list[Running] = []
    try:
        general = load_config(
            layout.general_config,
            GeneralConfig.from_json,
            GeneralConfig(),
            general_warnings,
        )
        for name, ns in command_args.items():
            command = COMMANDS[name]
            warnings: list[ConfigWarning] = []
            cfg = load_config(
                layout.command_config(name),
                command.from_json,
                command.default,
                warnings,
            )
            try:
                cfg = command.apply_flags(cfg, ns)
            except ValueError as e:
                command_parsers[name].error(str(e))
            running.append(
                Running(name, command, cfg, command.new_state(cfg), warnings)
            )
    except ConfigError as e:
        _fail(str(e))

    to_stdout = args.stdout or general.stdout
    to_file = general.log and not args.no_log
    if not (to_stdout or to_file):
        parser.error("log files are disabled and --stdout is not set: no output")

    # Also on stderr, once: by default events only go to the log files.
    for w in general_warnings + [w for r in running for w in r.warnings]:
        print(f"my_siem: warning: {w.message}", file=sys.stderr)

    # Shared, and locked inside, so concurrent commands never interleave a line.
    stdout = JsonLinesExporter(sys.stdout) if to_stdout else None
    retention = Retention(general.log_max_age_days, general.log_max_size_mb)
    api = None
    try:
        for r in running:
            try:
                r.logs = LogManager(
                    r.name,
                    layout.log_dir(r.name) if to_file else None,
                    retention,
                    r.command.count_keys,
                    stdout,
                )
            except OSError as e:
                _fail(f"cannot open log file ({e}); try --path or run as root")

        if args.api or general.api:
            host = args.api_host or general.api_host
            port = general.api_port if args.api_port is None else args.api_port
            hosts = [*general.api_allowed_hosts, host]
            app = create_app(
                {r.name: r.state.snapshot for r in running},
                hosts,
                logs={r.name: r.logs for r in running if r.logs is not None},
            )
            try:
                api = ApiServer(app, host, port)
            except OSError as e:
                _fail(f"cannot serve the API on {host}:{port} ({e})")

        for r in running:
            assert r.logs is not None
            _announce(r.logs, general_warnings + r.warnings)
        if api is not None:
            api.start()
            routes = ", ".join(f"{api.url}/{r.name}" for r in running)
            for r in running:
                assert r.logs is not None
                r.logs.out.emit(
                    INFO,
                    "siem.api.started",
                    f"serving the dashboard at {api.url}/ and the data at {routes}",
                    {"url.full": f"{api.url}/"},
                )
        started_at = local(time.time()).isoformat(timespec="seconds")
        for r in running:
            assert r.logs is not None
            r.logs.out.emit(
                INFO,
                "siem.started",
                f"started watching at {started_at}",
                {"siem.started_at": started_at},
            )
        print(f"my_siem: started watching at {started_at}", file=sys.stderr)
        _run_all(running)
    finally:
        if api is not None:
            api.stop()
        stopped_at = local(time.time()).isoformat(timespec="seconds")
        for r in running:
            if r.logs is not None:
                r.logs.out.emit(
                    INFO,
                    "siem.stopped",
                    f"shut down at {stopped_at}",
                    {"siem.stopped_at": stopped_at},
                )
                r.logs.close()
        print(f"my_siem: shut down at {stopped_at}", file=sys.stderr)


if __name__ == "__main__":
    main()
