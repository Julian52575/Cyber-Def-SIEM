import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, Protocol

from my_siem.api import ApiServer, create_app
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
from my_siem.ssh import cli as ssh_cli
from my_siem.ssh.monitor import SshMonitorConfig, new_state
from my_siem.ssh.monitor import run as run_ssh
from my_siem.telemetry import (
    INFO,
    WARN,
    EventLogger,
    JsonLinesExporter,
    event_logger,
    make_provider,
)


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
    run: Callable[[EventLogger, C, S], None]


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
        help="serve live monitoring data over HTTP",
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="my_siem", description="Security Information and Event Management"
    )
    _add_general_flags(parser, with_defaults=True)
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for name, command in COMMANDS.items():
        cmd_parser = sub.add_parser(name, help=command.help)
        _add_general_flags(cmd_parser, with_defaults=False)
        command.add_arguments(cmd_parser)
    return parser


def _fail(message: str) -> NoReturn:
    sys.exit(f"my_siem: error: {message}")


def _announce(
    out: EventLogger,
    log_file: Path | None,
    resumed: bool,
    warnings: list[ConfigWarning],
) -> None:
    if log_file is not None:
        verb = "appending to existing log" if resumed else "writing log to"
        out.emit(
            INFO,
            "siem.log.opened",
            f"{verb} {log_file}",
            {"log.file.path": str(log_file), "siem.log.resumed": resumed},
        )
    for w in warnings:
        # Also on stderr: by default events only go to the log file.
        print(f"my_siem: warning: {w.message}", file=sys.stderr)
        out.emit(WARN, w.event_name, w.message, {"siem.config.path": str(w.path)})


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = COMMANDS[args.command]
    layout = Layout(args.path)

    warnings: list[ConfigWarning] = []
    try:
        general = load_config(
            layout.general_config, GeneralConfig.from_json, GeneralConfig(), warnings
        )
        cfg = load_config(
            layout.command_config(args.command),
            command.from_json,
            command.default,
            warnings,
        )
    except ConfigError as e:
        _fail(str(e))
    try:
        cfg = command.apply_flags(cfg, args)
    except ValueError as e:
        parser.error(str(e))

    to_stdout = args.stdout or general.stdout
    to_file = general.log and not args.no_log
    if not (to_stdout or to_file):
        parser.error("log files are disabled and --stdout is not set: no output")

    exporters = []
    log_file, resumed = None, False
    if to_file:
        log_file = layout.log_file(args.command)
        try:
            exporter, resumed = JsonLinesExporter.append_to(log_file)
        except OSError as e:
            _fail(f"cannot open log file ({e}); try --path or run as root")
        exporters.append(exporter)
    if to_stdout:
        exporters.append(JsonLinesExporter(sys.stdout))

    state = command.new_state(cfg)
    api = None
    if args.api or general.api:
        host = args.api_host or general.api_host
        port = general.api_port if args.api_port is None else args.api_port
        app = create_app(args.command, state.snapshot, general.api_cors_origins)
        try:
            api = ApiServer(app, host, port)
        except OSError as e:
            _fail(f"cannot serve the API on {host}:{port} ({e})")

    provider = make_provider(exporters)
    try:
        out = event_logger(provider, f"my_siem.{args.command}")
        _announce(out, log_file, resumed, warnings)
        if api is not None:
            api.start()
            out.emit(
                INFO,
                "siem.api.started",
                f"serving the API at {api.url}/{args.command}",
                {"url.full": f"{api.url}/{args.command}"},
            )
        command.run(out, cfg, state)
    finally:
        if api is not None:
            api.stop()
        provider.shutdown()


if __name__ == "__main__":
    main()
