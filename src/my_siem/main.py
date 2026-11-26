import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from my_siem.config import (
    DEFAULT_ROOT,
    ConfigError,
    ConfigWarning,
    Fields,
    GeneralConfig,
    Layout,
    load_config,
)
from my_siem.ssh import cli as ssh_cli
from my_siem.ssh.monitor import SshMonitorConfig
from my_siem.ssh.monitor import run as run_ssh
from my_siem.telemetry import (
    INFO,
    WARN,
    EventLogger,
    JsonLinesExporter,
    event_logger,
    make_provider,
)


@dataclass(frozen=True)
class Command[C]:
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    from_json: Callable[[Fields], C]
    default: C
    # Command-line flags win over the config file.
    apply_flags: Callable[[C, argparse.Namespace], C]
    run: Callable[[EventLogger, C], None]


COMMANDS: dict[str, Command[Any]] = {
    "ssh": Command(
        help="track SSH connections on this system",
        add_arguments=ssh_cli.add_arguments,
        from_json=SshMonitorConfig.from_json,
        default=SshMonitorConfig(),
        apply_flags=ssh_cli.apply_flags,
        run=run_ssh,
    ),
}


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

    provider = make_provider(exporters)
    try:
        out = event_logger(provider, f"my_siem.{args.command}")
        _announce(out, log_file, resumed, warnings)
        command.run(out, cfg)
    finally:
        provider.shutdown()


if __name__ == "__main__":
    main()
