"""Command-line flags of the `ssh` command, layered over its config file."""

import argparse
from dataclasses import replace
from typing import Any

from my_siem.ssh.monitor import JOURNALD, SshMonitorConfig
from my_siem.ssh.net import parse_ports


def _ports(spec: str) -> frozenset[int]:
    try:
        return parse_ports(spec)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def add_arguments(ssh: argparse.ArgumentParser) -> None:
    # Defaults are None so that only flags actually given override the config.
    ssh.add_argument("--ports", type=_ports, help='SSH ports, e.g. "22,221-229"')
    ssh.add_argument("--iface", help="interface to sniff on (default: all)")
    source = ssh.add_mutually_exclusive_group()
    source.add_argument("--auth-log", help="sshd log file to follow")
    source.add_argument(
        "--journal", action="store_true", help="read sshd logs from journald"
    )
    ssh.add_argument("--no-auth-log", action="store_true", help="do not read sshd logs")
    ssh.add_argument("--no-sniff", action="store_true", help="do not sniff traffic")
    ssh.add_argument(
        "--fail-threshold", type=int, help="failed logins from one IP that alert"
    )
    ssh.add_argument(
        "--conn-threshold", type=int, help="new connections from one IP that alert"
    )
    ssh.add_argument("--window", type=float, help="alert window in seconds")


def apply_flags(cfg: SshMonitorConfig, args: argparse.Namespace) -> SshMonitorConfig:
    names = ("ports", "iface", "auth_log", "fail_threshold", "conn_threshold", "window")
    changes: dict[str, Any] = {
        n: getattr(args, n) for n in names if getattr(args, n) is not None
    }
    if args.journal:
        changes["auth_log"] = JOURNALD
    if args.no_auth_log:
        changes["read_auth_log"] = False
    if args.no_sniff:
        changes["sniff"] = False
    return replace(cfg, **changes)
