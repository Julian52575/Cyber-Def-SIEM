"""The admin tab: scheduled jobs, log folder sizes, and the log import."""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from my_siem.clock import HOUR, MINUTE, hour_start, minute_start
from my_siem.live import iso
from my_siem.logs import LogManager, Retention
from my_siem.logs.files import MB, list_logs
from my_siem.logs.importer import Importer


@dataclass(frozen=True)
class Job:
    service: str
    name: str
    schedule: str
    last: float | None
    next: float | None
    state: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "name": self.name,
            "schedule": self.schedule,
            "last": None if self.last is None else iso(self.last),
            "next": None if self.next is None else iso(self.next),
            "state": self.state,
        }


def log_jobs(logs: LogManager, now: float) -> list[Job]:
    """Both run on the first event past their boundary: a quiet command waits for one."""
    service = f"Log manager ({logs.command})"
    jobs = []
    if logs.writer is not None:
        jobs.append(
            Job(
                service,
                "Start the hour's file, gzip closed hours, apply retention",
                "hourly, on the first event of the hour",
                logs.writer.last_sweep,
                hour_start(now) + HOUR,
            )
        )
    if logs.rollup.path is not None:
        jobs.append(
            Job(
                service,
                "Save the counts (rollup.json)",
                "every minute, on the first event of the minute; and on exit",
                logs.rollup.saved_at,
                minute_start(now) + MINUTE,
            )
        )
    return jobs


@dataclass(frozen=True)
class FolderUsage:
    """What one command's log folder holds, from the file sizes alone."""

    name: str
    path: Path
    log_files: int
    plain_bytes: int  # the hours not gzipped yet, the current one included
    gz_bytes: int
    other_bytes: int  # rollup.json, and leftovers such as old <command>.jsonl files
    oldest: int | None  # hour of the oldest file
    newest: int | None
    cap_bytes: int | None

    @property
    def log_bytes(self) -> int:
        return self.plain_bytes + self.gz_bytes

    @property
    def total_bytes(self) -> int:
        return self.log_bytes + self.other_bytes

    @property
    def cap_share(self) -> float | None:
        """Retention caps the log files alone, not rollup.json."""
        return None if not self.cap_bytes else self.log_bytes / self.cap_bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "log_files": self.log_files,
            "plain_bytes": self.plain_bytes,
            "gz_bytes": self.gz_bytes,
            "other_bytes": self.other_bytes,
            "total_bytes": self.total_bytes,
            "oldest": None if self.oldest is None else iso(self.oldest),
            "newest": None if self.newest is None else iso(self.newest),
            "cap_bytes": self.cap_bytes,
        }


def scan_folder(folder: Path, cap_bytes: int | None) -> FolderUsage:
    logs = list_logs(folder, folder.name)
    names = {f.path.name for f in logs}
    plain = gz = other = 0
    with os.scandir(folder) as entries:
        for e in entries:
            try:
                if not e.is_file(follow_symlinks=False):
                    continue
                size = e.stat(follow_symlinks=False).st_size
            except FileNotFoundError:
                continue  # swept while listing
            if e.name not in names:
                other += size
            elif e.name.endswith(".gz"):
                gz += size
            else:
                plain += size
    return FolderUsage(
        folder.name,
        folder,
        len(logs),
        plain,
        gz,
        other,
        logs[0].hour if logs else None,
        logs[-1].hour if logs else None,
        cap_bytes,
    )


def scan_logs(root: Path, retention: Retention | None) -> list[FolderUsage]:
    """Every folder under logs/, running command or not, by name."""
    cap = retention.max_size_mb * MB if retention else None
    try:
        folders = sorted(p for p in root.iterdir() if p.is_dir())
    except FileNotFoundError:
        return []
    return [scan_folder(f, cap) for f in folders]


class AdminPanel:
    def __init__(
        self,
        logs: Mapping[str, LogManager],
        importer: Importer,
        log_root: Path | None,
        retention: Retention | None,
    ) -> None:
        """`log_root` is None with `--no-log`: nothing to scan or import into."""
        self.logs = dict(logs)
        self.importer = importer
        self.log_root = log_root
        self.retention = retention

    def jobs(self, now: float) -> list[Job]:
        jobs = [j for logs in self.logs.values() for j in log_jobs(logs, now)]
        job = self.importer.job
        if job is not None:
            jobs.append(
                Job(
                    "Admin",
                    "Log import",
                    "on demand, from this tab",
                    job.started_at,
                    None,
                    job.state,
                )
            )
        return jobs

    def usage(self) -> list[FolderUsage]:
        return [] if self.log_root is None else scan_logs(self.log_root, self.retention)
