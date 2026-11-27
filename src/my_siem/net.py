"""TCP connections seen on the wire, tracked from packets with Scapy.

Sees every server reachable through the interface, including ones whose logs
are not on this host (containers, other machines on a mirrored port).
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.sendrecv import sniff

from my_siem.telemetry import ERROR, INFO, EventLogger

_SYN = 0x02
_ACK = 0x10
_FIN = 0x01
_RST = 0x04

type FlowKey = tuple[str, int, str, int]


class ConnKind(StrEnum):
    OPENED = "conn_opened"
    CLOSED = "conn_closed"


@dataclass
class Connection:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    started: float
    packets: int = 0
    bytes: int = 0

    @property
    def key(self) -> FlowKey:
        return (self.client_ip, self.client_port, self.server_ip, self.server_port)


@dataclass(frozen=True)
class ConnEvent:
    kind: ConnKind
    conn: Connection
    at: float
    reset: bool = False

    @property
    def duration(self) -> float:
        return self.at - self.conn.started


class ConnTracker:
    def __init__(self, ports: frozenset[int]) -> None:
        self.ports = ports
        self.flows: dict[FlowKey, Connection] = {}

    def handle(self, pkt: Packet, now: float) -> ConnEvent | None:
        if TCP not in pkt:
            return None
        ip = ip_of(pkt)
        if ip is None:
            return None
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        src: tuple[str, int] = (ip.src, tcp.sport)
        dst: tuple[str, int] = (ip.dst, tcp.dport)

        # Flows are keyed client-first, so look up both directions.
        key: FlowKey = (*src, *dst)
        conn = self.flows.get(key)
        if conn is None:
            key = (*dst, *src)
            conn = self.flows.get(key)

        if conn is None:
            if flags & (_SYN | _ACK) == _SYN and tcp.dport in self.ports:
                conn = Connection(*src, *dst, started=now)
                self.flows[(*src, *dst)] = conn
                self._count(conn, pkt)
                return ConnEvent(ConnKind.OPENED, conn, now)
            return None

        self._count(conn, pkt)
        if flags & (_FIN | _RST):
            del self.flows[key]
            return ConnEvent(ConnKind.CLOSED, conn, now, reset=bool(flags & _RST))
        return None

    def client_flow(self, pkt: Packet) -> FlowKey | None:
        """The key of the tracked connection `pkt` goes from client to server on."""
        ip = ip_of(pkt)
        if TCP not in pkt or ip is None:
            return None
        key: FlowKey = (ip.src, pkt[TCP].sport, ip.dst, pkt[TCP].dport)
        return key if key in self.flows else None

    @staticmethod
    def _count(conn: Connection, pkt: Packet) -> None:
        conn.packets += 1
        conn.bytes += len(pkt)


def bpf_filter(ports: frozenset[int]) -> str:
    return " or ".join(f"tcp port {p}" for p in sorted(ports))


def parse_ports(spec: str) -> frozenset[int]:
    """Parse "22,221-229" into a set of ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        low, _, high = part.partition("-")
        start, end = int(low), int(high or low)
        if not 0 < start <= end <= 65535:
            raise ValueError(f"invalid port range: {part!r}")
        ports.update(range(start, end + 1))
    if not ports:
        raise ValueError("no port given")
    return frozenset(ports)


def ports_from_json(value: Any, default: frozenset[int]) -> frozenset[int]:
    """The `ports` config key: a list of ints or a string like "22,221-229"."""
    if value is None:
        return default
    if isinstance(value, str):
        return parse_ports(value)
    if isinstance(value, list) and all(type(p) is int for p in value):
        return parse_ports(",".join(map(str, value)))
    raise ValueError(
        f"'ports' must be a list of ints or a string like \"22,221-229\", got {value!r}"
    )


def ip_of(pkt: Packet) -> Any:
    return pkt[IP] if IP in pkt else pkt.getlayer(IPv6)


def conn_attributes(c: Connection) -> dict[str, str | int | float | bool]:
    return {
        "client.address": c.client_ip,
        "client.port": c.client_port,
        "server.address": c.server_ip,
        "server.port": c.server_port,
        "network.transport": "tcp",
        "network.type": "ipv6" if ":" in c.client_ip else "ipv4",
    }


class SourceState(Protocol):
    def source(self, name: str, status: str, detail: str) -> None: ...


def run_sniffer(
    out: EventLogger,
    state: SourceState,
    what: str,
    interface: str | None,
    ports: frozenset[int],
    on_packet: Callable[[Packet], None],
) -> None:
    """Sniff `ports` until stopped, reporting the "network" source's status."""
    listed = ",".join(map(str, sorted(ports)))
    state.source("network", "running", f"ports {listed}")
    out.emit(
        INFO,
        "siem.source.started",
        f"sniffing {what} traffic on ports {listed}",
        {
            "siem.source": "network",
            "network.interface.name": interface,
            "siem.ports": sorted(ports),
        },
    )
    try:
        sniff(interface=interface, filter=bpf_filter(ports), prn=on_packet, store=False)
    except (OSError, RuntimeError) as e:
        state.source("network", "failed", str(e))
        out.emit(
            ERROR,
            "siem.source.failed",
            f"cannot sniff (needs root or CAP_NET_RAW): {e}",
            {"siem.source": "network", "error.type": type(e).__name__},
        )
