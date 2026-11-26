"""SSH connections seen on the wire, tracked from TCP packets with Scapy.

Sees every SSH daemon reachable through the interface, including ones whose
logs are not on this host (containers, other machines on a mirrored port).
"""

from dataclasses import dataclass
from enum import StrEnum

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

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


@dataclass(frozen=True)
class ConnEvent:
    kind: ConnKind
    conn: Connection
    at: float
    reset: bool = False

    @property
    def duration(self) -> float:
        return self.at - self.conn.started


class SshConnTracker:
    def __init__(self, ports: frozenset[int]) -> None:
        self.ports = ports
        self.flows: dict[FlowKey, Connection] = {}

    def handle(self, pkt: Packet, now: float) -> ConnEvent | None:
        if TCP not in pkt:
            return None
        ip = pkt[IP] if IP in pkt else pkt.getlayer(IPv6)
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
