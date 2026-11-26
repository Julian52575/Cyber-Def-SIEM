import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from my_siem.net import ConnKind, ConnTracker, bpf_filter, parse_ports

CLIENT = ("10.0.0.5", 50122)
SERVER = ("10.0.0.1", 22)


def to_server(flags: str, payload: bytes = b"") -> Packet:
    pkt = IP(src=CLIENT[0], dst=SERVER[0]) / TCP(
        sport=CLIENT[1], dport=SERVER[1], flags=flags
    )
    return pkt / Raw(payload) if payload else pkt


def to_client(flags: str) -> Packet:
    return IP(src=SERVER[0], dst=CLIENT[0]) / TCP(
        sport=SERVER[1], dport=CLIENT[1], flags=flags
    )


def test_tracks_connection_from_syn_to_fin() -> None:
    tracker = ConnTracker(frozenset({22}))

    opened = tracker.handle(to_server("S"), now=100.0)
    assert opened is not None and opened.kind is ConnKind.OPENED
    assert tracker.handle(to_client("SA"), now=100.1) is None
    assert tracker.handle(to_server("PA", b"SSH-2.0-OpenSSH\r\n"), now=101.0) is None

    closed = tracker.handle(to_client("FA"), now=130.0)
    assert closed is not None and closed.kind is ConnKind.CLOSED
    assert closed.duration == pytest.approx(30.0)
    assert closed.conn.packets == 4
    assert not closed.reset
    assert tracker.flows == {}


def test_reset_closes_connection() -> None:
    tracker = ConnTracker(frozenset({22}))
    tracker.handle(to_server("S"), now=0.0)
    closed = tracker.handle(to_client("R"), now=0.1)
    assert closed is not None and closed.reset


def test_ignores_other_ports_and_mid_stream_packets() -> None:
    tracker = ConnTracker(frozenset({2222}))
    assert tracker.handle(to_server("S"), now=0.0) is None
    assert tracker.handle(to_server("PA"), now=0.0) is None
    assert tracker.flows == {}


def test_parse_ports_accepts_lists_and_ranges() -> None:
    assert parse_ports("22, 221-223") == frozenset({22, 221, 222, 223})


@pytest.mark.parametrize("spec", ["", "0", "30-20", "70000", "ssh"])
def test_parse_ports_rejects_bad_specs(spec: str) -> None:
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_bpf_filter_lists_every_port() -> None:
    assert bpf_filter(frozenset({222, 22})) == "tcp port 22 or tcp port 222"
