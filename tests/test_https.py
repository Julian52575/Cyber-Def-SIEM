import ssl

import pytest
from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from my_siem.https.command import HttpsConfig, HttpsState, HttpsWatcher
from my_siem.https.tls import (
    ClientHello,
    HelloAssembler,
    Opening,
    parse_client_hello,
)
from my_siem.telemetry import event_logger, make_provider

CLIENT = ("203.0.113.9", 50122)
SERVER = ("10.0.0.1", 443)
KEY = (*CLIENT, *SERVER)


def real_client_hello(server_name: str | None, alpn: list[str]) -> bytes:
    """A ClientHello as Python's own TLS stack sends it."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.set_alpn_protocols(alpn)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def legacy_client_hello() -> bytes:
    """A minimal TLS 1.0 ClientHello with no extension at all."""
    body = b"\x03\x01" + bytes(32) + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00"
    handshake = b"\x01" + len(body).to_bytes(3) + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2) + handshake


def to_server(flags: str, payload: bytes = b"") -> Packet:
    pkt = IP(src=CLIENT[0], dst=SERVER[0]) / TCP(
        sport=CLIENT[1], dport=SERVER[1], flags=flags
    )
    return pkt / Raw(payload) if payload else pkt


def to_client(flags: str) -> Packet:
    return IP(src=SERVER[0], dst=CLIENT[0]) / TCP(
        sport=SERVER[1], dport=CLIENT[1], flags=flags
    )


def watcher(
    cfg: HttpsConfig | None = None,
) -> tuple[HttpsWatcher, HttpsState, InMemoryLogRecordExporter]:
    exporter = InMemoryLogRecordExporter()
    state = HttpsState({})
    out = event_logger(make_provider([exporter]), "test")
    return HttpsWatcher(out, state, cfg or HttpsConfig()), state, exporter


def test_reads_server_name_version_and_alpn_from_a_real_hello() -> None:
    hello = parse_client_hello(real_client_hello("example.org", ["h2", "http/1.1"]))

    assert hello == ClientHello(0x0304, "example.org", ("h2", "http/1.1"))
    assert hello.version_name == "TLS 1.3"
    assert not hello.legacy


def test_a_hello_without_extensions_is_legacy() -> None:
    hello = parse_client_hello(legacy_client_hello())

    assert hello == ClientHello(0x0301)
    assert hello.legacy


@pytest.mark.parametrize(
    "record", [b"", b"\x16\x03\x01\x00\x05hello", b"\x17\x03\x03\x00\x01x"]
)
def test_other_records_are_no_hello(record: bytes) -> None:
    assert parse_client_hello(record) is None


def test_a_hello_split_across_segments_is_reassembled() -> None:
    record = real_client_hello("example.org", [])
    assembler = HelloAssembler()

    assert assembler.feed(KEY, record[:3]) is None
    assert assembler.feed(KEY, record[3:100]) is None
    seen = assembler.feed(KEY, record[100:])

    assert seen is not None and seen.kind is Opening.HELLO
    assert seen.hello is not None and seen.hello.server_name == "example.org"
    assert assembler.pending == {}
    # Later bytes of the same connection are application data, not a new hello.
    assert assembler.feed(KEY, record) is None


@pytest.mark.parametrize(
    ("payload", "kind"),
    [
        (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Opening.PLAINTEXT_HTTP),
        (b"SSH-2.0-OpenSSH_9.6\r\n", Opening.NOT_TLS),
    ],
)
def test_non_tls_openings_are_told_apart(payload: bytes, kind: Opening) -> None:
    seen = HelloAssembler().feed(KEY, payload)
    assert seen is not None and seen.kind is kind


def test_a_handshake_is_logged_and_counted() -> None:
    w, state, exporter = watcher()

    w.handle(to_server("S"), 100.0)
    w.handle(to_client("SA"), 100.0)
    w.handle(to_server("PA", real_client_hello("example.org", ["h2"])), 100.1)

    [rec] = (r.log_record for r in exporter.get_finished_logs())
    assert rec.event_name == "siem.https.client_hello"
    assert rec.severity_number is SeverityNumber.INFO
    attrs = dict(rec.attributes or {})
    assert attrs["tls.server_name"] == "example.org"
    assert attrs["tls.protocol.version"] == "1.3"
    assert attrs["client.address"] == CLIENT[0]
    snap = state.snapshot()
    assert snap["counts"] == {"conn_opened": 1, "hello": 1}
    assert snap["tls_versions"] == {"TLS 1.3": 1}
    assert len(snap["active_connections"]) == 1

    w.handle(to_client("FA"), 130.0)
    assert state.snapshot()["active_connections"] == []
    assert w.hellos.done == {}


def test_legacy_tls_alerts_once_per_window() -> None:
    w, state, exporter = watcher()

    for port, t in ((1, 0.0), (2, 1.0)):
        pkt = IP(src=CLIENT[0], dst=SERVER[0]) / TCP(sport=port, dport=443, flags="S")
        w.handle(pkt, t)
        w.handle(
            IP(src=CLIENT[0], dst=SERVER[0])
            / TCP(sport=port, dport=443, flags="PA")
            / Raw(legacy_client_hello()),
            t,
        )

    names = [r.log_record.event_name for r in exporter.get_finished_logs()]
    assert names.count("siem.alert.https_legacy_tls") == 1
    assert state.snapshot()["counts"]["legacy_tls"] == 2


def test_connections_already_open_when_sniffing_starts_are_skipped() -> None:
    w, state, exporter = watcher()

    w.handle(to_server("PA", b"\x17\x03\x03\x00\x10" + bytes(16)), 1.0)

    assert list(exporter.get_finished_logs()) == []
    assert state.snapshot()["counts"] == {}


def test_a_connection_flood_raises_an_alert() -> None:
    w, _, exporter = watcher(HttpsConfig(conn_threshold=3))

    for port in range(3):
        w.handle(
            IP(src=CLIENT[0], dst=SERVER[0])
            / TCP(sport=port + 1, dport=443, flags="S"),
            float(port),
        )

    alert = list(exporter.get_finished_logs())[-1].log_record
    assert alert.event_name == "siem.alert.https_conn_flood"
