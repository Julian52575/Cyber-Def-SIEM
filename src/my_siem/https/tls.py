"""TLS ClientHellos read from TCP payloads: server name, version and ALPN offered.

Only the handshake's first record is read. A ClientHello can span several TCP
segments (post-quantum key shares make it ~1.8 KB), so `HelloAssembler` buffers
a connection's first bytes until the record is complete.
"""

import struct
from dataclasses import dataclass
from enum import StrEnum

from my_siem.http.wire import parse_request
from my_siem.net import FlowKey

_HANDSHAKE = 0x16
_CLIENT_HELLO = 0x01
_EXT_SNI = 0x0000
_EXT_ALPN = 0x0010
_EXT_VERSIONS = 0x002B
# A TLS record's payload never exceeds 2^14 bytes, plus its 5-byte header.
MAX_RECORD = 5 + (1 << 14)
# Pending handshakes kept at once; the oldest is dropped past this.
MAX_PENDING = 4096

VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}
MODERN = 0x0303


@dataclass(frozen=True)
class ClientHello:
    version: int
    server_name: str | None = None
    alpn: tuple[str, ...] = ()

    @property
    def version_name(self) -> str:
        return VERSIONS.get(self.version, f"0x{self.version:04x}")

    @property
    def legacy(self) -> bool:
        return self.version < MODERN


def _is_grease(v: int) -> bool:
    # RFC 8701: 0x0a0a, 0x1a1a, ... are placeholders clients send to keep servers honest.
    return v & 0x0F0F == 0x0A0A and v >> 8 == v & 0xFF


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int(struct.unpack("!H", self.take(2))[0])

    def u24(self) -> int:
        return int.from_bytes(self.take(3))

    def vec(self, length_size: int) -> "_Reader":
        n = self.u8() if length_size == 1 else self.u16()
        return _Reader(self.take(n))

    def done(self) -> bool:
        return self.pos >= len(self.data)


def parse_client_hello(record: bytes) -> ClientHello | None:
    """The ClientHello in a complete TLS record, or None if it holds none."""
    try:
        r = _Reader(record)
        if r.u8() != _HANDSHAKE:
            return None
        r.take(2)  # record version, fixed by clients for compatibility
        r = r.vec(2)
        if r.u8() != _CLIENT_HELLO:
            return None
        r.u24()
        version = r.u16()
        r.take(32)  # random
        r.vec(1)  # session id
        r.vec(2)  # cipher suites
        r.vec(1)  # compression methods
        server_name: str | None = None
        alpn: tuple[str, ...] = ()
        exts = r.vec(2) if not r.done() else _Reader(b"")
        while not exts.done():
            kind, body = exts.u16(), exts.vec(2)
            if kind == _EXT_SNI:
                names = body.vec(2)
                while not names.done():
                    name_type, name = names.u8(), names.vec(2)
                    if name_type == 0:
                        server_name = name.data.decode("ascii", "replace")[:255]
            elif kind == _EXT_ALPN:
                protos = body.vec(2)
                found = []
                while not protos.done():
                    found.append(protos.vec(1).data.decode("ascii", "replace")[:32])
                alpn = tuple(found)
            elif kind == _EXT_VERSIONS:
                offered = body.vec(1)
                versions = []
                while not offered.done():
                    v = offered.u16()
                    if not _is_grease(v):
                        versions.append(v)
                if versions:
                    version = max(versions)
        return ClientHello(version, server_name, alpn)
    except ValueError:
        return None


class Opening(StrEnum):
    HELLO = "hello"
    NOT_TLS = "not_tls"
    PLAINTEXT_HTTP = "plaintext_http"


@dataclass(frozen=True)
class Handshake:
    kind: Opening
    hello: ClientHello | None = None


class HelloAssembler:
    """Collect each connection's first client bytes until they show what it speaks."""

    def __init__(self) -> None:
        self.pending: dict[FlowKey, bytearray] = {}
        # Ordered, so the oldest goes first when full.
        self.done: dict[FlowKey, None] = {}

    def feed(self, key: FlowKey, payload: bytes) -> Handshake | None:
        if key in self.done:
            return None
        buf = self.pending.pop(key, bytearray()) + payload
        result = self._read(bytes(buf))
        if result is None:
            if len(self.pending) >= MAX_PENDING:
                del self.pending[next(iter(self.pending))]
            self.pending[key] = buf
        else:
            if len(self.done) >= MAX_PENDING:
                del self.done[next(iter(self.done))]
            self.done[key] = None
        return result

    def forget(self, key: FlowKey) -> None:
        self.pending.pop(key, None)
        self.done.pop(key, None)

    @staticmethod
    def _read(buf: bytes) -> Handshake | None:
        if buf[0] != _HANDSHAKE:
            if parse_request(buf) is not None:
                return Handshake(Opening.PLAINTEXT_HTTP)
            return Handshake(Opening.NOT_TLS)
        if len(buf) < 5:
            return None
        end = 5 + int.from_bytes(buf[3:5])
        if end > MAX_RECORD:
            return Handshake(Opening.NOT_TLS)
        if len(buf) < end:
            return None
        hello = parse_client_hello(buf[:end])
        return Handshake(Opening.NOT_TLS if hello is None else Opening.HELLO, hello)
