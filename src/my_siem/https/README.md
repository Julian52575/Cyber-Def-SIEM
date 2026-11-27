# `https`: what it reads and how

The traffic is encrypted, so `https` reads only the one part sent in the clear: the TLS
ClientHello that opens each connection. Flags and config keys are in the
[main README](../../../README.md#tracking-https-traffic).

## How packets are captured

`run_sniffer` (`../net.py`) runs Scapy's `sniff` on `interface` (all interfaces when
`null`) with a kernel BPF filter such as `tcp port 443 or tcp port 8443`, so only packets
for the HTTPS ports reach Python. Packets are handled one by one and not kept. Capturing
needs root or `CAP_NET_RAW`.

## What is read from each packet

`HttpsWatcher.handle` (`command.py`):

1. `ConnTracker` reads the TCP headers. A SYN to a watched port opens a connection, and
   FIN or RST closes it. Only connections whose SYN was seen are read further, so those
   already open when my_siem starts are skipped.
2. Each payload the client sends on an open connection goes to `HelloAssembler`
   (`tls.py`), until the connection's opening is known. Later bytes and the server's
   replies are ignored.

### Putting the ClientHello together

A ClientHello can span several TCP segments: post-quantum key shares make it about
1.8 KB. `HelloAssembler` buffers each connection's first client bytes until it can
decide:

| First bytes                                | Result           | Logged as                     |
| ------------------------------------------ | ---------------- | ----------------------------- |
| a complete TLS record holding a ClientHello | `hello`          | `siem.https.client_hello`     |
| an HTTP request line                       | `plaintext_http` | `siem.https.plaintext_http` (`WARN`) |
| anything else, or a malformed record       | `not_tls`        | `siem.https.not_tls` (`WARN`) |

A TLS record is a 5-byte header (type `0x16` for a handshake, version, length) and then
up to 16 KB. The assembler waits for the whole record before parsing. At most 4096
handshakes are buffered at once, and the oldest is dropped past that.

### What is read from the ClientHello

`parse_client_hello` walks the record and skips the random, session ID, cipher suites
and compression methods. From the extensions it keeps:

| Extension                     | Kept as                                            |
| ----------------------------- | -------------------------------------------------- |
| `server_name` (SNI)           | the host name asked for, up to 255 characters      |
| `application_layer_protocol_negotiation` | the protocols offered, such as `h2` and `http/1.1` |
| `supported_versions`          | the highest version offered, GREASE values skipped |

Without `supported_versions` (clients older than TLS 1.3), the ClientHello's own
version field is used. The certificate, the server's reply and all application data stay
unread.

## Detection

- `https_legacy_tls`: a client offering nothing newer than TLS 1.1, at most once per IP
  per `window`. Old clients and scanners do this.
- `https_conn_flood`: `conn_threshold` new connections from one IP within `window`
  seconds.

A missing SNI is counted on the dashboard but raises no alert, because clients that
connect by IP address leave it out.
