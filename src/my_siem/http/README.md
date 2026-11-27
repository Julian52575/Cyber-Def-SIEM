# `http`: what it reads and how

`http` reads plaintext HTTP/1.x off the wire. It needs no access to the web server or
its logs. Flags and config keys are in the
[main README](../../../README.md#tracking-http-traffic).

## How packets are captured

`run_sniffer` (`../net.py`) runs Scapy's `sniff` on `interface` (all interfaces when
`null`) with a kernel BPF filter such as `tcp port 80 or tcp port 8080`, so only packets
for the HTTP ports reach Python. Packets are handled one by one and not kept. Capturing
needs root or `CAP_NET_RAW`.

## What is read from each packet

`HttpWatcher.handle` (`command.py`) looks at each TCP packet that carries a payload:

| Direction                 | Read as  | Parser                     |
| ------------------------- | -------- | -------------------------- |
| to a watched port         | request  | `parse_request` (`wire.py`) |
| from a watched port       | response | `parse_response` (`wire.py`) |

The payload is then passed to `ConnTracker`, which counts connections and their packets
and bytes from the TCP headers (SYN opens, FIN or RST closes), as in `ssh`.

### Requests

`parse_request` reads only the start of the payload:

- **Request line**: `<METHOD> <target> HTTP/<version>`. The method is 2 to 16 uppercase
  letters, so any method is accepted, not only `GET` or `POST`. A payload that doesn't
  start with a request line is skipped, which covers the body segments that follow.
- **Headers**: up to the blank line, only `Host` and `User-Agent` are kept. Names are
  matched case-insensitively, and only the first occurrence counts.

The target, `Host` and `User-Agent` are cut to 512 characters before logging, because
they are attacker-controlled. Each request is logged as `siem.http.request`, with the
path and query split apart.

### Responses

`parse_response` reads the status line `HTTP/<version> <code>` and keeps only the code.
Each response is logged as `siem.http.response`, at `WARN` for 4xx and 5xx.

## Detection

`match_rules` (`wire.py`) checks each request:

- The **target**, lowercased, both as sent and URL-decoded (`unquote_plus`), so
  `%2e%2e%2f` is caught as well as `../`. It is checked against `TARGET_RULES`:
  `path_traversal`, `sql_injection`, `xss`, `command_injection`, `log4shell`,
  `sensitive_file` and `admin_probe`.
- The **User-Agent**, against `SCANNER_AGENT` (sqlmap, nikto, Nmap, gobuster, …) and
  against the Log4Shell pattern, which is often sent in headers.

A request that matches any rule is logged at `WARN` and raises
`http_suspicious_request`. Rates are counted per client IP over `window` seconds:
`request_threshold` requests raise `http_request_flood`, and `error_threshold` 4xx
responses raise `http_error_scan`.

## Importing past requests (admin tab)

The admin tab's log importer can read the web server's access log instead of the wire
(`access_log.py`): nginx's and Apache's "combined" format, or "common", from `access_log`
(`"auto"`: `/var/log/nginx/access.log`, else `/var/log/apache2/access.log`, else
`/var/log/httpd/access_log`) and its rotated copies. Each line becomes a request and its
response, through `HttpWatcher`, so the same rules and alerts apply. The log has the
client's address but not its port, nor the server's address and port: those attributes
are left out. The `Host` header is not in these formats either.

The sniffer and the access log see the same requests, but not alike (ports, timing), so
they cannot be matched one by one: an hour in which `http` already logged live requests
is skipped whole.

## What it can't see

- Anything inside TLS: use `https`, or the web server's own logs.
- HTTP/2 and HTTP/3: they are binary, and are almost always encrypted anyway.
- A request line or header split across TCP segments. Only the first segment is parsed,
  and requests almost always fit in one.
- Request bodies: a POST body is never inspected.
