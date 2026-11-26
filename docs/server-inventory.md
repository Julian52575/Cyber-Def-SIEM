# Server inventory

Every server on our infrastructure. Add a row when a server joins the network.

Domain: `hopital.lan`

Open ports come from scans run from the bastion. "Full scan" means all 65535 TCP ports (`nmap -p- -sV`). Otherwise only ports 1–1024 were scanned (`nc -zv -w1 <ip> 1-1024`), and services listening higher do not show up.

## Servers

| IP address | Hostname | Purpose | Open TCP ports |
| ---------- | -------- | ------- | ----------------------- |
| `192.168.1.3` | ? (no reverse DNS) | Unknown Linux host, Ubuntu 22.04. Candidate for a workstation | 22 (OpenSSH 8.9p1) only — full scan |
| `192.168.1.12` | ? (service key `printer`) | Printer: "HP Printer Web Interface" (Flask app, lets users upload PDFs) | Full scan: 22 (OpenSSH 9.7), 5000 (http, Werkzeug 3.0.6 / Python 3.8.20) |
| `192.168.1.30` | `storage` | Samba storage (file shares) | Full scan: 139, 445 (Samba; nmap says 4.6.2, to verify on the host with `smbd --version`) |
| `192.168.1.45` | ? (service key `ekg`) | EKG-75 monitor: "EKG75 Device - Simplon 20k" | Full scan: 5020 (custom device protocol, STX/ETX framing, `ERR\|Invalid protocol format`), 10001 (http, Werkzeug 1.0.1 / Python 3.8.20) |
| `192.168.1.60` | `labresults` (`results.hopital.lan`) | Patient results portal: "MandeLab" web app (Flask, cookie sessions) | Full scan: 80 (http, Werkzeug 3.1.9 / Python 3.11.18) |
| `192.168.1.71` | `orthanc` | Orthanc DICOM: PACS, medical imaging server | Full scan: 4242 (DICOM), 8042 (Orthanc HTTP/REST API, HTTP Basic auth "Orthanc Secure Area") |
| `192.168.1.78` | `runner` | Python runner: "Python Task Manager" web app, runs arbitrary Python code submitted by users | 22 (ssh), 8000 (http, Python Task Manager) — scanned up to port 50000 |
| `192.168.1.100` / `10.10.10.11` | `bastion` | Bastion / IDS (our entry point). Runs in a Docker container (Docker DNS on `127.0.0.11`). nginx proxies traffic to the internal services | From `ss -tlnp`: 22 (sshd), 25 (nginx, SMTP proxy), 80 (nginx, HTTP), 6379 (nginx, Redis proxy), 7681 (web terminal, likely ttyd, owning process not visible), 8080 (python3, "SIEM - Hopital Mande" page?) |
| `192.168.1.102` | `ehr` | **Removed from the infrastructure, ignore** (confirmed by the organizers, 2026-11-26). Was MedShake EHR: patient records (PHP web app) | None: no reply to ARP, hence the 502 on `ehr.hopitalmande.fr`. Its `/etc/hosts` entry and nginx vhost are leftovers |
| `192.168.1.106` | `redis` | Redis: cache / key-value store | Full scan: 6379 (Redis 5.0.14) |
| `192.168.1.111` | `mail` | Mail server (custom Python services) | Full scan: 25 (Python SMTP, aiosmtpd 1.4.6), 80 (http, Python BaseHTTPServer / Python 3.14.10), 110 ("Simple POP3 server") |
| `192.168.1.122` | ? (no reverse DNS) | Unknown Linux host, Ubuntu 22.04 (different SSH host key from `.3`, so a different machine). Candidate for a workstation | 22 (OpenSSH 8.9p1) only — full scan |
| `10.10.10.18` | ? | Provided by the module organizers, out of our scope: "SIEM - Hopital Mande" status page showing the uptime of some of our machines, plus access to some service interfaces. Exposes exactly the same ports as our bastion: may be another team's bastion, to confirm | Full scan: 22 (OpenSSH 9.6p1, Ubuntu 24.04), 25 (Python SMTP, aiosmtpd 1.4.6), 80 (nginx 1.24.0), 6379 (Redis 5.0.14), 7681 (web terminal, likely ttyd), 8080 (Python SimpleHTTP, "SIEM - Hopital Mande") |

## Exposure through the bastion (nginx)

The bastion's nginx (`sudo nginx -T`) publishes the internal services on the `hopitalmande.fr` domain. Internal servers see every proxied request as coming from the bastion: the real client IP is only in the bastion's nginx logs.

### HTTP, port 80 (routed by `Host` header)

| Public name | Target | Notes |
| ----------- | ------ | ----- |
| `mail.hopitalmande.fr` | `mail.hopital.lan:80` | |
| `ehr.hopitalmande.fr` | `ehr.hopital.lan:80` | `ehr` was removed from the infrastructure: returns 502 |
| `runner.hopitalmande.fr` | `runner.hopital.lan:8000` | Python runner: arbitrary code execution reachable from outside |
| `storage.hopitalmande.fr`, `storage.hopital.lan` | Served by the bastion itself from `/var/www/html` | Not proxied: does not reach the Samba server |
| `orthanc.hopitalmande.fr` | `orthanc.hopital.lan:8042` | Orthanc web UI / REST API, HTTP Basic auth, sent in clear text (no HTTPS) |
| `results.hopitalmande.fr` | `results.hopital.lan:80` | Patient results portal |
| Any other name (default server) | Served by the bastion itself from `/var/www/html` | |

### TCP (nginx `stream`)

| Bastion port | Target | Notes |
| ------------ | ------ | ----- |
| 6379 | `redis.hopital.lan:6379` | Redis exposed from outside, no stream access log |
| 25 | `mail.hopital.lan:25` | SMTP, no stream access log |

Not exposed through the bastion: POP3 (110), Orthanc DICOM (4242), Samba (139/445), the printer, the EKG and the workstations.

No HTTPS anywhere: all traffic, credentials included, travels in clear text.

## Services monitored by the organizers

The organizers' status page (`10.10.10.18`, also available through the uptime API) tracks the uptime of these 7 services only, for our team (team 1). They must stay up: check any hardening change against this page.

The checker runs about every 30 seconds. The check type comes from the `last_code` field of the API:

| Service key | Label | Check type |
| ----------- | ----- | ---------- |
| `bastion` | Bastion / IDS | HTTP request, expects 200 |
| `labresults` | Patient results portal | HTTP request, expects 200 |
| `mail` | Mail server | TCP port open |
| `orthanc` | Orthanc DICOM | HTTP request, expects 200 |
| `redis` | Redis | Redis `PING`, expects `PONG` |
| `runner` | Python runner | HTTP request, expects 200 |
| `storage` | Samba storage | HTTP request, expects 200. Probably `storage.hopitalmande.fr`, which the bastion serves itself: the check does not test Samba |

Not monitored: `ehr`, `ehr_db`, `ekg`, the workstations and the printer. The organizers confirmed that `ehr` was removed from the infrastructure.

## Services not yet located

Listed in the exercise's service list, but not matched to an IP yet. The unknown hosts above (`192.168.1.3`, `192.168.1.122`) are candidates.

| Service key | Label | Notes |
| ----------- | ----- | ----- |
| `ehr_db` | EHR database | MedShake EHR uses MySQL/MariaDB: expect 3306. Probably removed along with `ehr` (no host exposes 3306), to confirm with the organizers. |
| `workstation` | Workstation WL-1045 | |
| `workstation3` | Workstation WL-1012 | The key suggests a `workstation2` that is not visible to us. |

## Gateways

| IP address | Role | Open TCP ports (1–1024) |
| ---------- | ---- | ----------------------- |
| `192.168.1.1` | LAN router/firewall | 22 (ssh), 25 (smtp), 80 (http), 221–229, 801–809 |
| `10.10.10.1` | Bastion gateway | 22 (ssh), 25 (smtp), 80 (http), 221–229, 801–809 |

Both gateways expose exactly the same ports, so they are probably the same device.

The 801–809 and 221–229 ranges are probably per-team forwards to each team's bastion: 80X to HTTP (port 80) and 22X to SSH (port 22) of team X. We are team 1: `http://<name>.hopitalmande.fr:801/` reaches our bastion's nginx (for example `storage.hopitalmande.fr:801` returns our empty `/var/www/html` page and `ehr.hopitalmande.fr:801` returns 502 because `ehr` is down). Port 221 for our SSH is not confirmed yet.
