# `ssh`: what it reads and how

`ssh` reads two sources side by side, each in its own thread. Either can be turned off
(`read_auth_log`, `sniff_traffic`), but not both. Flags and config keys are in the
[main README](../../../README.md#tracking-ssh-connections).

| Source      | Reads                              | Sees                                                |
| ----------- | ---------------------------------- | --------------------------------------------------- |
| `sshd_log`  | sshd's log lines                   | Who logged in or failed to, with which method       |
| `network`   | TCP packets to and from the SSH ports | Every connection, even from sshd running elsewhere |

## sshd logs (`log.py`)

### Where the lines come from

`auth_log` picks the source (`resolve_auth_log` in `monitor.py`):

| `auth_log`   | Read from |
| ------------ | --------- |
| `"auto"`     | `/var/log/auth.log` if it exists, else journald |
| `"journald"` | journald (also `--journal`) |
| a file path  | that file (also `--auth-log PATH`) |

Both are read from a point in time, then followed (`file_events`, `journal_events`):

- **The point** is where the last run stopped: the time of the last sshd event it read,
  saved in `logs/ssh/rollup.json` with the counts (`mark`, in `monitor.py`). A first run
  goes back 100 days, as far as the time filters reach. So history is filled in on the
  first run, and the gap of any restart afterwards. The point and the counts are saved
  together, so a crash makes both go back to the same moment and no event is counted twice.
- **A file** is read from its rotated copies first, oldest first (`auth.log.4.gz` ...
  `auth.log.1`, skipping copies last written before the point), then from the start of
  the live file, then followed like `tail -F` (`follow_file`): new lines every 0.5 s,
  and when the file's inode changes (logrotate), the new file is opened from the start.
- **journald** is read by running
  `journalctl --follow --since=@<point> --output=json _COMM=sshd _COMM=sshd-session`.
  JSON gives each entry's time to the microsecond and its PID, so only the message goes
  through the parser.

Every event keeps the time sshd logged it, not the time it was read: an old line lands
in its own minute, hour and day, and alerts it triggers (`ssh_bruteforce`) are timed and
windowed by the events' times too. A file line's time is its syslog stamp: ISO 8601 with
its offset (rsyslog's default since Debian 12 and Ubuntu 23.10), or the traditional
`Nov 26 14:50:00`, read in the host's time zone and the year that keeps it in the past.

Reading either needs read access to the log: root, or the `adm` group for auth.log and
`systemd-journal` for journald. If the source can't be read, the `sshd_log` source is
marked `failed` and the sniffer keeps running.

### What is read from each line

`parse_line` first finds the syslog header `sshd[<pid>]: ` or `sshd-session[<pid>]: `
(OpenSSH 9.8 and later logs as `sshd-session`), then matches the message against four
patterns. Any other line is skipped.

| Message (after the header)                                 | Event           |
| ---------------------------------------------------------- | --------------- |
| `Accepted <method> for <user> from <ip> port <port>`        | `login_success` |
| `Failed <method> for [invalid user ]<user> from <ip> port <port>` | `login_failure` |
| `Invalid user <user> from <ip> port <port>`                 | `invalid_user`  |
| `Disconnected from user <user> <ip> port <port>`            | `logout`        |

Each event keeps the user, client IP and port, sshd's PID and, for logins, the method
(`password`, `publickey`, …). It is logged as `siem.ssh.<event>`, at `WARN` for
`login_failure` and `invalid_user`.

`login_failure` and `invalid_user` both count towards `ssh_bruteforce`:
`fail_threshold` of them from one IP within `window` seconds raises the alert.

## Network (`../net.py`)

### How packets are captured

`run_sniffer` runs Scapy's `sniff` on `interface` (all interfaces when `null`) with a
kernel BPF filter such as `tcp port 22 or tcp port 2222`, so only packets for the SSH
ports reach Python. Packets are handled one by one and not kept. Capturing needs root or
`CAP_NET_RAW`; without it the `network` source is marked `failed` and the log reader
keeps running.

### What is read from each packet

Only the IP and TCP headers. The payload is encrypted and never read. `ConnTracker`
follows each connection:

1. A SYN without ACK to a watched port opens a connection. The sender is the client.
   The open is logged as `siem.ssh.connection.opened`.
2. Every later packet in either direction counts towards the connection's packets and
   bytes.
3. A FIN or RST closes it. The close is logged as `siem.ssh.connection.closed`, with its
   duration, packet and byte counts and whether it was reset.

Connections already open when my_siem starts are skipped, because their SYN was never
seen.

`conn_threshold` new connections from one IP within `window` seconds raises
`ssh_conn_flood`.

The network side catches what the logs miss: sshd in a container or on another machine
whose traffic crosses this interface, and scans that close the connection before sshd
logs anything.

## Importing past logs (admin tab)

The admin tab's log importer re-reads the same source for a span of closed hours, with
no following (`file_history`: the file and its rotated copies; `journal_history`:
`journalctl --since --until`). Each event goes through `report_auth` with a fresh state
and detector (`import_source` in `monitor.py`), so it is logged and alerted on as it
would have been live. Lines the running command already read are logged with the same
time and message, so the import recognizes them and writes only what is missing.

