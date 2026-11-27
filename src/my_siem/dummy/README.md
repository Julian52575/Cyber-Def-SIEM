# `dummy`: what it reads and how

`dummy` reads nothing. It makes up placeholder data, so the dashboard can be tried
without root, live traffic or sshd logs. It is also the template for new commands (see
[Adding a command](../README.md#adding-a-command)).

## Where the data comes from

All of it is generated in `command.py`, from a random generator seeded with `seed`
(default `42`), so every run starts with the same data:

| Data      | Starting values                                              |
| --------- | ------------------------------------------------------------ |
| `allowed` | 24 hourly counts on a daily curve, lowest at night           |
| `blocked` | 24 hourly counts between 10 and 35                           |
| `rules`   | hit counts for "Port scan", "Brute force", "Malware beacon" and "Data exfiltration" |

Every `interval` seconds (default 5, flag `--interval`), `run()` adds to the current
local hour: 0 to 6 to `allowed`, 0 to 2 to `blocked`, and, three times in ten, one hit
to a random rule.

Only one event is logged, `siem.source.started`, when the command starts. The data lives
in memory: the dashboard and `GET /dummy` read it, and it starts over on every run.
