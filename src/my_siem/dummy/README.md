# `dummy`: what it reads and how

`dummy` reads nothing. It makes up placeholder data, so the dashboard can be tried
without root, live traffic or sshd logs. It is also the template for new commands (see
[Adding a command](../README.md#adding-a-command)).

## Where the data comes from

All of it is generated in `command.py`, from a random generator seeded with `seed`
(default `42`), so every run makes up the same traffic.

Every `interval` seconds (default 5, flag `--interval`), `run()` logs one
`siem.dummy.tick` event with what it made up: 0 to 6 allowed events (more by day than by
night), 0 to 2 blocked, and three times in ten a random rule ("Port scan", "Brute force",
"Malware beacon" or "Data exfiltration"). `count_keys` turns each tick into the counts
the dashboard reads (`allowed`, `blocked`, `rule:<name>`), so like every command it is
read back for the chosen time window, across restarts.

