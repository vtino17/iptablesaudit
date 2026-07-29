# iptablesaudit

Review an iptables ruleset for holes.

Firewall rules are hard to read and easy to get wrong: a chain left on the
default `ACCEPT` policy, a database port opened to `0.0.0.0/0` "just for
testing", a blanket `-j ACCEPT` at the end. iptablesaudit reads `iptables-save`
output and reports the openings by severity. It changes nothing.

It is a single Python file with no dependencies and exits non-zero on any HIGH or
CRITICAL finding, so it fits CI or a periodic check.

## Usage

```sh
sudo iptables-save | iptablesaudit -
iptablesaudit /etc/iptables/rules.v4
```

Piping `sudo iptables-save` into it means the tool itself never needs root.

Example:

```
$ sudo iptables-save | iptablesaudit -
  HIGH     INPUT chain default policy is ACCEPT; it should be DROP with explicit allows
  HIGH     PostgreSQL (port 5432/tcp) is open to the whole internet (source any); restrict the source
  HIGH     blanket ACCEPT with no restriction: -A INPUT -j ACCEPT
  MEDIUM   SSH (port 22/tcp) is open to the whole internet (source any); restrict the source
```

## What it checks

- **Default-accept chains** — `INPUT` or `FORWARD` left on the `ACCEPT` policy
  instead of `DROP` with explicit allows.
- **Sensitive ports open to the world** — SSH, RDP, VNC, and databases
  (PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, the Docker API, …) accepted
  from `0.0.0.0/0`. A rule that restricts the source (e.g. `-s 10.0.0.0/8`) is
  recognised as fine and left quiet.
- **Blanket `-j ACCEPT`** with no match conditions.
- **Missing state tracking** — a `DROP`-by-default `INPUT` with no
  `ESTABLISHED,RELATED` accept, which can break return traffic.

It understands `-m multiport --dports`, and treats SSH-to-the-world as MEDIUM
(common, but worth restricting) versus databases-to-the-world as HIGH.

## Caveat

It reads the `filter` table's `INPUT`/`FORWARD` chains from a saved ruleset — it
does not follow every user-defined chain or evaluate `nat`/`mangle`, and it does
not see nftables. Treat it as a fast review of the common mistakes, not a proof
that a complex ruleset is airtight.

## Tests

```sh
./tests/run.sh
```

Builds open, locked-down and no-filter-table fixtures and asserts the findings,
including that a source-restricted rule stays quiet and multiport ports are each
checked.

## License

MIT. See `LICENSE`.
