#!/usr/bin/env python3
"""iptablesaudit - review an iptables ruleset for holes.

Firewall rules are hard to read and easy to get wrong: a chain left on the
default ACCEPT policy, a database port opened to 0.0.0.0/0 "just for testing", a
blanket ``-j ACCEPT``. iptablesaudit reads ``iptables-save`` output and reports
the openings by severity. It changes nothing.

    iptables-save | iptablesaudit -
    iptablesaudit rules.v4                 # a saved ruleset file

(Reading the live ruleset needs root; piping `sudo iptables-save` avoids running
this tool as root.) Exit status is non-zero on any HIGH or CRITICAL finding.
"""
from __future__ import annotations

import argparse
import re
import sys

SENSITIVE_PORTS = {
    "22": "SSH", "23": "Telnet", "3306": "MySQL/MariaDB", "5432": "PostgreSQL",
    "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch", "5601": "Kibana",
    "2375": "Docker API", "2376": "Docker API", "11211": "memcached",
    "5672": "RabbitMQ", "15672": "RabbitMQ admin", "9092": "Kafka",
    "3389": "RDP", "5900": "VNC", "2049": "NFS", "873": "rsync", "1433": "MSSQL",
}
ANY_SRC = {"0.0.0.0/0", "::/0", None}


class Finding:
    def __init__(self, level: str, msg: str):
        self.level, self.msg = level, msg


def _opt(tokens: list[str], *names: str) -> str | None:
    for name in names:
        if name in tokens:
            i = tokens.index(name)
            if i + 1 < len(tokens):
                return tokens[i + 1]
    return None


def audit(text: str) -> list[Finding]:
    out: list[Finding] = []
    table = ""
    policies: dict[tuple[str, str], str] = {}   # (table, chain) -> policy
    input_rules: list[list[str]] = []
    input_has_state_accept = False
    saw_filter = False

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:].strip()
            if table == "filter":
                saw_filter = True
            continue
        if line.startswith(":"):
            m = re.match(r":(\S+)\s+(\S+)", line)
            if m:
                policies[(table, m.group(1))] = m.group(2)
            continue
        if line.startswith("-A ") and table == "filter":
            tokens = line.split()
            chain = tokens[1]
            if chain == "INPUT":
                input_rules.append(tokens)
                target = _opt(tokens, "-j")
                state = _opt(tokens, "--ctstate", "--state")
                if target == "ACCEPT" and state and "ESTABLISHED" in state.upper():
                    input_has_state_accept = True

    if not saw_filter:
        return [Finding("HIGH", "no filter table in the ruleset (no host firewall rules at all)")]

    # default policies
    for chain in ("INPUT", "FORWARD"):
        pol = policies.get(("filter", chain))
        if pol is None:
            out.append(Finding("HIGH", f"filter table has no {chain} base chain declaration; audit is incomplete"))
        elif pol == "ACCEPT":
            lvl = "HIGH" if chain == "INPUT" else "MEDIUM"
            out.append(Finding(lvl, f"{chain} chain default policy is ACCEPT; it should be DROP with explicit allows"))

    # per-rule INPUT analysis
    for tokens in input_rules:
        target = _opt(tokens, "-j")
        if target != "ACCEPT":
            continue
        src = _opt(tokens, "-s")
        proto = _opt(tokens, "-p") or "any"
        dport = _opt(tokens, "--dport")
        dports = _opt(tokens, "--dports")
        has_match = any(t in tokens for t in ("-p", "--dport", "--dports", "-s", "-i", "-m"))
        # a truly blanket accept
        if not has_match or (has_match and not any(t in tokens for t in ("-p", "--dport", "--dports", "-s", "-i"))
                             and "conntrack" not in " ".join(tokens) and "state" not in " ".join(tokens)):
            if not dport and not dports and src in ANY_SRC and proto == "any":
                out.append(Finding("HIGH", f"blanket ACCEPT with no restriction: {' '.join(tokens)}"))
                continue

        ports = []
        if dport:
            ports = [dport]
        elif dports:
            ports = dports.split(",")
        for port in ports:
            svc = SENSITIVE_PORTS.get(port)
            if svc and src in ANY_SRC:
                lvl = "HIGH" if port not in ("22",) else "MEDIUM"
                out.append(Finding(lvl,
                    f"{svc} (port {port}/{proto}) is open to the whole internet (source {src or 'any'}); restrict the source"))

    # state tracking
    if policies.get(("filter", "INPUT")) == "DROP" and not input_has_state_accept:
        out.append(Finding("INFO",
            "INPUT drops by default but has no ESTABLISHED/RELATED accept; return traffic may be blocked"))

    if not out:
        out.append(Finding("OK", "no obvious firewall holes"))
    return out


RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "OK": 0}
COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
         "LOW": "\033[36m", "INFO": "\033[90m", "OK": "\033[32m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="iptablesaudit", description="review an iptables-save ruleset for holes")
    p.add_argument("file", help="iptables-save output file, or - for stdin")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    text = sys.stdin.read() if a.file == "-" else open(a.file, encoding="utf-8", errors="replace").read()
    findings = audit(text)
    worst = 0
    for f in sorted(findings, key=lambda x: -RANK[x.level]):
        worst = max(worst, RANK[f.level])
        tag = f"{COLOR[f.level]}{f.level:<8}{RESET}" if use_color else f"{f.level:<8}"
        print(f"  {tag} {f.msg}")
    return 1 if worst >= RANK["HIGH"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
