#!/usr/bin/env bash
# iptablesaudit tests. Read-only; fixtures in a temp dir.
set -uo pipefail
cd "$(dirname "$0")/.."
IA="python3 iptablesaudit.py"
pass=0; fail=0
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

assert() {   # <desc> <expect> -- <cmd...>
    local desc="$1" expect="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$expect" <<<"$out"; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$desc" "$expect" "$out"; fail=$((fail+1)); fi
}
refute() {   # <desc> <needle> -- <cmd...>
    local desc="$1" needle="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$needle" <<<"$out"; then printf '  FAIL  %s (found %s)\n' "$desc" "$needle"; fail=$((fail+1))
    else printf '  PASS  %s\n' "$desc"; pass=$((pass+1)); fi
}
assert_exit() {  # <desc> <code> -- <cmd...>
    local desc="$1" want="$2"; shift 2; [[ "$1" == "--" ]] && shift
    "$@" >/dev/null 2>&1; local rc=$?
    if [[ "$rc" == "$want" ]]; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s (exit %s want %s)\n' "$desc" "$rc" "$want"; fail=$((fail+1)); fi
}

echo "== syntax =="
if python3 -c "import ast; ast.parse(open('iptablesaudit.py').read())"; then
    echo "  PASS  iptablesaudit.py parses"; pass=$((pass+1))
else echo "  FAIL  syntax"; fail=$((fail+1)); fi

echo "== an open ruleset =="
cat > "$T/bad.v4" <<'EOF'
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 5432 -j ACCEPT
-A INPUT -s 10.0.0.0/8 -p tcp --dport 6379 -j ACCEPT
-A INPUT -j ACCEPT
COMMIT
EOF
assert "ACCEPT policy flagged"       "default policy is ACCEPT"          -- $IA "$T/bad.v4" --no-color
assert "postgres to world HIGH"      "PostgreSQL (port 5432"             -- $IA "$T/bad.v4" --no-color
assert "ssh to world is MEDIUM"      "MEDIUM"                            -- $IA "$T/bad.v4" --no-color
assert "blanket accept flagged"      "blanket ACCEPT with no restriction" -- $IA "$T/bad.v4" --no-color
refute "restricted-source redis ok"  "Redis"                             -- $IA "$T/bad.v4" --no-color
assert_exit "open ruleset exits non-zero" 1 -- $IA "$T/bad.v4" --no-color

echo "== a locked-down ruleset =="
cat > "$T/good.v4" <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -s 203.0.113.0/24 -j ACCEPT
COMMIT
EOF
assert "clean ruleset is OK"         "no obvious firewall holes"         -- $IA "$T/good.v4" --no-color
assert_exit "clean ruleset exits zero" 0 -- $IA "$T/good.v4" --no-color

echo "== empty / no filter table =="
printf '*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n' > "$T/nofilter.v4"
assert "no filter table flagged"     "no host firewall rules at all"     -- $IA "$T/nofilter.v4" --no-color

echo "== stdin + multiport =="
_out="$(printf '*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m multiport --dports 3306,6379 -j ACCEPT\nCOMMIT\n' | $IA - --no-color)"
if grep -q "MySQL/MariaDB" <<<"$_out" && grep -q "Redis" <<<"$_out"; then
    printf '  PASS  %s\n' "multiport dports each flagged"; pass=$((pass+1))
else printf '  FAIL  multiport dports (got: %s)\n' "$_out"; fail=$((fail+1)); fi

echo
echo "== $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
