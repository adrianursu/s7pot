#!/usr/bin/env bash
# test_honeypot.sh — end-to-end smoke test for s7pot honeypot stack
# Usage: ./test_honeypot.sh [--no-nmap] [--no-s7]
set -euo pipefail

# ── colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

PASS=0; FAIL=0; SKIP=0
declare -a FAILURES=()

pass()  { echo -e "  ${GREEN}✓${RESET} $1"; PASS=$((PASS+1));  }
fail()  { echo -e "  ${RED}✗${RESET} $1"; FAIL=$((FAIL+1)); FAILURES+=("$1"); }
skip()  { echo -e "  ${YELLOW}–${RESET} $1 (skipped)"; SKIP=$((SKIP+1)); }
header(){ echo -e "\n${CYAN}${BOLD}── $1 ──${RESET}"; }
check() {
    local desc="$1"; shift
    if eval "$@" &>/dev/null; then pass "$desc"; else fail "$desc"; fi
}
check_output() {
    # Uses $() to buffer output — avoids SIGPIPE under set -o pipefail
    local desc="$1" expected="$2"; shift 2
    local out; out=$(eval "$@" 2>&1) || true
    if echo "$out" | grep -qF "$expected"; then
        pass "$desc"
    else
        fail "$desc — got: $(echo "$out" | head -3)"
    fi
}

# ── parse flags ───────────────────────────────────────────────────────────────
SKIP_NMAP=false; SKIP_S7=false
for arg in "$@"; do
    case "$arg" in
        --no-nmap) SKIP_NMAP=true ;;
        --no-s7)   SKIP_S7=true   ;;
    esac
done

echo -e "${BOLD}s7pot honeypot test suite${RESET}  $(date)"

# ── 0. Prerequisites ──────────────────────────────────────────────────────────
header "0. Prerequisites"

check "docker available"          command -v docker
check "docker compose available"  docker compose version
check "curl available"            command -v curl
check "python3 available"         command -v python3

if command -v nmap &>/dev/null; then
    pass "nmap available"
else
    SKIP_NMAP=true
    skip "nmap not found — install with: brew install nmap"
fi

if python3 -c "import snap7" &>/dev/null; then
    pass "python3 snap7 available"
else
    SKIP_S7=true
    skip "python3 snap7 not installed — run: pip install python-snap7==1.3"
fi

# ── 1. Stack health ───────────────────────────────────────────────────────────
header "1. Stack health"

check "s7pot container running" \
    "docker inspect -f '{{.State.Running}}' s7pot | grep -q true"
check "s7pot_normalizer running" \
    "docker inspect -f '{{.State.Running}}' s7pot_normalizer | grep -q true"
check "s7pot_loki running" \
    "docker inspect -f '{{.State.Running}}' s7pot_loki | grep -q true"
check "s7pot_promtail running" \
    "docker inspect -f '{{.State.Running}}' s7pot_promtail | grep -q true"
check "s7pot_grafana running" \
    "docker inspect -f '{{.State.Running}}' s7pot_grafana | grep -q true"

# ── 2. Container security hardening ──────────────────────────────────────────
header "2. Container security hardening"

check "PID 1 running as uid=1000 (gosu drop worked)" \
    "docker exec s7pot cat /proc/1/status | grep -E '^Uid:' | awk '{print \$2}' | grep -q '^1000$'"

check_output "NET_ADMIN in CapAdd" "CAP_NET_ADMIN" \
    "docker inspect s7pot | python3 -c \"import sys,json; print(json.load(sys.stdin)[0]['HostConfig']['CapAdd'])\""
check_output "SETUID in CapAdd" "CAP_SETUID" \
    "docker inspect s7pot | python3 -c \"import sys,json; print(json.load(sys.stdin)[0]['HostConfig']['CapAdd'])\""
check_output "ALL in CapDrop" "ALL" \
    "docker inspect s7pot | python3 -c \"import sys,json; print(json.load(sys.stdin)[0]['HostConfig']['CapDrop'])\""

check_output "read-only root filesystem" "True" \
    "docker inspect s7pot | python3 -c \"import sys,json; print(json.load(sys.stdin)[0]['HostConfig']['ReadonlyRootfs'])\""
check_output "no-new-privileges set" "no-new-privileges" \
    "docker inspect s7pot | python3 -c \"import sys,json; print(json.load(sys.stdin)[0]['HostConfig']['SecurityOpt'])\""

check "/ is not writable" \
    "docker exec s7pot sh -c 'touch /canary 2>/dev/null && exit 1 || exit 0'"
check "/app is not writable" \
    "docker exec s7pot sh -c 'touch /app/canary 2>/dev/null && exit 1 || exit 0'"
check "/tmp is writable" \
    "docker exec s7pot sh -c 'touch /tmp/canary_test && rm /tmp/canary_test'"
check "/app/logs is writable" \
    "docker exec s7pot sh -c 'touch /app/logs/canary_test && rm /app/logs/canary_test'"

check_output "memory limit 512MB" "536870912" \
    "docker inspect s7pot | python3 -c \"import sys,json; print(json.load(sys.stdin)[0]['HostConfig']['Memory'])\""
check_output "pids limit 256" "256" \
    "docker inspect s7pot | python3 -c \"import sys,json; print(json.load(sys.stdin)[0]['HostConfig']['PidsLimit'])\""

# ── 3. HTTP fingerprint ───────────────────────────────────────────────────────
header "3. HTTP fingerprint"

check "HTTP port 80 responds" \
    "curl -sf --max-time 5 http://localhost:80/ -o /dev/null"
check_output "Server: Siemens HTTP Server" "Siemens HTTP Server" \
    "curl -sI --max-time 5 http://localhost:80/"
check_output "Keep-Alive header present" "Keep-Alive" \
    "curl -sI --max-time 5 http://localhost:80/"
check_output "X-Frame-Options: SAMEORIGIN" "SAMEORIGIN" \
    "curl -sI --max-time 5 http://localhost:80/"
check_output "Landing page contains SIMATIC" "SIMATIC S7-1200" \
    "curl -s --max-time 5 http://localhost:80/"
check_output "Portal GET returns login form (not open config)" "Log In" \
    "curl -s --max-time 5 'http://localhost:80/Portal/Portal.mwsl'"
check_output "Portal POST returns auth-fail page" "Login failed" \
    "curl -s --max-time 5 -X POST -d 'Login=admin&Password=test123&PriNav=Home' 'http://localhost:80/Portal/Portal.mwsl'"
sleep 1
check_output "Credential submission captured in log" "CREDENTIAL_SUBMISSION" \
    "docker exec s7pot grep -m1 'CREDENTIAL_SUBMISSION' /app/logs/interaction.json"
check_output "AWP directory stub responds" "awp" \
    "curl -s --max-time 5 http://localhost:80/awp/"

# ── 4. S7comm — memory areas, SZL proxy, client fingerprinting ───────────────
header "4. S7comm — memory areas, SZL proxy, client fingerprinting"

if $SKIP_S7; then
    skip "S7comm tests (python3 snap7 not available)"
else
    set +e
    S7_RESULT=$(python3 - 2>&1 <<'PYEOF'
import sys, snap7

c = snap7.client.Client()
try:
    c.connect('127.0.0.1', 0, 1, 102)
except Exception as e:
    print(f"CONNECT_FAIL:{e}"); sys.exit(1)

if not c.get_connected():
    print("NOT_CONNECTED"); sys.exit(1)
print("PROBE_CONNECTED")

for db_num in (1, 2, 3, 4):
    try:
        data = c.db_read(db_num, 0, 8)
        print(f"DB{db_num}_OK:{data[:4].hex()}")
    except Exception as e:
        print(f"DB{db_num}_FAIL:{e}")

for area_int, area_label in [(0x81,"I"), (0x82,"Q"), (0x83,"M")]:
    try:
        data = c.read_area(area_int, 0, 0, 1)
        print(f"{area_label}_AREA_OK:{data[0]:08b}")
    except Exception as e:
        print(f"{area_label}_AREA_FAIL:{e}")

try:
    szl = c.read_szl(0x001C, 0x0000)
    hdr = szl.Header
    n = getattr(hdr, 'N_DR', None) or getattr(hdr, 'LengthDataRecord', None) or '?'
    print(f"SZL_OK:records={n}")
except Exception as e:
    print(f"SZL_FAIL:{e}")

c.disconnect()
PYEOF
    )
    set -e

    while IFS= read -r line; do
        case "$line" in
            PROBE_CONNECTED)   pass "S7comm TCP connection on port 102 established" ;;
            CONNECT_FAIL:*)    fail "S7comm connect: ${line#*:}" ;;
            NOT_CONNECTED)     fail "S7comm: get_connected() returned False" ;;
            DB1_OK:*)          pass "DB1 readable (process values: ${line#*:})" ;;
            DB1_FAIL:*)        fail "DB1 read failed: ${line#*:}" ;;
            DB2_OK:*)          pass "DB2 readable (PID params: ${line#*:})" ;;
            DB2_FAIL:*)        fail "DB2 read failed: ${line#*:}" ;;
            DB3_OK:*)          pass "DB3 readable (alarms: ${line#*:})" ;;
            DB3_FAIL:*)        fail "DB3 read failed: ${line#*:}" ;;
            DB4_OK:*)          pass "DB4 readable (setpoints: ${line#*:})" ;;
            DB4_FAIL:*)        fail "DB4 read failed: ${line#*:}" ;;
            I_AREA_OK:*)       pass "I area (digital inputs) readable: ${line#*:}" ;;
            I_AREA_FAIL:*)     fail "I area read failed: ${line#*:}" ;;
            Q_AREA_OK:*)       pass "Q area (digital outputs) readable: ${line#*:}" ;;
            Q_AREA_FAIL:*)     fail "Q area read failed: ${line#*:}" ;;
            M_AREA_OK:*)       pass "M area (markers) readable: ${line#*:}" ;;
            M_AREA_FAIL:*)     fail "M area read failed: ${line#*:}" ;;
            SZL_OK:*)          pass "SZL 0x001C intercepted and returned (${line#*:})" ;;
            SZL_FAIL:*)        fail "SZL read failed: ${line#*:}" ;;
        esac
    done < <(echo "$S7_RESULT")

    # snap7 sends Setup Communication PDU on connect — proxy logs the tool
    sleep 1
    check_output "CLIENT_FINGERPRINTED logged (tool identified from Setup Comm PDU)" "CLIENT_FINGERPRINTED" \
        "docker exec s7pot grep -m1 'CLIENT_FINGERPRINTED' /app/logs/interaction.json"
fi

# ── 5. nmap S7 fingerprint ────────────────────────────────────────────────────
header "5. nmap S7 fingerprint"

if $SKIP_NMAP; then
    skip "nmap tests (nmap not available)"
else
    NMAP_OUT=$(nmap -sV --script s7-info -p 102 --open -T4 localhost 2>&1) || true
    if echo "$NMAP_OUT" | grep -q "open"; then
        pass "nmap: port 102 open"
    else
        fail "nmap: port 102 not reported open — $(echo "$NMAP_OUT" | tail -3)"
    fi
    if echo "$NMAP_OUT" | grep -qiE "1214|214-1AG40|1200"; then
        pass "nmap: identified as S7-1200 (not snap7 default)"
    else
        fail "nmap: S7-1200 fingerprint NOT seen — $(echo "$NMAP_OUT" | grep -i cpu || echo 'no CPU line')"
    fi
    if echo "$NMAP_OUT" | grep -qiE "SNAP7-SERVER|315|CPU 315"; then
        fail "nmap: still shows snap7 or S7-315 identity — SZL patch may have failed"
    else
        pass "nmap: no snap7/S7-315 strings in output"
    fi
fi

# ── 6. Physics simulation ─────────────────────────────────────────────────────
header "6. Physics simulation"

check_output "PLC physics log line present" "[PLC]" \
    "docker logs s7pot 2>&1 | grep '\[PLC\]' | tail -3"

L1=$(docker logs s7pot 2>&1 | grep '\[PLC\]' | tail -1 | grep -oE 'Level:[0-9.]+' | grep -oE '[0-9.]+' || echo "0")
sleep 3
L2=$(docker logs s7pot 2>&1 | grep '\[PLC\]' | tail -1 | grep -oE 'Level:[0-9.]+' | grep -oE '[0-9.]+' || echo "0")
if [[ "$L1" != "$L2" && -n "$L1" && -n "$L2" ]]; then
    pass "Tank level changing over time ($L1 L → $L2 L)"
else
    fail "Tank level not changing or unreadable ($L1 → $L2) — physics may be frozen"
fi

# ── 7. Log pipeline (Promtail → Loki) ────────────────────────────────────────
header "7. Log pipeline (Promtail → Loki)"

check_output "interaction.json exists and non-empty" "protocol" \
    "docker exec s7pot cat /app/logs/interaction.json 2>/dev/null | head -1"
check_output "interaction.ndjson being written by normalizer" "protocol" \
    "docker exec s7pot_normalizer cat /logs/interaction.ndjson 2>/dev/null | head -1"
check_output "Promtail started successfully" "Starting Promtail" \
    "docker logs s7pot_promtail"
check_output "Promtail tailing ndjson log file" "tail routine" \
    "docker logs s7pot_promtail"
check "Loki container healthy" \
    "docker inspect -f '{{.State.Running}}' s7pot_loki | grep -q true"
check "Grafana reachable on localhost:3000" \
    "curl -sf --max-time 5 http://localhost:3000/api/health -o /dev/null"

# ── 8. Anti-fingerprint hardening ────────────────────────────────────────────
header "8. Anti-fingerprint hardening"

check_output "tcp_sack disabled (defeats p0f/nmap -O)" "0" \
    "docker exec s7pot cat /proc/sys/net/ipv4/tcp_sack"
check_output "tcp_timestamps disabled" "0" \
    "docker exec s7pot cat /proc/sys/net/ipv4/tcp_timestamps"
check_output "tcp_window_scaling disabled" "0" \
    "docker exec s7pot cat /proc/sys/net/ipv4/tcp_window_scaling"

check_output "log entries carry HMAC hash field" '"hash"' \
    "docker exec s7pot cat /app/logs/interaction.json 2>/dev/null | tail -5"
check_output "log entries carry prev_hash chain field" '"prev_hash"' \
    "docker exec s7pot cat /app/logs/interaction.json 2>/dev/null | tail -5"

if $SKIP_S7; then
    skip "SZL catch-all test (python3 snap7 not available)"
else
    set +e
    SZL_UNKNOWN=$(python3 - 2>&1 <<'PYEOF'
import snap7, sys
c = snap7.client.Client()
try:
    c.connect('127.0.0.1', 0, 1, 102)
except Exception as e:
    print(f"CONNECT_FAIL:{e}"); sys.exit(1)
try:
    c.read_szl(0xFFFF, 0x0000)   # guaranteed unknown SZL ID
    print("UNKNOWN_SZL_HANDLED")
except Exception as e:
    # snap7 raises on error PDU — correct; the PLC is still alive
    print(f"UNKNOWN_SZL_ERROR_RESPONSE:{e}")
try:
    c.disconnect()
except Exception:
    pass
PYEOF
    )
    set -e
    if echo "$SZL_UNKNOWN" | grep -qE "UNKNOWN_SZL_HANDLED|UNKNOWN_SZL_ERROR_RESPONSE"; then
        pass "SZL catch-all: unknown SZL ID handled (server did not crash)"
        set +e
        RECONNECT=$(python3 -c "
import snap7
c = snap7.client.Client()
c.connect('127.0.0.1', 0, 1, 102)
print('RECONNECT_OK' if c.get_connected() else 'RECONNECT_FAIL')
c.disconnect()
" 2>&1)
        set -e
        if echo "$RECONNECT" | grep -q "RECONNECT_OK"; then
            pass "S7comm still accepts connections after unknown SZL query"
        else
            fail "S7comm not responding after unknown SZL query — server may have crashed"
        fi
    else
        fail "SZL catch-all: unexpected result — $SZL_UNKNOWN"
    fi
fi

# ── 9. CVE-2021-37185 exploit simulation (tank overflow) ─────────────────────
header "9. CVE-2021-37185 exploit simulation (tank overflow)"

if $SKIP_S7; then
    skip "Exploit simulation (python3 snap7 not available)"
else
    echo "  (pre-setting tank to 145 L + activating safety bypass — overflow expected in ~2s)"
    set +e
    EXPLOIT_RESULT=$(python3 - 2>&1 <<'PYEOF'
import snap7, sys, struct

c = snap7.client.Client()
try:
    c.connect('127.0.0.1', 0, 1, 102)
except Exception as e:
    print(f"CONNECT_FAIL:{e}"); sys.exit(1)

try:
    buf = bytearray(c.db_read(1, 0, 16))
    struct.pack_into('>f', buf, 2, 145.0)  # level → 145 L (5 L below overflow)
    buf[14] = 1                             # safety bypass ON
    c.db_write(1, 0, buf)
    print("EXPLOIT_WRITE_OK")
except Exception as e:
    print(f"EXPLOIT_WRITE_FAIL:{e}")

c.disconnect()
PYEOF
    )
    set -e

    if echo "$EXPLOIT_RESULT" | grep -q "EXPLOIT_WRITE_OK"; then
        pass "DB1[14]=1 written, level pre-set to 145 L (safety bypass active)"
    else
        fail "Exploit write failed: $EXPLOIT_RESULT"
    fi

    echo "  (waiting 3s for physics engine — 1 Hz loop — to trigger overflow...)"
    sleep 3

    check_output "CVE_TRIGGERED captured in log" "CVE_TRIGGERED" \
        "docker exec s7pot grep -m1 'CVE_TRIGGERED' /app/logs/interaction.json"
    check_output "DB1_WRITE_DETECTED captured in log" "DB1_WRITE_DETECTED" \
        "docker exec s7pot grep -m1 'DB1_WRITE_DETECTED' /app/logs/interaction.json"
    check_output "CRITICAL_OVERFLOW_ALARM captured in log" "CRITICAL_OVERFLOW_ALARM" \
        "docker exec s7pot grep -m1 'CRITICAL_OVERFLOW_ALARM' /app/logs/interaction.json"
    check_output "physics log shows EXPLOIT mode" "EXPLOIT" \
        "docker logs s7pot 2>&1 | tail -10"

    echo "  (clearing exploit flag — restoring normal operation)"
    set +e
    python3 - 2>&1 <<'PYEOF' | grep -q "CLEARED" \
        && pass "DB1[14] cleared — physics back to NORMAL" \
        || fail "Failed to clear exploit flag"
import snap7, struct
c = snap7.client.Client()
c.connect('127.0.0.1', 0, 1, 102)
buf = bytearray(c.db_read(1, 0, 16))
struct.pack_into('>f', buf, 2, 50.0)
buf[14] = 0
c.db_write(1, 0, buf)
print("CLEARED")
c.disconnect()
PYEOF
    set -e
fi

# ── 10. CPU STOP simulation ───────────────────────────────────────────────────
header "10. CPU STOP simulation"

if $SKIP_S7; then
    skip "CPU STOP test (python3 snap7 not available)"
else
    set +e
    STOP_RESULT=$(python3 - 2>&1 <<'PYEOF'
import snap7, sys
c = snap7.client.Client()
try:
    c.connect('127.0.0.1', 0, 1, 102)
except Exception as e:
    print(f"CONNECT_FAIL:{e}"); sys.exit(1)
try:
    c.plc_stop()
    print("STOP_SENT")
except Exception as e:
    print(f"STOP_FAIL:{e}")
c.disconnect()
PYEOF
    )
    set -e

    if echo "$STOP_RESULT" | grep -q "STOP_SENT"; then
        pass "PLCSTOP (S7comm function 0x29) sent via snap7"
    else
        fail "PLCSTOP failed: $STOP_RESULT"
    fi

    sleep 1
    check_output "CPU_STOP_ATTEMPT captured in log" "CPU_STOP_ATTEMPT" \
        "docker exec s7pot grep -m1 'CPU_STOP_ATTEMPT' /app/logs/interaction.json"
    check_output "CPU_HALTED captured in log (physics suspended 30s)" "CPU_HALTED" \
        "docker exec s7pot grep -m1 'CPU_HALTED' /app/logs/interaction.json"
    check_output "physics log shows STOP mode" "CPU: STOP mode" \
        "docker logs s7pot 2>&1 | tail -5"
fi

# ── 11. /teapot credential dashboard ─────────────────────────────────────────
header "11. /teapot credential dashboard"

check_output "/DataLogs/sysdiag returns landing page to external requests (no honeypot tell)" "SIMATIC" \
    "curl -s --max-time 5 http://localhost:80/DataLogs/sysdiag"

set +e
TEAPOT_HTML=$(docker exec s7pot python3 -c \
    "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1/DataLogs/sysdiag').read().decode())" \
    2>&1) || true
set -e

if echo "$TEAPOT_HTML" | grep -q "Login Statistics"; then
    pass "/teapot accessible from inside container"
else
    fail "/teapot not accessible from inside container — got: $(echo "$TEAPOT_HTML" | head -2)"
fi
if echo "$TEAPOT_HTML" | grep -q "Top Usernames"; then
    pass "/teapot shows credential statistics tables"
else
    fail "/teapot missing credential tables"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${GREEN}Passed: $PASS${RESET}  ${RED}Failed: $FAIL${RESET}  ${YELLOW}Skipped: $SKIP${RESET}"
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo -e "\n${RED}${BOLD}Failures:${RESET}"
    for f in "${FAILURES[@]}"; do echo -e "  ${RED}✗${RESET} $f"; done
fi
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
[[ $FAIL -eq 0 ]]
