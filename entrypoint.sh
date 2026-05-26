#!/bin/bash
#
# S7pot entrypoint
# 1. Configures tc netem latency on port 102 (requires NET_ADMIN — runs as root briefly)
# 2. Drops privileges to the 's7pot' user before exec'ing Python
#
# Real Siemens S7-1200 PLCs respond with 20–80 ms depending on CPU load and
# network hops. We inject 60 ms ± 15 ms (normal distribution) to defeat
# timing-based fingerprinters.
#
set -e

DELAY="${S7_DELAY:-60ms}"
JITTER="${S7_JITTER:-15ms}"
DISTRIBUTION="normal"
IFACE="${TC_IFACE:-eth0}"

echo ""
echo " S7pot — ICS Honeypot"
echo " Applying tc netem: ${DELAY} ± ${JITTER} (${DISTRIBUTION}) on ${IFACE}:102"
echo ""

# ---------------------------------------------------------------------------
# TCP stack hardening — defeat p0f / nmap -O fingerprinting
#
# Real S7-1200 (VxWorks-based RTOS) TCP characteristics:
#   TTL=128, window=8192, no SACK, no timestamps, no window scaling
# Default Linux gives TTL=64, window=65495, SACK+timestamps+scaling — all
# trivially identifiable as a general-purpose OS.
# ---------------------------------------------------------------------------

# TTL=128 matches Windows/embedded stacks (not Linux 64)
iptables -t mangle -A POSTROUTING -p tcp --sport 102 -j TTL --ttl-set 128 2>/dev/null || true
iptables -t mangle -A POSTROUTING -p tcp --dport 102 -j TTL --ttl-set 128 2>/dev/null || true

# Disable TCP options that a real S7-1200 does not advertise
sysctl -w net.ipv4.tcp_sack=0           2>/dev/null || true  # no Selective ACK
sysctl -w net.ipv4.tcp_timestamps=0     2>/dev/null || true  # no TCP timestamps
sysctl -w net.ipv4.tcp_window_scaling=0 2>/dev/null || true  # no window scaling

# Window size: 8192 bytes matches real S7-1200 initial receive window
sysctl -w net.ipv4.tcp_rmem="4096 8192 8192" 2>/dev/null || true
sysctl -w net.ipv4.tcp_wmem="4096 8192 8192" 2>/dev/null || true

# MSS clamping keeps segment sizes consistent with embedded stack behaviour
iptables -t mangle -A POSTROUTING -p tcp --sport 102 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

echo "TCP stack hardened: TTL=128, window=8192, SACK/timestamps/scaling disabled"

# Selective netem delay: only port 102 traffic gets the delay
if tc qdisc show dev "${IFACE}" | grep -q "prio"; then
    tc qdisc replace dev "${IFACE}" root handle 1: prio priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
else
    tc qdisc add    dev "${IFACE}" root handle 1: prio priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
fi

tc qdisc add dev "${IFACE}" parent 1:1 handle 10: netem \
    delay "${DELAY}" "${JITTER}" distribution "${DISTRIBUTION}"

tc filter add dev "${IFACE}" parent 1:0 protocol ip u32 \
    match ip dport 102 0xffff flowid 1:1
tc filter add dev "${IFACE}" parent 1:0 protocol ip u32 \
    match ip sport 102 0xffff flowid 1:1

echo "tc netem active on ${IFACE}: port 102 → ~${DELAY} ± ${JITTER}"
echo "TTL rewrite active: port 102 outbound TTL → 128"
echo ""

# Drop to unprivileged user for the Python process
exec gosu s7pot python3 /app/s7pot.py
