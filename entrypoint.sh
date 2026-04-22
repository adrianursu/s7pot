#!/bin/bash
# 
# S7pot entrypoint — applies realistic S7/PLC network latency via
# Linux Traffic Control (tc netem), then starts the honeypot.
#
# Real Siemens S7-1200 PLCs respond with 20–80ms depending on
# CPU load and network hops. We inject 60ms ± 15ms jitter on
# the container's eth0 interface to make timing-based fingerprinters
# believe this is genuine hardware.
#
# Requires: NET_ADMIN capability (set in docker-compose.yml)
# 

set -e

DELAY="60ms"
JITTER="15ms"
DISTRIBUTION="normal"        # normal | pareto | paretonormal
IFACE="${TC_IFACE:-eth0}"    # override with TC_IFACE env var if needed

echo ""
echo " S7pot — ICS Honeypot"
echo " Applying tc netem latency: ${DELAY} ± ${JITTER} (${DISTRIBUTION})"
echo ""

# Apply kernel-level network latency to mimic PLC hardware timing.
# We use a PRIO qdisc + filter so only traffic on port 102 (S7comm)
# gets the delay — HTTP/SNMP stay snappy.
if tc qdisc show dev "${IFACE}" | grep -q "prio"; then
    # Already configured — replace
    tc qdisc replace dev "${IFACE}" root handle 1: prio priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
else
    tc qdisc add dev "${IFACE}" root handle 1: prio priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
fi

# Attach netem delay to band 1 (low priority band — our filter will redirect to it)
tc qdisc add dev "${IFACE}" parent 1:1 handle 10: netem \
    delay "${DELAY}" "${JITTER}" distribution "${DISTRIBUTION}"

# Filter: redirect TCP dst port 102 and src port 102 into the delay band
tc filter add dev "${IFACE}" parent 1:0 protocol ip u32 \
    match ip dport 102 0xffff flowid 1:1
tc filter add dev "${IFACE}" parent 1:0 protocol ip u32 \
    match ip sport 102 0xffff flowid 1:1

echo "tc netem active: port 102 will respond in ~${DELAY} ± ${JITTER}"
echo "   Interface: ${IFACE}"
echo ""

# Hand off to the honeypot
exec python3 s7pot.py
