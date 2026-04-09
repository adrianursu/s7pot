# S7pot - A S7comm Honeypot

A high-interaction industrial control system (ICS) honeypot that simulates a **Siemens S7-1200 PLC** running a water treatment process. Built for research, threat intelligence, and CVE demonstration purposes.

> ⚠️ **For educational and research use only.** Deploy only in environments you own and control. Do not expose to the internet without a proper threat model and isolated network segment.

---

## Table of Contents

1. [What This Honeypot Simulates](#what-this-honeypot-simulates)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Quick Start — Docker (Recommended)](#quick-start--docker-recommended)
5. [Local Setup (No Docker)](#local-setup-no-docker)
6. [Testing the Honeypot](#testing-the-honeypot)
7. [Simulating an Attack](#simulating-an-attack)
8. [Reading the Logs](#reading-the-logs)
9. [Project Structure](#project-structure)
10. [How the Deception Works](#how-the-deception-works)

---

## What This Honeypot Simulates

| Service | Port | Protocol | Simulated Device |
|---------|------|----------|-----------------|
| S7comm PLC | `102/tcp` | ISO-TSAP / S7comm | Siemens S7-1200 (CPU 1214C) |
| Web Portal | `80/tcp` | HTTP | Siemens SIMATIC S7-300 Web Server |
| SNMP Agent | `161/udp` | SNMP | Siemens CP343-1 network module |

**Simulated CVEs:**

- **CVE-2021-37185** — Unauthenticated S7comm memory write triggers process failure (ESD bypass)
- **CVE-2019-10929** — Siemens SIMATIC web server information disclosure via `/Portal/Portal.mwsl`

**Simulated Process:**  
A water tank process. The PLC cycles the pump between 20–100 L. If an attacker writes to the crash flag in memory, the pump locks ON, the tank overflows past the 150 L Emergency Shutdown threshold, and an alarm fires.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Container                          │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  s7pot.py  (main process)                             │  │
│  │                                                       │  │
│  │  ┌─────────────────┐   ┌──────────────────────────┐  │  │
│  │  │  snap7 Server   │   │  Physics Engine Thread   │  │  │
│  │  │  port 102/tcp   │   │  (water tank simulation) │  │  │
│  │  │  (ISO-TSAP)     │   │  pump, level, ESD alarm  │  │  │
│  │  └────────┬────────┘   └──────────────────────────┘  │  │
│  │           │  shared db1_memory (ctypes buffer)        │  │
│  │  ┌────────▼────────┐   ┌──────────────────────────┐  │  │
│  │  │  psutil Watcher │   │  Write Detector          │  │  │
│  │  │  (new TCP conns)│   │  (diff vs last state)    │  │  │
│  │  └─────────────────┘   └──────────────────────────┘  │  │
│  └──────────────┬────────────────────────────────────────┘  │
│                 │ subprocess                                  │
│     ┌───────────┴─────────────┐                             │
│     │                         │                             │
│  ┌──▼──────────────┐  ┌───────▼────────────┐               │
│  │  web_server.py  │  │  snmp_agent.py     │               │
│  │  port 80/tcp    │  │  port 161/udp      │               │
│  └─────────────────┘  └────────────────────┘               │
│                                                             │
│  logs/interaction.json  ◄── all events written here        │
└─────────────────────────────────────────────────────────────┘
```

**Data Block Memory Layout (DB1):**

| Byte(s) | Type | Description |
|---------|------|-------------|
| `0` | `BYTE` | Pump status (`0` = OFF, `1` = ON) |
| `1` | — | Padding |
| `2–5` | `REAL` (big-endian float) | Water tank level in litres |
| `6` | `BYTE` | Crash/ESD-bypass flag (`0` = normal, `1` = exploit active) |
| `7–15` | — | Reserved |

---

## Prerequisites

### For Docker (recommended)

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- Any terminal (macOS Terminal, iTerm2, etc.)

### For Local Setup

- Python 3.9 or newer
- `pip` package manager
- Root/sudo privileges (ports 80, 102, and 161 are privileged)

---

## Quick Start — Docker (Recommended)

Docker is the recommended way to run this honeypot. It handles all dependencies, binary patching of the snap7 library, and port exposure automatically.

### Step 1 — Clone / Navigate to the Project

```bash
cd /path/to/s7_snap7_honeypot
```

### Step 2 — Build the Docker Image

```bash
docker build -t s7pot .
```

This will:
1. Pull `python:3.9-slim` as the base image
2. Install `python-snap7`, `pysnmp`, and `psutil`
3. **Binary-patch** the snap7 C library to present as a Siemens S7-1200 instead of the default S7-315 (the thesis-grade deception layer)
4. Copy all honeypot files into the image

Expected output (last few lines):
```
✅ Binary Hot-Patch Successful!
...
Successfully built <image_id>
Successfully tagged s7pot:latest
```

### Step 3 — Run the Container

```bash
docker run -it --rm \
  -p 102:102 \
  -p 80:80 \
  -p 161:161/udp \
  -v "$(pwd)/logs:/app/logs" \
  --name honeypot \
  s7pot
```

| Flag | Purpose |
|------|---------|
| `-p 102:102` | Forward S7comm port to host |
| `-p 80:80` | Forward HTTP web portal to host |
| `-p 161:161/udp` | Forward SNMP port (UDP) to host |
| `-v "$(pwd)/logs:/app/logs"` | Mount logs directory so `interaction.json` persists on your machine |
| `--name honeypot` | Give the container a friendly name |
| `--rm` | Auto-remove container on exit |

### Step 4 — Verify It's Running

You should see output like:
```
🚀 Booting s7pot — High-Interaction S7 Honeypot...
✅ S7comm Server LIVE on Port 102.
🔍 Connection Watcher LIVE (polling port 102 for new IPs).
🌊 Physics Engine LIVE. Simulating water treatment process...

🔌 Launching Web Portal Simulation...
📡 Launching SNMP Agent Simulation...
📊 [PLC] Pump: ON  | Level: 22.0L | State: NORMAL
📊 [PLC] Pump: ON  | Level: 24.0L | State: NORMAL
```

### Useful Docker Commands

```bash
# View live logs
docker logs -f honeypot

# Stop the honeypot
docker stop honeypot

# Run in detached (background) mode
docker run -d \
  -p 102:102 -p 80:80 -p 161:161/udp \
  -v "$(pwd)/logs:/app/logs" \
  --name honeypot \
  s7pot

# Rebuild after code changes
docker build -t s7pot . && docker stop honeypot; docker run -d \
  -p 102:102 -p 80:80 -p 161:161/udp \
  -v "$(pwd)/logs:/app/logs" \
  --name honeypot \
  s7pot

# Open a shell inside the running container
docker exec -it honeypot /bin/bash

# Remove the image entirely (to start fresh)
docker rmi s7pot
```

---

## Local Setup (No Docker)

Use this if you want to run without Docker for development/debugging.

### Step 1 — Install Python Dependencies

```bash
pip3 install "python-snap7<3" pysnmp psutil
```

### Step 2 — Run the Honeypot

Ports 80, 102, and 161 are privileged on Linux/macOS and require `sudo`:

```bash
sudo python3 s7pot.py
```

> **Note:** If port 80 is already in use (e.g. by another web server), the HTTP service automatically falls back to port **8080**. Port 161 falls back to **16161** if not running as root.

### Step 3 — Verify Services Are Listening

```bash
# Check TCP ports (S7comm + HTTP)
lsof -i :102
lsof -i :80

# Check UDP port (SNMP)
lsof -i UDP:161
```

---

## Testing the Honeypot

### Test 1 — Nmap Service Scan

```bash
# Service version detection + Siemens S7 fingerprint
nmap -sV -p 80,102 --script s7-info 127.0.0.1

# Include UDP SNMP
sudo nmap -sU -p 161 127.0.0.1
```

Expected output for port 102:
```
PORT    STATE SERVICE  VERSION
102/tcp open  iso-tsap
| s7-info:
|   Module: 6ES7 214-1AG40-0XB0
|   Module Type: CPU 1214C
|   Serial Number: S C-X4U748823009
|_  System Name: SIMATIC-1200
```

### Test 2 — HTTP Web Portal

```bash
# Generic scan
curl -I http://127.0.0.1/
# Expected: Server: Siemens S7-300 Web Server

# CVE-2019-10929 probe endpoint
curl http://127.0.0.1/Portal/Portal.mwsl
# Expected: HTML with info-leak comment
```

### Test 3 — SNMP

```bash
# Requires net-snmp: brew install net-snmp
snmpwalk -v2c -c public 127.0.0.1
```

### Test 4 — S7comm Read (python-snap7 required)

```bash
pip3 install "python-snap7<3"
```

```python
import snap7, struct
plc = snap7.client.Client()
plc.connect('127.0.0.1', 0, 1)
data = plc.db_read(1, 0, 16)
print(f"Pump : {data[0]}")
print(f"Level: {struct.unpack_from('>f', data, 2)[0]:.1f} L")
print(f"Flag : {data[6]}")
plc.disconnect()
```

---

## Simulating an Attack

> Make sure the honeypot is running before executing any of these.

### Attack 1 — Built-in Single-Step Exploit

Triggers CVE-2021-37185 by writing the crash flag directly:

```bash
python3 attack.py
```

### Attack 2 — Full Automated Attack Chain

Walks through all 5 attack phases with live output:

```bash
python3 full_attack_demo.py

# Against a remote honeypot:
python3 full_attack_demo.py --ip 192.168.1.50
```

Phases executed:
1. **HTTP Recon** — probes web portal and CVE endpoint
2. **S7comm Connect** — connects and enumerates PLC identity
3. **DB Read** — reads live process state from DB1
4. **Exploit** — writes crash flag to bypass ESD
5. **Monitoring** — watches water level climb to overflow

### Manual Exploit Variants

```python
import snap7, struct

plc = snap7.client.Client()
plc.connect('127.0.0.1', 0, 1)

# Trigger ESD bypass (core exploit)
plc.db_write(1, 6, bytearray([1]))

# Inject fake water level (SCADA spoofing)
plc.db_write(1, 2, bytearray(struct.pack('>f', 999.9)))

# Force pump OFF (process disruption)
plc.db_write(1, 0, bytearray([0]))

plc.disconnect()
```

### Reset the Exploit

```python
# Write crash flag back to 0 to restore normal operation
plc.db_write(1, 6, bytearray([0]))
```

---

## Reading the Logs

All events are appended to `logs/interaction.json` as newline-delimited JSON objects.

```bash
# Watch events in real time
tail -f logs/interaction.json

# Pretty-print recent events
tail -n 20 logs/interaction.json | python3 -m json.tool

# Filter by event type
grep "EXPLOIT_TRIGGERED" logs/interaction.json
grep "CONNECTION_DETECTED" logs/interaction.json
```

### Log Event Reference

| `intent` field | Triggered By |
|----------------|-------------|
| `CONNECTION_DETECTED` | Any TCP connection established to port 102 |
| `GENERIC HTTP SCAN` | Any HTTP GET to port 80 |
| `CVE-2019-10929 PROBE` | GET request to `/Portal/Portal.mwsl` |
| `SNMP_SCAN_OR_WALK` | Any UDP packet received on port 161 |
| `DB1_WRITE_DETECTED` | Attacker wrote to any byte in DB1 |
| `EXPLOIT_TRIGGERED` | Crash flag (byte 6) set to 1 |
| `CRITICAL_OVERFLOW_ALARM` | Tank level exceeded 150 L |

### Example Full Attack Log Sequence

```json
{"protocol":"S7COMM","intent":"CONNECTION_DETECTED","source_ip":"192.168.1.5","source_port":54321}
{"protocol":"S7COMM","intent":"DB1_WRITE_DETECTED","byte_offset":2,"old_value":0,"new_value":66}
{"protocol":"S7COMM","intent":"DB1_WRITE_DETECTED","byte_offset":6,"old_value":0,"new_value":1}
{"protocol":"S7COMM","intent":"EXPLOIT_TRIGGERED","details":"CVE-2021-37185 DOS: Memory write bypassed safety logic. Pump forced ON."}
{"protocol":"S7COMM","intent":"CRITICAL_OVERFLOW_ALARM","details":"Tank exceeded 150.0L. ESD triggered.","level_at_esd":154.02}
```

---

## Project Structure

```
s7_snap7_honeypot/
│
├── s7pot.py                 # Main process — snap7 server, physics engine,
│                            #   psutil watcher, subprocess launcher
│
├── services/
│   ├── web_server.py        # HTTP honeypot — Siemens SIMATIC web portal
│   ├── snmp_agent.py        # SNMP honeypot — logs all UDP probes on port 161
│   └── s7_proxy.py         # (Legacy) TCP proxy with latency injection
│                            #   Not used in current architecture
│
├── attack.py                # Minimal single-step CVE-2021-37185 exploit
├── full_attack_demo.py      # Full 5-phase automated attack simulation
├── test_callback.py         # snap7 server callback test utility
│
├── Dockerfile               # Container definition with binary hot-patch
│
└── logs/
    └── interaction.json     # All captured attacker interactions (append-only)
```

---

## How the Deception Works

### 1 — Binary Hot-Patching (Dockerfile)

The Dockerfile patches the compiled `libsnap7.so` C library at build time, replacing hardcoded strings:

| Original string | Replaced with |
|----------------|---------------|
| `SNAP7-SERVER` | `SIMATIC-1200` |
| `6ES7 315-2EH14-0AB0` | `6ES7 214-1AG40-0XB0` |
| `CPU 315-2 PN/DP` | `CPU 1214C` |

This means Nmap's `s7-info` NSE script and attacker enumeration tools receive authentic-looking S7-1200 strings.

### 2 — Live Physics Engine

The water tank simulation runs on a real thread, continuously updating DB1 memory. An attacker who reads the data block sees values that change over time — pump cycling, water level fluctuating — making it indistinguishable from a live PLC process.

### 3 — Write Detection

The physics engine snapshots the memory state after each tick. On the next tick, any byte that differs from the snapshot was written by an external actor (attacker). This is how `DB1_WRITE_DETECTED` events are generated without needing any proxy or middleware.

### 4 — Realistic Network Fingerprint

- Port 102 speaks real ISO-TSAP via the snap7 library — not a TCP banner simulator
- HTTP responses include correct `Server: Siemens S7-300 Web Server` headers
- 80 ms artificial latency (configurable in `s7_proxy.py`) mimics real PLC network timing
