# s7pot.py — Complete Technical Explanation

## Table of Contents

1. [What problem does this file solve?](#1-what-problem-does-this-file-solve)
2. [Background: what is a PLC and why does it matter for security?](#2-background-what-is-a-plc-and-why-does-it-matter-for-security)
3. [Background: what is a honeypot?](#3-background-what-is-a-honeypot)
4. [The S7comm protocol stack](#4-the-s7comm-protocol-stack)
5. [Memory areas — the PLC's data model](#5-memory-areas--the-plcs-data-model)
6. [The snap7 server](#6-the-snap7-server)
7. [The CVE trigger framework](#7-the-cve-trigger-framework)
8. [Client fingerprinting](#8-client-fingerprinting)
9. [CPU state management](#9-cpu-state-management)
10. [Logging with HMAC chain integrity](#10-logging-with-hmac-chain-integrity)
11. [GeoIP enrichment](#11-geoip-enrichment)
12. [Connection watcher](#12-connection-watcher)
13. [Physics engine — the water treatment simulation](#13-physics-engine--the-water-treatment-simulation)
14. [The SZL intercept proxy — the core technical contribution](#14-the-szl-intercept-proxy--the-core-technical-contribution)
15. [The web server subprocess](#15-the-web-server-subprocess)
16. [How all components interact at runtime](#16-how-all-components-interact-at-runtime)
17. [What an attacker sees at each stage](#17-what-an-attacker-sees-at-each-stage)

---

## 1. What problem does this file solve?

s7pot.py is the core of a **research honeypot** that impersonates a Siemens SIMATIC S7-1200 Programmable Logic Controller (PLC) — specifically a **CPU 1214C DC/DC/DC running firmware version 4.4**. Its purpose is to be deployed on the public internet, attract real attackers and automated scanners targeting industrial control systems, and collect structured data about their behaviour, tools, and geographic origin.

The key challenge is **deception fidelity**: an attacker or scanner must be unable to distinguish the honeypot from a real device. If they can tell it is a honeypot, they will disconnect and the interaction is lost. Every design choice in this file exists to maintain that deception.

---

## 2. Background: what is a PLC and why does it matter for security?

A **Programmable Logic Controller (PLC)** is a small, specialised computer used in industrial environments to control physical processes — manufacturing lines, water treatment plants, electrical substations, oil pipelines. Unlike a general-purpose computer, a PLC runs continuously in a tight loop (called a **scan cycle**, typically 1–100 ms), reading sensors, executing a control program, and writing commands to actuators.

The **Siemens SIMATIC S7-1200** is one of the most widely deployed PLC families in the world. It is used in water treatment, building automation, food production, and many other critical infrastructure sectors. Siemens assigns it the article number **6ES7 214-1AG40-0XB0** — this is the specific model identifier encoded in the honeypot's responses.

PLCs were historically air-gapped (physically disconnected from the internet). Over the past 15 years, operational technology (OT) networks have increasingly been connected to corporate IT networks and, in many cases, to the internet directly. The search engine **Shodan** indexes over 100,000 Siemens S7 devices reachable on the public internet. This exposure is the threat this honeypot is designed to study.

The most famous ICS attack is **Stuxnet** (2010), a sophisticated worm that targeted Siemens S7-315 PLCs at Iran's Natanz uranium enrichment facility. It exploited the S7comm protocol to read and write PLC memory while hiding its modifications from the operators' screens. Later attacks — **Industroyer** (Ukraine power grid, 2016) and **TRITON/TRISIS** (Saudi petrochemical safety systems, 2017) — used similar techniques: connect to the PLC over its engineering protocol, read memory to understand the process, then write crafted values to cause physical damage or disable safety systems.

---

## 3. Background: what is a honeypot?

A **honeypot** is a system that deliberately presents itself as a legitimate target to attract attackers, with the goal of studying their methods. Unlike intrusion detection, a honeypot generates no false positives: any interaction with it is, by definition, malicious or scanning activity, because no legitimate user should ever connect to it.

For ICS honeypots specifically, the goal is to understand **who is scanning industrial protocols on the internet, what tools they use, and whether any attackers go beyond passive scanning to active exploitation**. This data informs defenders about the real-world threat landscape facing industrial systems.

The challenge unique to ICS honeypots is that industrial protocols are highly specialised. An attacker using an ICS-specific tool (such as a snap7-based Python script) can probe the PLC with protocol-level queries that a generic honeypot cannot answer correctly. If the response does not match what a real Siemens device would return, the attacker's tool will either error out or flag the device as non-genuine. **s7pot must respond correctly at the byte level to every standard probe.**

---

## 4. The S7comm protocol stack

Understanding the protocol is essential to understanding the code. S7comm does not run directly over TCP. It uses four nested layers:

```
TCP (port 102)
  └── TPKT  (RFC 1006 — adds a 4-byte length header)
        └── COTP  (ISO 8073 — connection-oriented transport, handles session setup)
              └── S7comm  (Siemens proprietary — the actual PLC commands)
```

**Port 102** is the IANA-assigned port for ISO-TSAP, the transport layer S7comm rides on. This is the port that Siemens TIA Portal (the engineering software), nmap's `s7-info` script, PLCScan, Shodan, and Metasploit's `s7_enumerate` module all connect to when targeting an S7 device. It is the primary attack surface.

**S7comm function codes** are the commands within the S7comm layer. The important ones for this honeypot:

| Code | Name | What it does |
|------|------|--------------|
| `0xF0` | Setup Communication | Negotiates PDU size and session parameters — the handshake |
| `0x04` | Read Variable | Reads bytes from a memory area (e.g. DB1) |
| `0x05` | Write Variable | Writes bytes to a memory area |
| `0x29` | PLCSTOP | Commands the CPU to halt (enter STOP mode) |
| `0x07` | UserData | Container for SZL queries and other diagnostic functions |

Within UserData, **SZL (System-Zustands-Liste, "System Status List")** is a Siemens-specific read-only directory of device information: the CPU order number, firmware version, communication parameters, diagnostic buffer. SZL responses are the primary source of device identification — every scanner queries them first.

---

## 5. Memory areas — the PLC's data model

### What memory areas are

A real S7-1200 stores all of its data in structured memory areas. These are not files — they are fixed byte arrays mapped to physical I/O or used by the control program. When an attacker connects with a tool like snap7's Python client, they can read and write these areas using standard S7comm Read Variable / Write Variable function codes.

The honeypot defines seven memory areas. Each is a raw C byte array (`ctypes.c_uint8 * SIZE`) because the snap7 library requires a C-compatible memory pointer — it cannot use a Python list or bytearray directly.

```python
db1 = (ctypes.c_uint8 * DB1_SIZE)()
```

This line allocates a C array of 16 unsigned bytes, zero-initialised. The `ctypes` module is Python's foreign function interface — it lets Python manage memory in the same way that a C program would, which is necessary because snap7 is a compiled C library.

### DB1 — Process values (16 bytes)

This is the most important memory block. It holds the live state of the simulated water treatment process.

```
Byte 0     : Pump status (0=OFF, 1=ON)
Byte 1     : Valve state (0=CLOSED, 1=OPEN)
Bytes 2–5  : Water level in litres (IEEE 754 big-endian REAL)
Bytes 6–9  : Inlet pressure in bar (IEEE 754 big-endian REAL)
Bytes 10–13: Flow rate in m³/h (IEEE 754 big-endian REAL)
Byte 14    : Exploit/safety-bypass flag (0=Normal, 1=Bypass)
Byte 15    : Reserved
```

**Why floats are encoded as `">f"`:** Siemens PLCs use big-endian byte order (most significant byte first) for all multi-byte values. This matches the Motorola convention, not the Intel convention. `struct.pack_into(">f", db1, 2, 50.0)` encodes the float 50.0 in big-endian IEEE 754 format and writes it into bytes 2–5 of the array.

**Why these values specifically:** The initial values (50.0 L level, 2.4 bar pressure, 12.5 m³/h flow) are realistic for a small water treatment process. An attacker who reads DB1 and looks at these values should conclude this is a real installation, not a test device. A tank at 50% capacity with a pump filling it is a completely normal operational state.

**Byte 14 — the exploit lure:** This byte has no counterpart in a standard water treatment program. It simulates a memory location that a CVE describes as exploitable — writing `1` to it bypasses the pump safety interlock. This is the trigger for CVE-2021-37185 (see Section 7). The design deliberately makes this byte readable (so an attacker discovers it exists) but does not advertise what it does — they must understand the CVE or experiment.

### DB2 — PID controller parameters (20 bytes)

A PID (Proportional-Integral-Derivative) controller is the standard algorithm for maintaining a setpoint in a physical process. In a real water treatment plant, a PID controller would regulate pump speed to maintain the tank level at a target value. DB2 contains the tuning parameters: Kp (proportional gain), Ki (integral gain), Kd (derivative gain), the target setpoint, and an output limit.

This block exists to make the memory layout look like a genuine engineering installation, not a demonstration. A real water treatment PLC program would have exactly this kind of data block. It is not actively used by the physics engine (the engine uses simpler bang-bang control for simplicity) but it is readable — an attacker who reads DB2 sees sensible PID values, confirming the "this is a real plant" narrative.

### DB3 — Alarm data (24 bytes)

Real PLCs maintain an alarm system. DB3 simulates this:

```
Byte 0     : Count of currently active alarms (starts at 0 — no alarms)
Byte 1     : Severity class (0=none, 1=warning, 2=fault)
Bytes 2–5  : Timestamp of last alarm
Bytes 6–9  : Alarm code
Bytes 10–23: ASCII alarm message, null-terminated ("OK\0" at startup)
```

The initial message `b"OK\x00"` is written byte-by-byte:
```python
msg = b"OK\x00"
for i, b in enumerate(msg):
    db3[10 + i] = b
```

When the exploit is triggered, the physics engine sets `db3[0] = 1` (one active alarm) and `db3[1] = 2` (fault class) to simulate the PLC detecting the safety bypass. This makes the alarm state consistent with the physical state — an attacker who reads both DB1 and DB3 after triggering the exploit will see a coherent picture.

### DB4 — Setpoints / recipe (16 bytes)

This block contains the operational thresholds:

```
Bytes 0–3  : High level alarm threshold (90.0 L — triggers if tank overflows)
Bytes 4–7  : Low level alarm threshold  (15.0 L — triggers if tank runs dry)
Bytes 8–11 : Maximum pressure alarm     (5.0 bar)
Bytes 12–15: Target flow rate           (15.0 m³/h)
```

DB4 is the target for the second CVE (CVE-2022-38465, alarm suppression). An attacker who writes a very high value to bytes 0–3 (e.g. 9999.0 L) raises the high-level alarm threshold so high that the overflow alarm can never fire — the alarm is silenced while the tank overflows. This is a classic ICS attack pattern (used in Stuxnet: suppress safety signals while causing physical damage).

### I area — Process inputs / sensor readings (16 bytes)

In a real PLC, the I (Input) area is continuously refreshed from physical sensor hardware at the start of each scan cycle. The honeypot simulates this:

```
Byte 0      : Digital inputs as bit flags (pump running bit, valve open bit, etc.)
Bytes 4–5   : IW4 — Analog level sensor reading (integer, 0–27648 raw ADC units)
Bytes 8–9   : IW8 — Analog pressure sensor reading
```

**Why 27648?** Siemens S7 PLCs use 27648 as the full-scale value for analog inputs. It is the integer representation of 100% — so a water level of 50 L out of a 100 L maximum maps to an ADC reading of `(50/100) * 27648 = 13824`. This is the exact scaling used in real Siemens programs and documented in the S7-1200 system manual.

The physics engine updates this area every second, converting the live level value back to an ADC integer:
```python
adc_level = int((level / TANK_MAX) * 27648)
struct.pack_into(">H", i_area, 4, adc_level)
```

An attacker who reads the I area (which a real SCADA system would) sees sensor values that track the DB1 process values — the two representations are always consistent.

### Q area — Process outputs / actuator commands (8 bytes)

The Q (Output) area controls actuators. In a real PLC, writing to Q bits drives physical relay outputs (turning on a motor contactor, opening a valve solenoid).

```
Byte 0, bit 0 : Pump ON command
Byte 0, bit 1 : Valve OPEN command
Byte 0, bit 2 : Alarm indicator light
Bytes 4–5     : Pump speed setpoint (integer, 0–27648)
```

Initial state: `0b00000011` = bits 0 and 1 set = pump on and valve open, which is consistent with DB1 showing a filling process.

### M area — Marker / flag memory (8 bytes)

The M (Marker) area is general-purpose flag memory — the PLC equivalent of global variables.

```
Byte 0, bit 0 : FirstScan flag (0 = first scan has happened — set during init)
Byte 0, bit 1 : InitDone flag  (1 = initialisation complete)
Byte 0, bit 2 : ExploitDetected flag (set when an exploit trigger fires)
Bytes 4–7     : MD4 — scan cycle counter (32-bit integer, incremented every second)
```

Initial value: `0b00000011` — FirstScan=0 (done), InitDone=1 (ready). The scan cycle counter at MD4 is important: a real PLC increments this every scan cycle (every 5 ms). The honeypot increments it every physics loop iteration (every 1 second). An attacker who reads MD4 twice will see it increasing — confirming an active, running CPU. The increment rate is slower than a real PLC but it is non-zero, which is the key distinguishing factor from a static honeypot.

---

## 6. The snap7 server

### What snap7 is

`snap7` is the only mature open-source S7comm server implementation. It is a compiled C library originally written for use as an S7 client (to communicate with real PLCs from Linux). It also provides a server mode that accepts S7comm connections and serves registered memory areas.

```python
server = Server()
server.register_area(srvAreaDB, 1, db1)   # register DB1
server.register_area(srvAreaDB, 2, db2)   # register DB2
...
server.start(tcpport=SNAP7_PORT)           # listen on localhost:10201
```

`register_area` takes three arguments: the area type (DB, PE for inputs, PA for outputs, MK for markers), the area number, and the C array. snap7 holds a pointer to that array — when an attacker's S7comm Read Variable request arrives asking for DB1, snap7 reads from the array and returns the current bytes. When a Write Variable arrives, snap7 writes the new bytes into the array. This shared-memory arrangement is why the physics engine and the server can both access the same `db1` array without coordination beyond a mutex.

### Why snap7 runs on port 10201, not port 102

Port 102 is the standard S7comm port and what all scanners probe. But snap7's responses contain a fingerprint problem: when asked for SZL (device information) queries, snap7 returns its own internal values — wrong order numbers, wrong firmware versions, and generic error responses that no real S7-1200 would produce. Running snap7 directly on port 102 would cause nmap's `s7-info` script to return snap7's internal strings, immediately exposing the honeypot.

The solution is to run snap7 on the internal port `10201` (not accessible from outside the container) and put a custom TCP proxy on port `102` that intercepts SZL queries before they reach snap7, replaces snap7's responses with correct firmware blobs, and forwards everything else unchanged. This proxy is the SZL intercept proxy, described in Section 14.

### The read callback

```python
def on_read_event(event):
    log_s7("DB_READ_DETECTED", "Client performed a DB read", ...)

server.set_read_events_callback(on_read_event)
```

snap7 fires this callback whenever any client reads a DB area. This is how the honeypot distinguishes a passive scanner (which only sends SZL queries and never reads memory) from an active attacker (who reads DB1 to observe the process). The log entry `DB_READ_DETECTED` is one of the most important signals in the dataset: it marks the transition from reconnaissance to active interaction.

---

## 7. The CVE trigger framework

### What a CVE is

A **CVE (Common Vulnerabilities and Exposures)** is a standardised identifier for a publicly disclosed security vulnerability. For example, CVE-2021-37185 is an arbitrary memory write vulnerability in Siemens S7-1200 firmware that allows an unauthenticated attacker to write to protected memory areas via S7comm.

### The framework design

Rather than hardcoding specific exploit behaviours directly into the Python code, the honeypot loads exploit definitions from an external JSON file:

```json
[
  {
    "cve_id": "CVE-2021-37185",
    "title": "S7comm Memory Manipulation — Safety Interlock Bypass",
    "description": "Writing 1 to DB1 byte 14 bypasses the pump safety interlock...",
    "area": "DB1",
    "offset": 14,
    "trigger_val": 1,
    "consequence": "overflow",
    "mitre": "T0831"
  },
  {
    "cve_id": "CVE-2022-38465",
    "title": "Setpoint Manipulation — Silent Alarm Suppression",
    "area": "DB4",
    "offset": 0,
    "trigger_val": null,
    "consequence": "alarm_suppressed",
    "mitre": "T0836"
  }
]
```

Each entry specifies:
- **area**: which memory block to watch (DB1, DB4, etc.)
- **offset**: which byte within that block is the trigger
- **trigger_val**: what value the byte must be set to to activate the CVE (`null` means any non-default value)
- **consequence**: what the physics engine should do when triggered
- **mitre**: the MITRE ATT&CK for ICS technique ID (T0831 = Manipulation of Control, T0836 = Modify Parameter)

At startup, the file is loaded:
```python
with open(_CVE_CONFIG_PATH) as _f:
    CVE_TRIGGERS = json.load(_f)
```

The physics engine then evaluates all entries generically — it does not contain CVE-specific code. To add a new CVE, only `cve_config.json` needs to be edited. The code does not change. This is the "framework" property: the framework evaluates rules; the rules are data.

### Why this design was chosen

Fully automatic CVE simulation (where you give the system a CVE number and it generates the exploit) is not feasible. CVE descriptions in the NVD (National Vulnerability Database) are written in natural language and do not specify protocol-level details like which memory offset to target. That knowledge requires ICS protocol expertise. What the framework does automate is: once a researcher has determined the exploit parameters, they can add the CVE without touching any Python code. The framework also auto-fetches CVE metadata (description, CVSS severity, CWE) from the NVD API at startup, so the log entries contain rich context.

---

## 8. Client fingerprinting

### The Setup Communication negotiation

When any S7comm client connects, the very first packet it sends (after the TCP and COTP handshakes) is a **Setup Communication PDU**. This packet negotiates three parameters:

- **PDU length**: the maximum size of a single S7comm packet the client can handle
- **AMQ Calling**: maximum number of concurrent unacknowledged requests the client will send
- **AMQ Called**: maximum number the client expects the server to handle

These values are **hardcoded in every tool's source code**. Different tools use different values, and those values are stable across versions. This makes them a reliable fingerprint:

```python
_CLIENT_FINGERPRINTS = {
    (480, 8, 8): "Metasploit/snap7-based tool",
    (240, 1, 1): "nmap:s7-info or PLCScan",
    (960, 8, 8): "Siemens TIA Portal",
}
```

When the proxy receives the Setup Communication packet, it parses out these three values:
```python
def _parse_setup_comm(data: bytes):
    idx = data.index(b'\x32\x01')   # find S7comm header
    p = idx + 10                    # skip to function code
    if data[p] != 0xF0:             # 0xF0 = Setup Communication
        return None
    amq_calling = struct.unpack_from(">H", data, p + 2)[0]
    amq_called  = struct.unpack_from(">H", data, p + 4)[0]
    pdu_len     = struct.unpack_from(">H", data, p + 6)[0]
    return pdu_len, amq_calling, amq_called
```

The result is logged as `CLIENT_FINGERPRINTED` with the tool name. This allows the thesis dataset to attribute each session to a specific tool category without having to rely on IP reputation or banner analysis.

### SZL query sequence fingerprinting

Beyond the Setup Communication, each tool queries a characteristic sequence of SZL IDs. The proxy tracks the ordered list of SZL IDs queried within a session:

```python
_SZL_TOOL_PATTERNS = {
    (0x001C, 0x0131):         "nmap:s7-info",
    (0x001C, 0x0131, 0x0232): "Metasploit:auxiliary/scanner/scada/s7_enumerate",
    (0x001C, 0x0131, 0x0424): "PLCScan",
}
```

When a session's accumulated SZL sequence matches one of these patterns, the tool is identified and logged. Combined with the PDU fingerprint, this provides two independent signals for the same attribution — if they agree, confidence is high.

---

## 9. CPU state management

A real Siemens PLC can be commanded to enter **STOP mode** via a specific S7comm function code (`0x29`, PLCSTOP). In STOP mode, the CPU halts its scan cycle, all outputs go to a safe default state, and the process stops. This is a significant attack: stopping a water treatment PLC could deprive a town of water, or allow a tank to overflow.

The proxy detects this command:
```python
def _is_cpu_stop(data: bytes) -> bool:
    try:
        idx = data.index(b'\x32\x01')
        return data[idx + 10] == 0x29
    except (ValueError, IndexError):
        return False
```

When detected, a global flag is set:
```python
_CPU_RUNNING    = True
_CPU_STATE_LOCK = threading.Lock()
```

The physics engine checks this flag at the start of every iteration. If `_CPU_RUNNING` is False, it skips all updates and logs `[PLC] CPU: STOP mode — physics suspended`. After 30 seconds, `_cpu_auto_restart()` sets it back to True — simulating the standard Siemens auto-restart behaviour. The interaction is logged as `CPU_HALTED` with the attacker's IP and the halt duration.

A threading lock (`_CPU_STATE_LOCK`) protects the flag because both the proxy (which sets it) and the physics engine (which reads it) run in separate threads. Without the lock, one thread could read a partially-written value — a standard concurrent programming hazard called a race condition.

---

## 10. Logging with HMAC chain integrity

### The log format

Every security event produces a JSON log entry written to `logs/interaction.json`, one entry per line (NDJSON format, compatible with log aggregation tools like Grafana Loki):

```json
{
  "timestamp": 1716844800.123,
  "timestamp_iso": "2024-05-27T12:00:00Z",
  "protocol": "S7COMM",
  "intent": "DB_READ_DETECTED",
  "details": "Client performed a DB read",
  "prev_hash": "a3f9...",
  "hash": "7b2c..."
}
```

The `intent` field is the primary classification signal. The values used are:

| Intent | What it means |
|--------|---------------|
| `S7COMM_CONNECTION` | A TCP connection was established to port 102 |
| `CLIENT_FINGERPRINTED` | Setup Communication PDU identified the tool |
| `SZL_PROBE` | Client queried SZL device information |
| `TOOL_IDENTIFIED` | SZL sequence matched a known tool pattern |
| `DB_READ_DETECTED` | Client read a data block (active interaction) |
| `DB1_WRITE_DETECTED` | Client wrote to DB1 (potential exploitation) |
| `CVE_TRIGGERED` | A CVE trigger condition was met |
| `CRITICAL_OVERFLOW_ALARM` | The tank overflow threshold was reached |
| `CPU_STOP_ATTEMPT` | PLCSTOP command received |
| `CPU_HALTED` | Physics engine suspended |
| `CPU_RESTARTED` | Physics engine resumed after 30 s |
| `GEO_ENRICHMENT` | Geographic location of attacker IP resolved |
| `CREDENTIAL_SUBMISSION` | HTTP POST to the web portal login form |

### HMAC chain integrity

Standard log files can be tampered with by an attacker who gains filesystem access — they could delete entries, modify timestamps, or remove evidence of their own activity. The honeypot implements a **hash chain** to make tampering detectable.

At startup, a 32-byte random key is generated and stored in a separate file:
```python
_LOG_HMAC_KEY = secrets.token_bytes(32)
with open("logs/hmac.key", "wb") as _kf:
    _kf.write(_LOG_HMAC_KEY)
```

Before writing each log entry, its JSON is serialised with keys in a canonical sorted order, and an HMAC-SHA256 digest is computed:
```python
payload = json.dumps(entry, sort_keys=True).encode()
entry["hash"] = hmac.new(_LOG_HMAC_KEY, payload, hashlib.sha256).hexdigest()
```

Each entry also includes the hash of the previous entry (`prev_hash`). This creates a chain: entry N's `prev_hash` equals entry N−1's `hash`. The genesis entry uses `"0" * 64` as the sentinel.

To verify the chain after collection, a verifier recomputes each HMAC using the stored key and checks that each `prev_hash` matches the hash of the entry before it. Any insertion, deletion, or modification breaks the chain at that point. This is the same principle used in blockchain data structures, applied here for forensic log integrity.

**Why this matters:** Neither HoneyPLC (CCS 2020) nor HoneyICS (ARES 2023) implement log integrity. If the honeypot is compromised, the logs remain trustworthy evidence.

The `_LOG_LOCK` ensures that `_LOG_PREV_HASH` is updated atomically — if two events occur simultaneously on different threads, only one writes at a time, preventing chain corruption.

---

## 11. GeoIP enrichment

Every new connection triggers an asynchronous geographic lookup:

```python
def enrich_geoip(ip):
    if ipaddress.ip_address(ip).is_private:
        return   # skip RFC1918 addresses — they have no geographic data
    ...
    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,lat,lon"
    resp = urllib.request.urlopen(url, timeout=5)
```

The lookup runs in a separate thread (`daemon=True`) so it never blocks the main proxy thread. The result enriches the log entry with country, city, ISP name, ASN (autonomous system number), latitude, longitude, and timezone.

**Why this is research-relevant:** Country and ASN attribution transforms a list of IP addresses into structured threat intelligence. An ASN identifies the organisation that owns the IP block — distinguishing a university research scanner (ASN belonging to an academic institution) from a cloud-hosted automated scanner (ASN belonging to AWS or DigitalOcean) from a state-attributed network. This data feeds the thesis analysis chapter.

The `geoip_cache` dictionary prevents repeated lookups for the same IP. The `geoip_lock` protects it from simultaneous access from multiple threads.

---

## 12. Connection watcher

```python
def watch_connections():
    while True:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.laddr.port == 102 and conn.status == "ESTABLISHED":
                ...log and enrich...
        time.sleep(0.5)
```

`psutil` (Process Utilities) is a cross-platform Python library that can query the operating system's network stack. The watcher polls active TCP connections to port 102 every 500 ms, logging any new ones with their source IP and port. It also prunes its `known` set when connections close, so a reconnect from the same IP is logged again.

**Why this exists in addition to the proxy's own logging:** The proxy logs connections when it handles them. The watcher provides a secondary log source and catches edge cases — for example, connections that complete the TCP handshake but send no S7comm data (a common technique in stealthy scanners that check if a port is open without sending application-layer data).

---

## 13. Physics engine — the water treatment simulation

### Why a physics engine is necessary

This is arguably the most important contribution for deception fidelity. Consider what happens without it:

1. Attacker connects to the honeypot
2. Attacker reads DB1 — gets {level=50.0, pressure=2.4, flow=12.5}
3. Attacker waits 10 seconds
4. Attacker reads DB1 again — gets exactly {level=50.0, pressure=2.4, flow=12.5}

Identical values. No real PLC running a water treatment process would ever have a static level, static pressure, and static flow. The attacker concludes this is a static honeypot and disconnects. Conpot (the most widely deployed ICS honeypot) has this exact problem — its memory areas never change.

The physics engine prevents this by running a continuous simulation:

### The simulation model

```python
TANK_MAX     = 100.0   # litres — normal operating maximum
OVERFLOW_LIM = 150.0   # litres — overflow threshold (exploit scenario)
REFILL_THR   = 20.0    # litres — pump turns on when level drops below this
```

Normal operation (bang-bang control):
- If the pump is ON, level increases by 2.0 ± 0.1 L per second
- When level reaches 100 L, the pump turns OFF
- Level drains at 0.5 ± 0.05 L per second (simulating water usage)
- When level drops to 20 L, the pump turns ON again

The small random noise (`random.uniform(-0.1, 0.1)`) is important. Without it, the values would cycle in a perfectly regular saw-tooth pattern, which is not realistic and could be detected by an observer watching values over time. Real physical processes have sensor noise.

### CVE trigger scenario

When the exploit byte (DB1[14]) is set to 1:

```python
pump   = 1            # force pump on regardless of level
level += 5.0 + random.uniform(-0.2, 0.2)   # accelerated fill rate
```

The pump is forced ON and level climbs at 5 L/s — far above the normal 2 L/s. When level reaches 150 L, an `CRITICAL_OVERFLOW_ALARM` is logged and the `ESD` (Emergency Shutdown) is described as triggered. The auto-reset fires after 30 seconds, returning the system to normal. This simulates the documented consequence of CVE-2021-37185: uncontrolled actuator state leading to a process upset.

### Write detection

At the start of every physics cycle, the current DB1 is compared byte-by-byte against the state from the previous cycle:

```python
for i in range(DB1_SIZE):
    if cur[i] != last_physics[i]:
        ...log DB1_WRITE_DETECTED...
```

If any byte changed and the physics engine didn't change it itself (tracked via `last_physics`), the change must have come from an external write — an attacker using a Write Variable command. The CVE framework is queried to check if the change matches a trigger, and the log entry includes the CVE ID if it does.

### The `physics_lock` mutex

```python
physics_lock = threading.Lock()
```

Both the physics engine and the snap7 server can access `db1` simultaneously: the engine writes new values, while snap7 reads the array to serve client requests. Without a lock, a read could occur while a write is half-complete — for example, a 4-byte float written two bytes at a time might produce a garbled intermediate value. The `with physics_lock:` block ensures the engine has exclusive access during each update cycle.

### Known limitation

The physics loop runs at 1 Hz (`time.sleep(1)`) — one update per second. A real S7-1200 scan cycle is 5 ms (200 Hz). This means the DB1 update frequency is approximately 200× slower than a real PLC. This is an acknowledged software limitation: reliable sub-100 ms Python threads require a real-time operating system. Process values are numerically correct (the physics model is accurate); only the update rate is an approximation.

---

## 14. The SZL intercept proxy — the core technical contribution

This is the most complex and most important component of the honeypot. It is what makes s7pot distinguishable from a naive snap7 deployment.

### The problem it solves

When `nmap --script s7-info` connects to an S7 device, it sends three specific SZL queries:
1. SZL ID `0x001C` — "Component Identification" — returns the CPU order number (e.g. `6ES7 214-1AG40-0XB0`), hardware revision, and firmware version
2. SZL ID `0x0131` — "Communication capability parameters" — returns PDU limits
3. SZL ID `0x0424` — "Current mode transition" — the diagnostic buffer

A real S7-1200 CPU 1214C running FW V4.4 returns specific byte sequences for each query. snap7, when acting as a server, returns its own internal values for these queries — wrong order number, wrong firmware string, and a generic error format that no real S7-1200 would produce. A single `nmap -O` would immediately expose the honeypot.

### The architecture

```
External attacker
        │
        ▼
  ┌─────────────────────────────┐
  │  SZL Intercept Proxy        │  ← runs on 0.0.0.0:102 (external)
  │  _proxy_connection()        │
  │  - fingerprints clients     │
  │  - detects CPU STOP         │
  │  - patches SZL responses    │
  │  - rate-limits connections  │
  └─────────────────────────────┘
        │ plain S7comm (everything except SZL)
        │ patched SZL responses (our blobs, not snap7's)
        ▼
  ┌─────────────────────────────┐
  │  snap7 server               │  ← runs on 127.0.0.1:10201 (internal only)
  │  - handles R/W variable     │
  │  - serves DB1–DB4, I, Q, M  │
  └─────────────────────────────┘
```

### The SZL blobs

The proxy contains pre-constructed byte sequences for the three SZL IDs that scanners query. These are stored as hexadecimal strings:

```python
_SZL_BLOBS = {
    (0x001C, 0x0000): bytes.fromhex(
        "001c0000"      # SZL-ID and index
        "001c"          # partial list length (28 bytes per record)
        "0001"          # 1 record follows
        "001c0000"      # record header (SZL-ID and index repeated)
        "36455337203231342d314147343002d305842300000000004657203434"
                        # order number: "6ES7 214-1AG40...FW V44"
        "000400"        # hardware version 4
        "5634002e0034"  # firmware string "V4.4"
        "0000000000000000"  # reserved padding
    ),
    ...
}
```

These byte values were constructed according to the field layout documented by Thomas Wiens in `packet-s7comm_szl_ids.c` (the Wireshark S7comm dissector) and cross-validated against the field expectations of nmap's `s7-info.nse` script. They are not byte-for-byte copies of a physical device capture — they are constructed from the documented protocol structure.

### The patching mechanism

When a client sends an SZL query, the proxy intercepts it by identifying the SZL-ID and SZL-Index in the packet:

```python
def _find_szl_id_index(payload: bytes):
    for i in range(len(payload) - 4):
        if payload[i] == _S7_USERDATA and payload[i+2] == _SZL_READ_REQ:
            szl_off = i + 8
            szl_id  = struct.unpack_from(">H", payload, szl_off)[0]
            szl_idx = struct.unpack_from(">H", payload, szl_off + 2)[0]
            return szl_id, szl_idx
```

It then forwards the query to snap7 and waits for snap7's (wrong) response. Before returning that response to the client, it replaces snap7's S7comm body with the correct blob:

```python
def _patch_szl_response(original: bytes, szl_id: int, szl_index: int):
    blob = _SZL_BLOBS.get((szl_id, szl_index))
    if blob is None:
        return _make_szl_error_response(original)   # return realistic error
    idx = original.index(b"\x32\x07")    # find start of S7comm body
    data_start = idx + 12
    return original[:data_start] + blob  # keep TPKT/COTP headers, replace body
```

The TPKT and COTP headers are kept from snap7's response (so the packet framing is correct), but the S7comm UserData body is replaced with the honeypot's blob. The client receives a correctly-framed packet with the right firmware identification.

For unknown SZL indices (ones not in `_SZL_BLOBS`), the proxy constructs a realistic error response instead of passing through snap7's generic error. The error uses error-class `0x81` (resource unavailable) and error-code `0x04`, which is the specific byte sequence a real S7-1200 FW V4.4 returns for unsupported SZL queries.

### Cycle-aligned response timing

```python
def _cycle_align_delay():
    t = time.monotonic()
    remainder = t % PLC_SCAN_CYCLE_S    # PLC_SCAN_CYCLE_S = 0.005 s
    sleep_s = PLC_SCAN_CYCLE_S - remainder
    time.sleep(sleep_s)
```

A real PLC does not respond to SZL queries instantly. The S7-1200 CPU runs on a VxWorks RTOS with a 5 ms scan cycle. Responses are only dispatched at cycle boundaries. This means that if you measure the time between sending an SZL request and receiving the response on a real device, the histogram is **periodic** — values cluster at multiples of 5 ms.

On a Linux server, without this delay, responses arrive in <1 ms with a Gaussian distribution around the CPU scheduler jitter. A sophisticated timing-based detection tool could use this to distinguish a real PLC from a software simulation. The `_cycle_align_delay()` call waits until the next 5 ms boundary, making the honeypot's timing histogram look periodic rather than Gaussian.

This is applied only to SZL responses (the queries that timing-sensitive fingerprinting tools use). Read/write variable responses pass through without added delay.

### Rate limiting — 32 concurrent sessions

```python
_PROXY_CONN_LOCK = threading.Semaphore(32)

if not _PROXY_CONN_LOCK.acquire(blocking=False):
    client.close()   # reject — limit exceeded
    return
```

A real S7-1200 CPU 1214C supports a maximum of approximately 32 concurrent S7comm sessions. This is documented in the hardware specification. A Linux server can handle thousands of concurrent TCP connections. If a flood scanner opens 200 simultaneous connections and they all succeed, the device is immediately exposed as non-genuine (a real PLC would reject connections beyond 32 with error code `0x8551`).

The `Semaphore(32)` is a counting lock that allows at most 32 simultaneous `_proxy_connection()` handlers. The 33rd connection attempt finds the semaphore exhausted (`acquire(blocking=False)` returns False immediately) and is logged as `S7COMM_REJECTED` with the reason "session limit reached" before the socket is closed.

### The bidirectional forwarding loop

Each accepted connection spawns two threads:
```python
t1 = threading.Thread(target=forward, args=(client, srv, True, done))   # client → snap7
t2 = threading.Thread(target=forward, args=(srv, client, False, done))  # snap7 → client
```

`t1` (intercept_szl=True) receives data from the external client. It performs fingerprinting, CPU STOP detection, and SZL query interception before forwarding to snap7. `t2` (intercept_szl=False) passes snap7's responses straight back to the client — except when t1 has intercepted an SZL query, in which case t1 handles the full round-trip itself (sends to snap7, receives, patches, and returns to the client) so t2 never sees that exchange.

The `done` threading.Event is set by either thread when its socket closes or errors. The main handler waits on `done.wait(timeout=300)` — the connection is forcibly cleaned up after 300 seconds maximum, preventing thread leaks from idle connections.

---

## 15. The web server subprocess

```python
http_proc = subprocess.Popen(["python3", "services/web_server.py"])
```

The HTTP web server runs as a separate Python process, not a thread. This provides process isolation: if the web server crashes (for example, due to a malformed HTTP request), the S7comm honeypot continues running. The web server simulates the Siemens S7-1200's integrated web portal — specifically the `/Portal/Portal.mwsl` endpoint that is the subject of CVE-2019-10929 (configuration data disclosure without authentication in unpatched firmware).

Key design points of the web server:
- It is a **raw TCP socket server**, not Python's `http.server`. The reason is header control: Python's SimpleHTTPRequestHandler sends headers in its own order and with its own version string. Fingerprinting tools like Shodan's HTTP banner analyser and `httprint` would immediately identify it as Python, not as a Siemens device. The raw socket approach allows complete control over the header order and content.
- The `Server:` header is `Siemens HTTP Server` (the real value from FW V4.4 captures)
- Credential submissions to the login form are always rejected (matching real patched firmware) and logged with the attempted username and password
- The **teapot dashboard** at `/DataLogs/sysdiag` (accessible only from localhost — external requests receive the landing page) renders a live HTML table of the top 10 attempted usernames and passwords, with counts

---

## 16. How all components interact at runtime

On startup, s7pot.py does the following in order:

1. Allocates all memory areas (DB1–DB4, I, Q, M) as C arrays
2. Loads CVE triggers from `cve_config.json`
3. Defines client fingerprint tables
4. Creates the snap7 server, registers all memory areas, starts it on port 10201
5. Generates the HMAC key and starts the log file
6. Registers the read callback with snap7
7. Starts the GeoIP enrichment function (called on-demand, not a thread itself)
8. Starts the connection watcher thread (psutil polling every 500 ms)
9. Starts the physics engine thread (updates DB1 every 1 second)
10. Starts the SZL intercept proxy in a non-daemon thread on port 102
11. Launches the web server as a subprocess on port 80
12. Enters the main loop (`while True: time.sleep(1)`) waiting for KeyboardInterrupt

At runtime, the active concurrent threads are:
- **Main thread**: sleeps, waiting for shutdown signal
- **snap7 internal threads** (managed by the snap7 library): handle TCP on port 10201
- **Physics engine thread**: updates DB1, detects writes, evaluates CVE triggers
- **Connection watcher thread**: polls psutil every 500 ms
- **SZL proxy accept thread**: calls `srv.accept()` in a loop
- **Per-connection proxy threads** (up to 32 pairs): each active S7comm session has two threads (t1 forward and t2 forward)
- **GeoIP threads** (short-lived): spawned per new IP, live for one HTTP request

---

## 17. What an attacker sees at each stage

This section traces a complete attack session through the honeypot, mapping each step to the code component that handles it and the log entries produced.

### Stage 1: Passive scanning (automated scanner, no human operator)

The scanner (e.g. Shodan, ZMap/ZGrab, or nmap) connects to port 102 and sends SZL queries.

1. TCP connection → `_proxy_connection()` starts → `S7COMM_CONNECTION` logged
2. GeoIP lookup starts in background thread → `GEO_ENRICHMENT` logged (within ~2 s)
3. Scanner sends Setup Communication → PDU values parsed → `CLIENT_FINGERPRINTED` logged
4. Scanner sends SZL 0x001C query → proxy intercepts → correct blob returned → `SZL_PROBE` logged
5. Scanner sends SZL 0x0131 query → proxy intercepts → correct blob returned → `SZL_PROBE` logged
6. SZL sequence matches `(0x001C, 0x0131)` → `TOOL_IDENTIFIED: nmap:s7-info` logged
7. Scanner disconnects. No DB reads, no writes.

**Net result:** Shodan indexes the honeypot as a Siemens CPU 1214C DC/DC/DC running FW V4.4. The thesis dataset captures the scan event with full geographic attribution.

### Stage 2: Active reconnaissance (human attacker with snap7 Python client)

The attacker, having seen the device on Shodan, connects with a snap7 Python script to read the process data:

1. Connection established → same as Stage 1
2. Attacker calls `client.db_read(1, 0, 16)` (read DB1, 16 bytes)
3. snap7 internal handler fires → `on_read_event` callback → `DB_READ_DETECTED` logged
4. Attacker receives DB1: pump=ON, level=73.4 L, pressure=2.4 bar, flow=12.5 m³/h
5. Attacker waits 10 seconds and reads again: level=75.2 L (physics engine advanced it)
6. Attacker sees live, changing values and concludes this is a real, active plant

**Net result:** The attacker is engaged with the honeypot. The physics engine has prevented passive detection.

### Stage 3: Exploitation attempt

The attacker, having read DB1 and understood byte 14 is a "safety bypass flag" (from the CVE description or experimentation), writes `1` to it:

1. Attacker calls `client.db_write(1, 14, bytearray([1]))` (write byte 14 of DB1 to 1)
2. snap7 writes the value into the `db1` C array
3. Next physics cycle: `cur[14] != last_physics[14]` → `DB1_WRITE_DETECTED` logged with `cve_id: "CVE-2021-37185"`
4. CVE trigger evaluation: offset=14, trigger_val=1, consequence="overflow" → matches
5. `CVE_TRIGGERED` logged with MITRE T0831
6. Physics enters exploit mode: pump forced ON, level climbs 5 L/s
7. Level reaches 150 L → `CRITICAL_OVERFLOW_ALARM` logged
8. After 30 seconds: `do_reset()` fires → `EXPLOIT_RESET` logged → system returns to normal

**Net result:** The thesis dataset captures a complete exploitation event: the specific CVE triggered, the memory write that caused it, the process consequence, and the attacker's IP with geographic attribution.
