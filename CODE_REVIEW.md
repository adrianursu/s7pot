# s7pot — Code Review & Improvement Guide

A per-file breakdown of every library used, every function written, what was implemented, and what can be improved.

---

## Table of Contents

1. [`s7pot.py` — Main Process](#1-s7potpy--main-process)
2. [`services/web_server.py` — HTTP Honeypot](#2-servicesweb_serverpy--http-honeypot)
3. [`services/snmp_agent.py` — SNMP Honeypot](#3-servicessnmp_agentpy--snmp-honeypot)
4. [`services/s7_proxy.py` — TCP Proxy (Legacy)](#4-servicess7_proxypy--tcp-proxy-legacy)
5. [`attack.py` — Minimal Exploit Script](#5-attackpy--minimal-exploit-script)
6. [`full_attack_demo.py` — Full Attack Chain](#6-full_attack_demopy--full-attack-chain)
7. [`test_callback.py` — Callback Unit Test](#7-test_callbackpy--callback-unit-test)
8. [Cross-Cutting Improvements](#cross-cutting-improvements)

---

## 1. `s7pot.py` — Main Process

The entry point. Boots all subsystems: S7comm server, physics engine, connection watcher, GeoIP enrichment, and subprocess launchers for HTTP and SNMP.

### Libraries

| Library | Why it's used |
|---|---|
| `snap7` / `snap7.server.Server` / `snap7.type.SrvArea` | Wraps the native `libsnap7.so` C library to run a real ISO-TSAP server on port 102. Registers shared memory areas that a real S7 client can read/write. |
| `ctypes` | Allocates a C-compatible `c_uint8` array (`db1_memory`) that `libsnap7` reads directly from memory — no serialisation overhead. |
| `struct` | Packs/unpacks a 32-bit IEEE 754 big-endian float (`>f`) into `db1_memory` bytes 2–5 for the water-level value. |
| `threading` | Runs the physics engine and connection watcher as daemon threads. Also used to spawn async GeoIP lookups and the auto-reset timer. |
| `time` | `time.sleep()` for tick control. `time.time()` for Unix timestamps in log entries. |
| `json` | Serialises structured log entries to newline-delimited JSON (NDJSON). |
| `os` | `os.makedirs("logs", exist_ok=True)` — ensures the log directory exists before any write. |
| `subprocess` | `subprocess.Popen` launches `web_server.py` and `snmp_agent.py` as independent OS processes so they each own their own socket. |
| `logging` | Silences snap7's internal C-library log noise via `setLevel(logging.CRITICAL)`. |
| `random` | Adds ±0.1–0.2 L of jitter to every physics tick so water-level data does not look artificially smooth. |
| `ipaddress` | `ipaddress.ip_address(ip).is_private` — skips GeoIP lookups for RFC 1918 / loopback addresses. |
| `urllib.request` | Makes HTTP GET requests to `ip-api.com` for GeoIP enrichment. Used instead of `requests` to keep dependencies minimal. |
| `psutil` | `psutil.net_connections(kind='tcp')` — inspects the OS TCP table to detect new `ESTABLISHED` connections on port 102 without a proxy. Optional; degrades gracefully if missing. |

### Functions

#### `on_read_event(event)`
- **What it does:** snap7 callback registered via `server.set_read_events_callback()`. Fires every time a client calls `db_read`. Logs a `DB1_READ_DETECTED` entry.
- **Improvement:** The `event` object exposes `EvtCode`, `EvtRetCode`, and `SenderHandle` — all currently discarded. Log them for richer reconnaissance telemetry.

#### `log_s7_interaction(intent, details, extra=None)`
- **What it does:** Appends a structured JSON line to `logs/interaction.json`. Builds a base dict (`timestamp`, `timestamp_iso`, `protocol`, `intent`, `details`) and merges any `extra` fields.
- **Improvements:**
  - File is opened and closed on every call. Use a module-level `logging.handlers.RotatingFileHandler` with a custom JSON formatter for better I/O performance and automatic log rotation.
  - `from datetime import datetime, timezone` is re-imported on every call. Move to module level.
  - No log rotation: `interaction.json` grows unboundedly in production.

#### `enrich_with_geoip(ip)`
- **What it does:** Async GeoIP lookup via `ip-api.com`. Skips private IPs and already-seen IPs (using `geoip_cache`). On success, logs a `GEO_ENRICHMENT` entry with country, city, ISP, ASN, lat/lon, and timezone.
- **Improvements:**
  - `ip-api.com` enforces a 45 req/min rate limit. Consider [`maxmind/geoip2-python`](https://github.com/maxmind/geoip2-python) with a local GeoLite2 database for unlimited, offline, sub-millisecond lookups.
  - `geoip_cache` is never evicted — it grows indefinitely in long-running deployments. Add a max-size cap (e.g., an `OrderedDict` with a fixed size) or a TTL.
  - Under a heavy scan, this can spawn hundreds of threads. Gate with `threading.Semaphore(10)`.

#### `watch_connections()`
- **What it does:** Polls `psutil.net_connections` every 500 ms. Detects new `ESTABLISHED` TCP connections on port 102. Logs each new `(ip, port)` as `CONNECTION_DETECTED` and spawns a GeoIP thread per unique IP.
- **Improvements:**
  - 500 ms polling can miss very short-lived connections from Nmap SYN scans or Masscan. A raw-socket or `iptables LOG` + parser approach would be zero-miss.
  - When psutil is unavailable, only stdout is notified. Write a structured `WATCHER_UNAVAILABLE` event to `interaction.json` so operators have a record.

#### `do_exploit_reset()`
- **What it does:** Sleeps `RESET_DELAY_SEC` (30 s) then acquires `physics_lock` and restores DB1: crash flag → 0, pump → ON, level → 50 L. Updates `last_physics_state` to prevent a false `DB1_WRITE_DETECTED` on the next physics tick.
- **Improvements:**
  - Uses `time.sleep()` inside the thread. A `threading.Event.wait(timeout)` would allow clean cancellation on `KeyboardInterrupt`.
  - `RESET_DELAY_SEC` is a hardcoded constant. Expose it as an environment variable for Docker flexibility.

#### `physics_loop()`
- **What it does:** Daemon thread ticking every 1 second. Reads DB1 via `ctypes`, computes the next water level, detects attacker writes by diffing against `last_physics_state`, and simulates two modes: **NORMAL** (pump cycles 20–100 L) and **EXPLOIT** (pump locked ON, level climbs to 150 L). Schedules `do_exploit_reset` on overflow.
- **Improvements:**
  - The write-detection loop iterates all 16 bytes with Python. A `bytes(current_raw) != bytes(last_physics_state)` short-circuit check first would skip the per-byte loop most ticks.
  - `random.uniform(-0.2, 0.2)` gives uniform noise. `random.gauss(0, 0.1)` would be more physically realistic.
  - No unit tests for the state-machine logic. Add `pytest` tests that mock `db1_memory` and verify NORMAL → EXPLOIT → RESET transitions.

---

## 2. `services/web_server.py` — HTTP Honeypot

Simulates a Siemens SIMATIC S7-300 Web Server on port 80 (fallback: 8080).

### Libraries

| Library | Why it's used |
|---|---|
| `http.server` + `SimpleHTTPRequestHandler` | Standards-compliant HTTP/1.0 handler with minimal boilerplate. |
| `socketserver.TCPServer` | Base class for the server; subclassed into `QuietTCPServer`. |
| `logging` | Structured stdout messages. |
| `json` | NDJSON log entries. |
| `time` | `time.time()` for log timestamps. |
| `os` | Ensures `logs/` directory exists. |

### Functions / Classes

#### `HoneypotHTTPRequestHandler` (extends `SimpleHTTPRequestHandler`)

- `log_interaction(intent, details)` — writes a JSON log entry with source IP, port, protocol, path, and intent.
- `do_GET()` — routes `/Portal/Portal.mwsl` to a CVE-2019-10929 simulated info-leak response; all other paths get a generic S7 portal page. Both respond with `Server: Siemens S7-300 Web Server`.
- `log_message(format, *args)` — overridden to suppress Apache-style access log spam on stdout.

**Improvements:**
- Only `GET` is handled. Adding `do_POST`, `do_HEAD`, `do_PUT` (even as empty loggers) would capture credentials POSTed by credential-stuffing tools and SOAP payloads.
- HTML responses are hardcoded bytes. Real Siemens portals serve multi-page JS apps — even a minimal static HTML with `<frame>` tags fools more scanners.
- Response lacks `Date:` and `Content-Length` headers, which real HTTP servers always send. Adding them improves fingerprint fidelity.
- `log_interaction` opens the log file on every request — same bottleneck as `s7pot.py`. Use a shared `RotatingFileHandler`.

#### `QuietTCPServer` (extends `socketserver.TCPServer`)
- **What it does:** `allow_reuse_address = True`. Silently drops `ConnectionResetError` and `BrokenPipeError` from scanner-induced connection drops.
- **Improvement:** The `import sys` is inside `handle_error`. Move to module level.

#### `run_web_server()`
- **What it does:** Binds to `0.0.0.0:80`, falls back to 8080 on `OSError`. Serves forever.
- **Improvement:** Only one fallback is tried. A `for port in [80, 8080, 8000]:` loop is more robust. Log the final port to `interaction.json`.

---

## 3. `services/snmp_agent.py` — SNMP Honeypot

Listens on UDP port 161 (fallback: 16161) and logs all incoming packets as hex payloads.

### Libraries

| Library | Why it's used |
|---|---|
| `socket` | Raw `SOCK_DGRAM` UDP socket — captures any SNMP packet without a full SNMP stack. |
| `json` | NDJSON log entries. |
| `time` | `time.time()` for timestamps. |
| `logging` | Structured stdout messages. |
| `os` | `logs/` directory creation. |
| `binascii` | `binascii.hexlify(data)` — encodes raw UDP payload bytes as a hex string. |

### Functions

#### `log_interaction(addr, port, hex_payload)`
- **What it does:** Writes a single `SNMP_SCAN_OR_WALK` JSON entry with source IP, port, and hex payload.
- **Improvements:**
  - All packets get the same `intent`. Parse the BER/DER PDU type byte (offset 7 in a standard SNMP packet) to distinguish `GetRequest`, `GetNextRequest`, `GetBulkRequest`, `SetRequest`, and `Trap` — each tells you something different about attacker intent.
  - Decode and log the SNMP community string (plaintext in SNMPv1/v2c). Attackers often try non-standard strings; capturing them is high-value intelligence.

#### `run_snmp_agent()`
- **What it does:** Binds UDP socket. Falls back to 16161. Loops `recvfrom(2048)` indefinitely.
- **Improvements:**
  - Sends no response — `nmap --script snmp-info` and `snmpwalk` will not show the honeypot as a live device. Sending a static pre-crafted BER-encoded `GetResponse` with fake Siemens OIDs (e.g., `sysDescr = "Siemens CP343-1"`) would dramatically improve realism.
  - `recvfrom(2048)` may truncate large bulk-walk packets. 4096 bytes is safer.

---

## 4. `services/s7_proxy.py` — TCP Proxy (Legacy)

> **Not active in the current architecture.** Kept for reference. The main process connects snap7 directly to port 102.

A transparent TCP proxy that forwards traffic between port 102 (attacker) and a backend snap7 server on port 10200, injecting 80 ms of artificial latency.

### Libraries

| Library | Why it's used |
|---|---|
| `socket` | TCP sockets for both the attacker-facing and backend connections. |
| `select` | `select.select()` for non-blocking multiplexed I/O between both sockets. |
| `time` | `time.sleep(LATENCY_SEC)` — injects latency on the first client packet. |
| `json` | NDJSON logging. |
| `os` | `logs/` directory creation. |
| `threading` | Daemon thread per accepted client connection. |

### Functions

#### `log_interaction(ip_address, data_size)`
- Only the first packet of each session is logged, and only its size. Log full hex payload too.

#### `handle_client(client_socket, addr)`
- **What it does:** Relays data bidirectionally. Injects latency on first packet. Cleans up in `finally`.
- **Improvements:** Bare `except Exception: pass` silently swallows mid-session errors. No socket timeout — stalled connections hold threads open indefinitely. Use `socket.settimeout(30)`.

#### `run_proxy()`
- **What it does:** Accepts connections on `PROXY_PORT`, dispatches to `handle_client` on a daemon thread.
- **Improvement:** Unbounded thread creation under scan storms. Use `concurrent.futures.ThreadPoolExecutor(max_workers=50)`.

---

## 5. `attack.py` — Minimal Exploit Script

Single-step CVE-2021-37185 simulation: connects as an S7 client and writes `0x01` to DB1.DBB6.

### Libraries

| Library | Why it's used |
|---|---|
| `snap7` | `snap7.client.Client` — `connect`, `db_write`, `disconnect`. |

### What it does

1. Instantiates an S7 client and connects to `127.0.0.1` (rack 0, slot 1).
2. Writes `bytearray([1])` to DB1 byte 6 (the crash flag).
3. Disconnects. The physics engine detects the flag and enters exploit mode.

### Improvements

- No post-write verification. Add `plc.db_read(1, 6, 1)` to confirm the byte was accepted.
- Target IP is hardcoded. Accept `--ip` as a CLI arg (`argparse`).
- Missing `if __name__ == "__main__":` guard and no docstring.
- No `finally` block — if `connect()` succeeds but `db_write()` raises, `disconnect()` is never called.

---

## 6. `full_attack_demo.py` — Full Attack Chain

Walks through all 5 attacker phases with a live CLI display.

### Libraries

| Library | Why it's used |
|---|---|
| `sys` | Parses the `--ip` CLI argument via `sys.argv`. |
| `snap7` | S7comm client — `connect`, `get_cpu_info`, `db_read`, `db_write`, `disconnect`. |
| `struct` | `struct.unpack_from('>f', data, 2)` — decodes the big-endian float water level. |
| `time` | Phase delays and monitoring poll interval. |
| `urllib.request` | HTTP GET for the recon phase. |

### Phases

| Phase | What it does |
|---|---|
| 1 — HTTP Recon | GETs `/` and `/Portal/Portal.mwsl`; prints status code, `Server` header, checks for info-leak text. |
| 2 — S7 Connect | `Client.connect(target, 0, 1)` then `get_cpu_info()` to print module type, serial, and AS name. |
| 3 — DB Read | `db_read(1, 0, 16)` decodes pump status, water level, and crash flag. |
| 4 — Exploit | `db_write(1, 6, bytearray([1]))` triggers the ESD bypass. |
| 5 — Monitoring | Polls DB1 every second for 12 s; renders an ASCII progress bar and prints an ESD alarm at ≥ 150 L. |

### Improvements

- `sys.argv[sys.argv.index("--ip") + 1]` raises `IndexError` if `--ip` is the last token. Use `argparse`.
- The info-leak check (`if "leaked" in body`) is fragile. The actual HTML contains `"Configuration payload leaked"`. Use `re.search` or a more specific substring.
- The progress bar `int(level / 5)` can mathematically exceed 30. Clamp with `max(0, min(30, int(level / 5)))`.
- No `finally` block to call `plc.disconnect()` on exception.
- Phase 2 silently swallows `get_cpu_info()` exceptions — print them for debugging.

---

## 7. `test_callback.py` — Callback Unit Test

Sanity-check that verifies the snap7 read-event callback fires on a `db_read`.

### Libraries

| Library | Why it's used |
|---|---|
| `snap7` | Boots a `Server`, sets a callback, connects a `Client`, calls `db_read`. |
| `time` | `time.sleep(1)` — waits for the callback thread to fire before stopping. |

### Improvements

- No assertion — pass/fail requires eyeballing stdout. Convert to `pytest` with `unittest.mock.patch` asserting the callback was called.
- No DB area registered before the read. Register a dummy buffer so the server can satisfy the request cleanly.
- No `if __name__ == "__main__":` guard — importing in a test suite executes the full sequence immediately.

---

## Cross-Cutting Improvements

### Logging

| Issue | Suggestion |
|---|---|
| Every function opens `interaction.json` individually | Use a single named `logging.Logger` with a `RotatingFileHandler` (e.g., 10 MB × 5 files) and a custom `JSONFormatter`. |
| No schema validation on log entries | Define a `dataclass` or `TypedDict` for log entries to enforce consistent field names. |
| Two timestamp formats | Standardise on ISO 8601 with UTC timezone everywhere. |

### Configuration

All thresholds and ports are hardcoded. A `config.yaml` or environment-variable layer allows tuning per deployment:

```yaml
physics:
  tank_max_capacity: 100.0
  overflow_threshold: 150.0
  refill_threshold: 20.0
  reset_delay_sec: 30
  tick_interval_sec: 1.0

ports:
  s7comm: 102
  http: 80
  snmp: 161
```

### Concurrency

| Current | Improvement |
|---|---|
| Raw `threading.Thread` per GeoIP lookup | Cap with `threading.Semaphore(10)` to prevent thread storms under heavy scanning. |
| No pool limit on `s7_proxy.py` connections | Use `ThreadPoolExecutor(max_workers=50)`. |
| `physics_lock` is undocumented | Add a comment documenting lock ordering to prevent future deadlocks. |

### Security of the Honeypot Itself

| Risk | Mitigation |
|---|---|
| Outbound `ip-api.com` calls from the honeypot host reveal its internet presence | Use a local MaxMind GeoLite2 database. |
| `interaction.json` is world-readable by default | Add `chmod 600 logs/interaction.json` in the Dockerfile entrypoint. |
| `subprocess.Popen` leaks service stdout/stderr to the terminal | Redirect with `stdout=subprocess.DEVNULL` or pipe to a log file. |
| GeoIP threads have no upper bound | Gate with a `Semaphore`. |
