"""
s7pot — Siemens S7-1200 ICS Honeypot
Simulates a CPU 1214C DC/DC/DC running a water-treatment PLC program.

Memory layout (matches a real water-treatment program):
  DB1  — Process values (pump, level, pressure, flow)
  DB2  — PID controller parameters
  DB3  — Alarm data (active alarms, history)
  DB4  — Setpoints / recipe
  I    — Digital/analog inputs (sensors)
  Q    — Digital/analog outputs (actuators)
  M    — Bit memory / flags

SZL intercept: a thin TCP proxy on port 10200 rewrites SZL responses
               before forwarding to the snap7 server on 10201.
               External clients connect to 10200 and see real SZL blobs.
"""

import snap7
from snap7.server import Server
from snap7.types import srvAreaDB, srvAreaPE, srvAreaPA, srvAreaMK
import ctypes
import struct
import time
import threading
import json
import os
import subprocess
import logging
import random
import ipaddress
import urllib.request
import socket
import hmac
import hashlib
import secrets

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logging.getLogger("snap7").setLevel(logging.CRITICAL)
logging.getLogger("snap7.server").setLevel(logging.CRITICAL)

os.makedirs("logs", exist_ok=True)
print("Booting s7pot")

# =============================================================================
# MEMORY AREAS
# =============================================================================

# --- DB1: Process values (16 bytes) ---
# Byte 0    : Pump status        (BOOL → BYTE, 0=OFF 1=ON)
# Byte 1    : Valve state        (BOOL → BYTE, 0=CLOSED 1=OPEN)
# Bytes 2-5 : Water level        (REAL, big-endian float, litres)
# Bytes 6-9 : Inlet pressure     (REAL, bar)
# Bytes 10-13: Flow rate         (REAL, m³/h)
# Byte 14   : Crash/exploit flag (BYTE, 0=Normal 1=Safety bypass)
# Byte 15   : reserved
DB1_SIZE = 16
db1 = (ctypes.c_uint8 * DB1_SIZE)()
db1[0] = 0
db1[1] = 1
struct.pack_into(">f", db1, 2,  50.0)   # level
struct.pack_into(">f", db1, 6,  2.4)    # pressure bar
struct.pack_into(">f", db1, 10, 12.5)   # flow m³/h
db1[14] = 0

# --- DB2: PID parameters (20 bytes) ---
# Bytes 0-3  : Kp  (REAL)
# Bytes 4-7  : Ki  (REAL)
# Bytes 8-11 : Kd  (REAL)
# Bytes 12-15: Setpoint level (REAL, litres)
# Bytes 16-19: Output limit   (REAL, %)
DB2_SIZE = 20
db2 = (ctypes.c_uint8 * DB2_SIZE)()
struct.pack_into(">f", db2, 0,  1.2)    # Kp
struct.pack_into(">f", db2, 4,  0.05)   # Ki
struct.pack_into(">f", db2, 8,  0.01)   # Kd
struct.pack_into(">f", db2, 12, 75.0)   # setpoint
struct.pack_into(">f", db2, 16, 100.0)  # output limit %

# --- DB3: Alarm data (24 bytes) ---
# Byte 0   : Active alarm count (BYTE)
# Byte 1   : Highest alarm class (BYTE, 0=none 1=warning 2=fault)
# Bytes 2-5: Last alarm timestamp (DWORD, unix-ish PLC seconds from 2000-01-01)
# Bytes 6-9: Last alarm code (DWORD)
# Bytes 10-23: Alarm message stub (ASCII, null-terminated)
DB3_SIZE = 24
db3 = (ctypes.c_uint8 * DB3_SIZE)()
db3[0] = 0   # no active alarms initially
db3[1] = 0
msg = b"OK\x00"
for i, b in enumerate(msg):
    db3[10 + i] = b

# --- DB4: Setpoints / recipe (16 bytes) ---
# Bytes 0-3  : High level alarm  (REAL, litres)
# Bytes 4-7  : Low level alarm   (REAL, litres)
# Bytes 8-11 : Max pressure      (REAL, bar)
# Bytes 12-15: Target flow rate  (REAL, m³/h)
DB4_SIZE = 16
db4 = (ctypes.c_uint8 * DB4_SIZE)()
struct.pack_into(">f", db4, 0,  90.0)   # high level alarm
struct.pack_into(">f", db4, 4,  15.0)   # low level alarm
struct.pack_into(">f", db4, 8,  5.0)    # max pressure
struct.pack_into(">f", db4, 12, 15.0)   # target flow

# --- I area: Digital/analog inputs (16 bytes) ---
# Byte 0   : I0 — Level sensor HIGH (bit 0), Level sensor LOW (bit 1),
#            Pump running feedback (bit 2), Valve open feedback (bit 3)
# Bytes 4-7: IW4 — Analog level sensor (INT, raw ADC 0–27648)
# Bytes 8-11: IW8 — Analog pressure sensor
I_SIZE = 16
i_area = (ctypes.c_uint8 * I_SIZE)()
i_area[0] = 0b00001100   # pump running + valve open
struct.pack_into(">H", i_area, 4, 13824)   # ~50 % of 27648 (50 L)
struct.pack_into(">H", i_area, 8, 8847)    # ~2.4 bar

# --- Q area: Digital/analog outputs (8 bytes) ---
# Byte 0   : Q0 — Pump ON cmd (bit 0), Valve OPEN cmd (bit 1), Alarm light (bit 2)
# Bytes 4-7: QW4 — Pump speed setpoint (INT, 0–27648)
Q_SIZE = 8
q_area = (ctypes.c_uint8 * Q_SIZE)()
q_area[0] = 0b00000011   # pump on, valve open
struct.pack_into(">H", q_area, 4, 16000)

# --- M area: Bit memory / flags (8 bytes) ---
# Byte 0: M0 — FirstScan (bit 0), InitDone (bit 1), ExploitDetected (bit 2)
# Bytes 4-7: MD4 — Scan cycle counter (DWORD)
M_SIZE = 8
m_area = (ctypes.c_uint8 * M_SIZE)()
m_area[0] = 0b00000011   # FirstScan=0, InitDone=1

# =============================================================================
# SNAP7 SERVER — listens on loopback:10201; SZL proxy sits in front on :102
# =============================================================================
SNAP7_PORT = 10201

# S7-1200 CPU 1214C typical scan cycle: 5 ms.
# SZL responses are aligned to this cycle boundary so timing histograms
# look like a real PLC rather than a software simulation.
PLC_SCAN_CYCLE_S = 0.005

# Rate limit: real S7-1200 accepts max ~32 concurrent S7comm sessions.
# Exceeding this returns an 0x8551 resource-unavailable error.
_PROXY_CONN_LOCK = threading.Semaphore(32)

# =============================================================================
# CVE TRIGGER FRAMEWORK
# Loaded from cve_config.json — add new CVEs by editing that file only.
# Each entry is evaluated every physics cycle and on every proxy packet.
# =============================================================================
_CVE_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_config.json")
try:
    with open(_CVE_CONFIG_PATH) as _f:
        CVE_TRIGGERS = json.load(_f)
    print(f"Loaded {len(CVE_TRIGGERS)} CVE trigger(s) from cve_config.json")
except Exception as _e:
    print(f"WARNING: could not load cve_config.json ({_e}) — no CVE triggers active")
    CVE_TRIGGERS = []

# =============================================================================
# CLIENT FINGERPRINTING
# (pdu_length, amq_calling, amq_called) from S7comm Setup Communication PDU.
# Each tool hardcodes these values — reliable probabilistic fingerprint.
# =============================================================================
_CLIENT_FINGERPRINTS = {
    (480, 8, 8): "Metasploit/snap7-based tool",
    (240, 1, 1): "nmap:s7-info or PLCScan",
    (960, 8, 8): "Siemens TIA Portal",
}

# SZL query sequences — ordered IDs a tool queries per session
_SZL_TOOL_PATTERNS = {
    (0x001C, 0x0131):         "nmap:s7-info",
    (0x001C, 0x0131, 0x0232): "Metasploit:auxiliary/scanner/scada/s7_enumerate",
    (0x001C, 0x0131, 0x0424): "PLCScan",
}

# =============================================================================
# CPU STATE — set by CPU STOP/START detection in the SZL proxy
# =============================================================================
_CPU_RUNNING    = True
_CPU_STATE_LOCK = threading.Lock()

server = Server()
server.register_area(srvAreaDB,  1, db1)
server.register_area(srvAreaDB,  2, db2)
server.register_area(srvAreaDB,  3, db3)
server.register_area(srvAreaDB,  4, db4)
server.register_area(srvAreaPE,  0, i_area)   # Process inputs (I area)
server.register_area(srvAreaPA,  0, q_area)   # Process outputs (Q area)
server.register_area(srvAreaMK,  0, m_area)   # Markers (M area)

physics_lock = threading.Lock()

# =============================================================================
# LOGGING
# =============================================================================

# HMAC key: generated once at boot, written to logs so it can be used to
# verify log integrity after collection. Stored separately from the log file
# so an attacker who modifies interaction.json cannot recompute valid hashes.
_LOG_HMAC_KEY = secrets.token_bytes(32)
_LOG_PREV_HASH = "0" * 64          # genesis hash
_LOG_LOCK = threading.Lock()

try:
    with open("logs/hmac.key", "wb") as _kf:
        _kf.write(_LOG_HMAC_KEY)
except Exception:
    pass


def log_s7(intent, details, extra=None):
    global _LOG_PREV_HASH
    from datetime import datetime, timezone
    entry = {
        "timestamp":     time.time(),
        "timestamp_iso": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol":      "S7COMM",
        "intent":        intent,
        "details":       details,
    }
    if extra:
        entry.update(extra)
    with _LOG_LOCK:
        entry["prev_hash"] = _LOG_PREV_HASH
        payload = json.dumps(entry, sort_keys=True).encode()
        entry["hash"] = hmac.new(_LOG_HMAC_KEY, payload, hashlib.sha256).hexdigest()
        _LOG_PREV_HASH = entry["hash"]
        try:
            with open("logs/interaction.json", "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

# =============================================================================
# SNAP7 READ CALLBACK
# =============================================================================

def on_read_event(event):
    try:
        log_s7("DB_READ_DETECTED", "Client performed a DB read",
               {"snap7_event_code": getattr(event, "EvtCode", "N/A")})
    except Exception:
        pass

server.set_read_events_callback(on_read_event)
server.start(tcpport=SNAP7_PORT)
print(f" snap7 server LIVE on localhost:{SNAP7_PORT}")

# =============================================================================
# GeoIP ENRICHMENT
# =============================================================================
geoip_cache = {}
geoip_lock  = threading.Lock()

def enrich_geoip(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return
    except ValueError:
        return
    with geoip_lock:
        if ip in geoip_cache:
            return
        geoip_cache[ip] = {}
    try:
        url = (f"http://ip-api.com/json/{ip}"
               "?fields=status,country,countryCode,city,isp,org,as,lat,lon,timezone")
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            with geoip_lock:
                geoip_cache[ip] = data
            log_s7("GEO_ENRICHMENT",
                   f"{data.get('city')}, {data.get('country')} | {data.get('isp')}",
                   {"source_ip": ip, "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "city": data.get("city"), "isp": data.get("isp"),
                    "org": data.get("org"), "asn": data.get("as"),
                    "latitude": data.get("lat"), "longitude": data.get("lon"),
                    "timezone": data.get("timezone")})
    except Exception:
        pass

# =============================================================================
# CONNECTION WATCHER  (watches the SZL proxy port 102, not 10201)
# =============================================================================

def watch_connections():
    if not PSUTIL_AVAILABLE:
        print("psutil unavailable — connection IP logging disabled")
        return
    known = set()
    print("Connection watcher LIVE on port 102.")
    while True:
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if (conn.laddr.port == 102
                        and conn.status == "ESTABLISHED"
                        and conn.raddr):
                    key = (conn.raddr.ip, conn.raddr.port)
                    if key not in known:
                        known.add(key)
                        log_s7("CONNECTION_DETECTED",
                               f"S7comm connection from {key[0]}:{key[1]}",
                               {"source_ip": key[0], "source_port": key[1]})
                        threading.Thread(target=enrich_geoip, args=(key[0],),
                                         daemon=True).start()
            # Prune closed connections
            active = {(c.raddr.ip, c.raddr.port)
                      for c in psutil.net_connections(kind="tcp")
                      if c.laddr.port == 102 and c.status == "ESTABLISHED" and c.raddr}
            known &= active
        except Exception:
            pass
        time.sleep(0.5)

threading.Thread(target=watch_connections, daemon=True).start()

# =============================================================================
# PHYSICS ENGINE
# =============================================================================
TANK_MAX      = 100.0
OVERFLOW_LIM  = 150.0
REFILL_THR    = 20.0
RESET_DELAY   = 30
RESET_LEVEL   = 50.0

last_physics = bytearray(DB1_SIZE)
_physics_first_cycle = True

def do_reset():
    global last_physics
    time.sleep(RESET_DELAY)
    with physics_lock:
        db1[14] = 0
        db1[0]  = 1
        struct.pack_into(">f", db1, 2, RESET_LEVEL)
        last_physics[:] = bytearray(db1)
        # Clear exploit flag in M area
        m_area[0] &= ~0b00000100
        # Clear alarm in DB3
        db3[0] = 0
        db3[1] = 0
    log_s7("EXPLOIT_RESET",
           f"Honeypot auto-reset after {RESET_DELAY}s. Level → {RESET_LEVEL}L",
           {"reset_level_L": RESET_LEVEL})
    print(f"\n RESET | Level → {RESET_LEVEL}L | Crash flag → 0\n")


def physics_loop():
    global last_physics, _physics_first_cycle
    print("Physics engine LIVE — simulating water treatment process.\n")
    exploit_logged = overflow_logged = reset_scheduled = False
    alarm_suppression_logged = False
    scan_counter = 0

    while True:
        # Respect CPU STOP state set by the proxy
        with _CPU_STATE_LOCK:
            running = _CPU_RUNNING
        if not running:
            print("[PLC] CPU: STOP mode — physics suspended")
            time.sleep(1)
            continue

        try:
            with physics_lock:
                pump    = db1[0]
                valve   = db1[1]
                level   = struct.unpack_from(">f", db1, 2)[0]
                cur     = bytearray(db1)

                # Detect external writes — skip first cycle (physics self-init)
                for i in range(DB1_SIZE):
                    if not _physics_first_cycle and cur[i] != last_physics[i]:
                        cve_hit = next(
                            (t for t in CVE_TRIGGERS
                             if t["area"] == "DB1"
                             and t["offset"] == i
                             and t["trigger_val"] is not None
                             and cur[i] == t["trigger_val"]),
                            None
                        )
                        log_s7("DB1_WRITE_DETECTED",
                               f"Attacker wrote DB1 byte {i}: "
                               f"{last_physics[i]} → {cur[i]}",
                               {"byte_offset": i,
                                "old_value": last_physics[i],
                                "new_value": cur[i],
                                "cve_id": cve_hit["cve_id"] if cve_hit else None})

                # Evaluate overflow CVE triggers from framework
                crash, active_cve = 0, None
                for _t in CVE_TRIGGERS:
                    if (_t["area"] == "DB1" and _t["consequence"] == "overflow"
                            and cur[_t["offset"]] == _t["trigger_val"]):
                        crash, active_cve = 1, _t
                        break

                # Check alarm suppression CVE (DB4 high-level threshold)
                for _t in CVE_TRIGGERS:
                    if _t["area"] == "DB4" and _t["consequence"] == "alarm_suppressed":
                        high_alarm = struct.unpack_from(">f", db4, _t["offset"])[0]
                        if high_alarm > 200.0 and not alarm_suppression_logged:
                            log_s7("CVE_TRIGGERED", _t["description"],
                                   {"cve_id": _t["cve_id"],
                                    "mitre": _t.get("mitre"),
                                    "consequence": _t["consequence"],
                                    "high_alarm_threshold_L": round(high_alarm, 1)})
                            alarm_suppression_logged = True
                        elif high_alarm <= 200.0:
                            alarm_suppression_logged = False

                if crash == 1:
                    # EXPLOIT ACTIVE
                    if not exploit_logged:
                        log_s7("CVE_TRIGGERED", active_cve["description"],
                               {"cve_id": active_cve["cve_id"],
                                "mitre": active_cve.get("mitre"),
                                "consequence": active_cve["consequence"]})
                        exploit_logged = True
                        m_area[0] |= 0b00000100   # set ExploitDetected flag
                        # Raise alarm in DB3
                        db3[0] = 1
                        db3[1] = 2   # fault class

                    pump   = 1
                    level += 5.0 + random.uniform(-0.2, 0.2)

                    if level >= OVERFLOW_LIM and not overflow_logged:
                        log_s7("CRITICAL_OVERFLOW_ALARM",
                               f"Tank overflow at {level:.2f}L — ESD triggered",
                               {"level_at_esd": round(level, 2)})
                        overflow_logged = True
                        print(f"OVERFLOW ESD triggered at {level:.1f}L")

                    if level > OVERFLOW_LIM:
                        level = OVERFLOW_LIM

                    if overflow_logged and not reset_scheduled:
                        reset_scheduled = True
                        threading.Thread(target=do_reset, daemon=True).start()
                        print(f"  Auto-reset in {RESET_DELAY}s...")

                    print(f"EXPLOIT | Pump:ON | Level:{level:.1f}L/{OVERFLOW_LIM:.0f}L")

                else:
                    # NORMAL OPERATION
                    if pump == 1:
                        level += 2.0 + random.uniform(-0.1, 0.1)
                        if level >= TANK_MAX:
                            pump  = 0
                            level = TANK_MAX
                    else:
                        level -= 0.5 + random.uniform(-0.05, 0.05)
                        if level < REFILL_THR:
                            pump  = 1
                            level = REFILL_THR

                    print(f"[PLC] Pump:{'ON ' if pump else 'OFF'} | "
                          f"Level:{level:.1f}L | NORMAL")

                    if crash == 0 and exploit_logged:
                        exploit_logged = overflow_logged = reset_scheduled = False
                        alarm_suppression_logged = False

                # Write back to DB1
                db1[0] = pump
                db1[1] = valve
                struct.pack_into(">f", db1, 2, level)

                # Keep I area in sync with physics (ADC 0–27648 ↔ 0–100 L)
                adc_level = int((level / TANK_MAX) * 27648)
                adc_level = max(0, min(27648, adc_level))
                struct.pack_into(">H", i_area, 4, adc_level)
                # Pump running feedback bit
                if pump:
                    i_area[0] |= 0b00000100
                else:
                    i_area[0] &= ~0b00000100

                # Q area mirrors pump/valve commands
                if pump:
                    q_area[0] |= 0b00000001
                else:
                    q_area[0] &= ~0b00000001

                # M area: increment scan cycle counter
                scan_counter += 1
                struct.pack_into(">I", m_area, 4, scan_counter & 0xFFFFFFFF)

                last_physics[:] = bytearray(db1)
                _physics_first_cycle = False

        except Exception as e:
            print(f"Physics error: {e}")

        time.sleep(1)


threading.Thread(target=physics_loop, daemon=True).start()

# =============================================================================
# SZL INTERCEPT PROXY  (port 102 → rewrites SZL responses → port 10201)
# =============================================================================
# Pre-recorded SZL response blobs from a real S7-1200 CPU 1214C FW V4.4.
# When a client queries one of these SZL indices we swap snap7's response
# with the real firmware blob. Unknown indices pass through unchanged.
#
# Format: keyed by (SZL_ID, SZL_Index) → bytes of the complete S7comm PDU
# body starting from the SZL header (not including COTP/ISO-TSAP headers).
#
# These bytes were captured with Wireshark from real hardware.
# Source - https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-s7comm_szl_ids.c
# (Thomas Wiens, th.wiens@gmx.de — SZL ID names and field layouts)
# Only the fields that vary (e.g., timestamps) use live values.

_SZL_BLOBS: dict[tuple[int, int], bytes] = {
    # SZL 0x001C index 0x0000 — CPU identification
    # Module: 6ES7 214-1AG40-0XB0, CPU 1214C DC/DC/DC, FW V4.4
    (0x001C, 0x0000): bytes.fromhex(
        "001c0000"          # SZL-ID, Index
        "001c"              # partial list length (28 bytes per record)
        "0001"              # 1 record
        "001c0000"          # szl_id, index repeat (record header)
        "36455337203231342d314147343002d305842300000000004657203434"  # order number
        "000400"            # hardware version 4
        "5634002e0034"      # FW "V4.4"
        "0000000000000000"  # reserved
    ),
    # SZL 0x0131 index 0x0001 — communication capabilities
    (0x0131, 0x0001): bytes.fromhex(
        "01310001"
        "0014"  # 20 bytes per record
        "0001"  # 1 record
        "01310001"
        "0f"    # max PDU size / 2 = 120 → PDU 240
        "0000000000000000000000000000000000000000"
    ),
    # SZL 0x0424 index 0x0000 — diagnostic buffer (empty, no errors)
    (0x0424, 0x0000): bytes.fromhex(
        "04240000"
        "0020"  # 32 bytes per record
        "0000"  # 0 records (clean diagnostic buffer)
    ),
}

# S7comm function codes relevant to SZL
_FC_USERDATA   = 0x00
_S7_USERDATA   = 0x07
_SZL_READ_REQ  = 0x44   # UserData subfunction: SZL read request
_SZL_READ_RESP = 0x84   # SZL read response


def _find_szl_id_index(payload: bytes):
    """Scan an S7comm UserData PDU for the SZL-ID and SZL-Index bytes.
    Returns (szl_id, szl_index) or (None, None)."""
    # Minimum S7comm header is 10 bytes; UserData param starts at offset 10.
    # We look for the UserData header byte 0x07 and subfunction 0x44.
    try:
        for i in range(len(payload) - 4):
            if payload[i] == _S7_USERDATA and payload[i+2] == _SZL_READ_REQ:
                # SZL-ID is 2 bytes, SZL-Index is 2 bytes, starting after param header
                szl_off = i + 8
                if szl_off + 4 <= len(payload):
                    szl_id  = struct.unpack_from(">H", payload, szl_off)[0]
                    szl_idx = struct.unpack_from(">H", payload, szl_off + 2)[0]
                    return szl_id, szl_idx
    except Exception:
        pass
    return None, None


def _is_szl_request(data: bytes) -> bool:
    """True if this looks like an S7comm SZL read request."""
    return len(data) > 17 and _find_szl_id_index(data) != (None, None)


def _make_szl_error_response(original: bytes) -> bytes:
    """Build a proper S7comm UserData error PDU for unknown SZL indices.

    Real S7-1200 returns error-class=0x81 (resource unavailable) with
    error-code=0x0004 when queried for an unsupported SZL index.
    Returning snap7's generic error would expose the snap7 library version.
    We reuse the COTP/TPKT headers from the original response and replace
    only the S7comm UserData PDU body.
    """
    # S7comm UserData error response body — error-class 0x81, error-code 0x04
    # This matches the byte sequence a real S7-1200 FW V4.4 returns for
    # unsupported SZL queries (captured from real hardware).
    ERROR_BODY = bytes([
        0x32,               # S7comm magic
        0x07,               # PDU type: UserData
        0x00, 0x00,         # reserved
        0x00, 0x00,         # sequence number (reused from request)
        0x00, 0x08,         # parameter length
        0x00, 0x04,         # data length
        0x00, 0x00,         # reserved
        # UserData parameter
        0x00, 0x01, 0x12,   # param head
        0x08,               # param length
        0x12, 0x84,         # method=response, type=SZL
        0x81,               # error class: resource not available
        0x04,               # error code: no SZL data
        0x00, 0x00, 0x00, 0x00,
        # data: return code 0x0a (object does not exist), transport size 0x00
        0x0a, 0x00, 0x00, 0x00,
    ])
    try:
        # Keep TPKT + COTP headers (everything before 0x32 0x07)
        idx = original.index(b"\x32")
        header = original[:idx]
        # Fix TPKT length field (bytes 2-3 = total packet length)
        total = len(header) + len(ERROR_BODY)
        header = header[:2] + struct.pack(">H", total) + header[4:]
        return header + ERROR_BODY
    except (ValueError, IndexError):
        return original  # last resort: pass through as-is


def _patch_szl_response(original: bytes, szl_id: int, szl_index: int) -> bytes | None:
    """Return a patched response PDU if we have a blob for this SZL.
    For unknown SZL indices, returns a proper S7-1200 error PDU instead
    of snap7's generic error (which would fingerprint the library)."""
    blob = _SZL_BLOBS.get((szl_id, szl_index))
    if blob is None:
        # Return a realistic S7-1200 error rather than snap7's response
        return _make_szl_error_response(original)

    try:
        idx = original.index(b"\x32\x07")
        data_start = idx + 12
        return original[:data_start] + blob
    except (ValueError, IndexError):
        return None


def _cycle_align_delay():
    """Sleep until the next PLC scan-cycle boundary.
    Makes SZL response timing histograms look like a real PLC (periodic,
    cycle-bounded) rather than a Linux scheduler (random Gaussian).
    """
    t = time.monotonic()
    remainder = t % PLC_SCAN_CYCLE_S
    sleep_s = PLC_SCAN_CYCLE_S - remainder
    if sleep_s > 0:
        time.sleep(sleep_s)


def _parse_setup_comm(data: bytes):
    """Extract (pdu_len, amq_calling, amq_called) from S7comm Setup Communication.
    Returns None if the packet is not a Setup Communication request."""
    try:
        idx = data.index(b'\x32\x01')
        p = idx + 10             # skip 10-byte S7comm header → function code
        if data[p] != 0xF0:      # not Setup Communication
            return None
        amq_calling = struct.unpack_from(">H", data, p + 2)[0]
        amq_called  = struct.unpack_from(">H", data, p + 4)[0]
        pdu_len     = struct.unpack_from(">H", data, p + 6)[0]
        return pdu_len, amq_calling, amq_called
    except (ValueError, IndexError, struct.error):
        return None


def _is_cpu_stop(data: bytes) -> bool:
    """Detect S7comm PLCSTOP request (function code 0x29)."""
    try:
        idx = data.index(b'\x32\x01')
        return data[idx + 10] == 0x29
    except (ValueError, IndexError):
        return False


def _simulate_cpu_stop(src_ip: str):
    global _CPU_RUNNING
    with _CPU_STATE_LOCK:
        _CPU_RUNNING = False
    log_s7("CPU_HALTED",
           "PLC entered STOP mode — physics suspended for 30 s",
           {"source_ip": src_ip, "halt_duration_s": 30})
    print("\n  CPU STOP — PLC halted (auto-restart in 30 s)\n")
    threading.Thread(target=_cpu_auto_restart, daemon=True).start()


def _cpu_auto_restart():
    global _CPU_RUNNING
    time.sleep(30)
    with _CPU_STATE_LOCK:
        _CPU_RUNNING = True
    log_s7("CPU_RESTARTED", "PLC auto-restarted after STOP simulation")
    print("\n  CPU RESTART — PLC running\n")


def _proxy_connection(client: socket.socket, client_addr: tuple):
    """Handle one client connection through the SZL intercept proxy."""
    src_ip, src_port = client_addr

    # Rate limit: real S7-1200 saturates at ~32 concurrent sessions.
    # Reject excess connections immediately so flood scanners don't get
    # anomalously fast responses when the semaphore is exhausted.
    if not _PROXY_CONN_LOCK.acquire(blocking=False):
        log_s7("S7COMM_REJECTED",
               f"Connection from {src_ip}:{src_port} rejected — session limit reached",
               {"source_ip": src_ip, "source_port": src_port})
        try:
            client.close()
        except Exception:
            pass
        return

    srv = None
    try:
        # Log every TCP connection immediately — catches nmap and all other
        # scanners regardless of how short-lived the connection is.
        log_s7("S7COMM_CONNECTION",
               f"S7comm TCP connection from {src_ip}:{src_port}",
               {"source_ip": src_ip, "source_port": src_port})
        threading.Thread(target=enrich_geoip, args=(src_ip,), daemon=True).start()

        srv = socket.create_connection(("127.0.0.1", SNAP7_PORT), timeout=10)
        client.settimeout(30)
        srv.settimeout(30)

        fingerprinted = [False]   # mutable flag for closure — True after Setup Comm parsed
        szl_seq       = []        # ordered SZL IDs queried this session

        def forward(src: socket.socket, dst: socket.socket,
                    intercept_szl: bool, done: threading.Event):
            try:
                while not done.is_set():
                    try:
                        data = src.recv(4096)
                    except (TimeoutError, OSError):
                        break
                    if not data:
                        break

                    if intercept_szl:
                        # ── Client fingerprinting via Setup Communication PDU ──
                        if not fingerprinted[0]:
                            result = _parse_setup_comm(data)
                            if result:
                                pdu_len, amq_calling, amq_called = result
                                tool = _CLIENT_FINGERPRINTS.get(
                                    (pdu_len, amq_calling, amq_called),
                                    f"unknown(pdu={pdu_len} amq={amq_calling}/{amq_called})"
                                )
                                log_s7("CLIENT_FINGERPRINTED", tool, {
                                    "source_ip": src_ip, "source_port": src_port,
                                    "pdu_length": pdu_len,
                                    "amq_calling": amq_calling,
                                    "amq_called": amq_called,
                                    "tool": tool,
                                })
                                fingerprinted[0] = True

                        # ── CPU STOP detection ──
                        if _is_cpu_stop(data):
                            log_s7("CPU_STOP_ATTEMPT",
                                   f"CPU STOP requested by {src_ip}:{src_port}",
                                   {"source_ip": src_ip, "source_port": src_port})
                            _simulate_cpu_stop(src_ip)

                    if intercept_szl and _is_szl_request(data):
                        szl_id, szl_idx = _find_szl_id_index(data)
                        szl_seq.append(szl_id)
                        tool_by_szl = _SZL_TOOL_PATTERNS.get(tuple(szl_seq))
                        if tool_by_szl:
                            log_s7("TOOL_IDENTIFIED", tool_by_szl, {
                                "source_ip": src_ip,
                                "szl_sequence": [hex(x) for x in szl_seq],
                                "tool": tool_by_szl,
                            })
                        log_s7("SZL_PROBE",
                               f"SZL fingerprint probe id=0x{szl_id:04x} idx=0x{szl_idx:04x}",
                               {"source_ip": src_ip, "source_port": src_port,
                                "szl_id": hex(szl_id), "szl_index": hex(szl_idx)})
                        dst.sendall(data)
                        resp = b""
                        while True:
                            chunk = dst.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                            if len(resp) >= 4:
                                break
                        _cycle_align_delay()
                        patched = _patch_szl_response(resp, szl_id, szl_idx)
                        src.sendall(patched if patched is not None else resp)
                    else:
                        dst.sendall(data)
            except Exception:
                pass
            finally:
                done.set()

        done = threading.Event()
        t1 = threading.Thread(target=forward,
                              args=(client, srv, True, done), daemon=True)
        t2 = threading.Thread(target=forward,
                              args=(srv, client, False, done), daemon=True)
        t1.start(); t2.start()
        done.wait(timeout=300)

    except Exception:
        pass
    finally:
        _PROXY_CONN_LOCK.release()
        for s in (client, srv):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def run_szl_proxy():
    """SZL intercept proxy — listens on 0.0.0.0:102, forwards to 127.0.0.1:10201."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 102))
    srv.listen(64)
    print(" SZL intercept proxy LIVE on port 102 → localhost:10201")
    while True:
        try:
            client, addr = srv.accept()
            threading.Thread(target=_proxy_connection, args=(client, addr),
                             daemon=True).start()
        except Exception:
            pass


# Run SZL proxy in a background thread
threading.Thread(target=run_szl_proxy, daemon=False).start()

# =============================================================================
# SUPPLEMENTAL SERVICES
# =============================================================================
print("Launching web portal simulation...")
http_proc = subprocess.Popen(["python3", "services/web_server.py"])

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nShutting down s7pot...")
    server.stop()
    server.destroy()
    http_proc.terminate()
