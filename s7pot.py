import snap7
from snap7.server import Server
from snap7.type import SrvArea
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

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Suppress snap7 C-library logs
logging.getLogger("snap7").setLevel(logging.CRITICAL)
logging.getLogger("snap7.server").setLevel(logging.CRITICAL)

os.makedirs("logs", exist_ok=True)

print("Booting s7pot")

# --- 1. MEMORY SETUP (Data Block 1) ---
DB_NUMBER = 1
DB_SIZE = 16
db1_memory = (ctypes.c_uint8 * DB_SIZE)()

db1_memory[0] = 0                            # Byte 0: Pump status (0=OFF, 1=ON)
struct.pack_into('>f', db1_memory, 2, 50.0)  # Bytes 2-5: Water level (L, big-endian float)
db1_memory[6] = 0                            # Byte 6: Crash flag (0=Normal, 1=EXPLOIT)

# --- 2. S7 SERVER SETUP (direct on port 102 — no proxy, so Nmap s7-info works) ---
server = Server()
server.register_area(SrvArea.DB, DB_NUMBER, db1_memory)

# --- READ LOGGING via snap7 native callback ---
# Fires every time a client performs a DB read — captures silent reconnaissance.
def on_read_event(event):
    """Called by snap7 whenever a client reads from any registered area."""
    try:
        log_s7_interaction(
            "DB1_READ_DETECTED",
            "Attacker performed a DB read (reconnaissance)",
            {"snap7_event_code": getattr(event, 'EvtCode', 'N/A')}
        )
    except Exception:
        pass

server.set_read_events_callback(on_read_event)

server.start(tcp_port=102)
print(" S7comm Server LIVE on Port 102.")

# Lock for thread-safe access to db1_memory
physics_lock = threading.Lock()

def log_s7_interaction(intent, details, extra=None):
    from datetime import datetime, timezone
    log_entry = {
        "timestamp":     time.time(),
        "timestamp_iso": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol":      "S7COMM",
        "intent":        intent,
        "details":       details
    }
    if extra:
        log_entry.update(extra)
    try:
        with open("logs/interaction.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception:
        pass

# --- 3. GeoIP ENRICHMENT ---
# ip-api.com: free, no API key, 45 req/min limit.
# Lookups are async (daemon threads) and cached per IP.
geoip_cache = {}              # ip -> enrichment dict
geoip_cache_lock = threading.Lock()

def enrich_with_geoip(ip):
    """Async GeoIP lookup for a single attacker IP.
    Writes a GEO_ENRICHMENT log entry. Silently no-ops on any failure."""
    # Skip private / loopback / link-local addresses
    try:
        if ipaddress.ip_address(ip).is_private:
            return
    except ValueError:
        return

    # Skip if already enriched for this IP
    with geoip_cache_lock:
        if ip in geoip_cache:
            return
        geoip_cache[ip] = {}      # reserve slot immediately to prevent duplicate calls

    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,city,isp,org,as,lat,lon,timezone"
        )
        req  = urllib.request.urlopen(url, timeout=5)
        data = json.loads(req.read().decode())

        if data.get("status") == "success":
            with geoip_cache_lock:
                geoip_cache[ip] = data

            log_s7_interaction(
                "GEO_ENRICHMENT",
                f"Attacker geolocated: {data.get('city', '?')}, {data.get('country', '?')} "
                f"| ISP: {data.get('isp', '?')} | ASN: {data.get('as', '?')}",
                {
                    "source_ip":    ip,
                    "country":      data.get("country"),
                    "country_code": data.get("countryCode"),
                    "city":         data.get("city"),
                    "isp":          data.get("isp"),
                    "org":          data.get("org"),
                    "asn":          data.get("as"),
                    "latitude":     data.get("lat"),
                    "longitude":    data.get("lon"),
                    "timezone":     data.get("timezone"),
                }
            )
            print(f"GeoIP | {ip}  {data.get('city')}, "
                  f"{data.get('country')} | {data.get('isp')}")
    except Exception:
        pass   # best-effort — geo enrichment never blocks core logging


# --- 4. CONNECTION WATCHER (psutil-based, no proxy interference) ---
def watch_connections():
    """Monitor new TCP connections to port 102 and log attacker IPs."""
    if not PSUTIL_AVAILABLE:
        print("psutil not installed - run: pip3 install psutil")
        print("Connection IP logging disabled, all other logging active.")
        return

    known = set()
    print("Connection Watcher LIVE (polling port 102 for new IPs).")
    while True:
        try:
            current = set()
            for conn in psutil.net_connections(kind='tcp'):
                if (conn.laddr.port == 102
                        and conn.status == 'ESTABLISHED'
                        and conn.raddr):
                    key = (conn.raddr.ip, conn.raddr.port)
                    current.add(key)
                    if key not in known:
                        log_s7_interaction(
                            "CONNECTION_DETECTED",
                            f"S7comm connection from {key[0]}:{key[1]}",
                            {"source_ip": key[0], "source_port": key[1]}
                        )
                        # Spawn async GeoIP lookup — one per unique IP
                        threading.Thread(
                            target=enrich_with_geoip,
                            args=(key[0],),
                            daemon=True
                        ).start()
            # Forget connections that are no longer active
            known.clear()
            known.update(current)
        except Exception:
            pass
        time.sleep(0.5)

watcher_thread = threading.Thread(target=watch_connections, daemon=True)
watcher_thread.start()

# --- 4. PHYSICS ENGINE THREAD ---
TANK_MAX_CAPACITY  = 100.0  # Normal max (L)
OVERFLOW_THRESHOLD = 150.0  # ESD trigger point (L)
REFILL_THRESHOLD   = 20.0   # Auto-refill kicks in (L)
RESET_DELAY_SEC    = 30     # Seconds after overflow before honeypot auto-resets
RESET_WATER_LEVEL  = 50.0   # Level to restore after reset (L)

# Shared snapshot — updated by physics_loop each tick AND by do_exploit_reset.
# Keeps the write-detection diff consistent after auto-resets.
last_physics_state = bytearray(DB_SIZE)

def do_exploit_reset():
    """Run in a separate thread: wait RESET_DELAY_SEC after overflow, then restore
    the process to normal so the honeypot is a perpetual trap for attackers."""
    global last_physics_state
    time.sleep(RESET_DELAY_SEC)
    with physics_lock:
        db1_memory[6] = 0                                        # Clear crash flag
        db1_memory[0] = 1                                        # Pump ON
        struct.pack_into('>f', db1_memory, 2, RESET_WATER_LEVEL) # Restore level
        # CRITICAL: update the diff-snapshot so the physics engine doesn't
        # mistake this reset write for a new attacker write on the next tick.
        last_physics_state[:] = bytearray(db1_memory)
    log_s7_interaction(
        "EXPLOIT_RESET",
        f"Honeypot auto-reset after {RESET_DELAY_SEC}s. "
        f"Process restored to normal. Ready for next attacker.",
        {"reset_level_L": RESET_WATER_LEVEL}
    )
    print(f"\n RESET | Honeypot restored after {RESET_DELAY_SEC}s. "
          f"Water level  {RESET_WATER_LEVEL}L | Crash flag  0\n")


def physics_loop():
    print("Physics Engine LIVE. Simulating water treatment process...\n")
    exploit_logged  = False
    overflow_logged = False
    reset_scheduled = False   # True once the reset timer thread has been fired

    # last_physics_state is now a module-level variable shared with do_exploit_reset
    global last_physics_state

    while True:
        try:
            with physics_lock:
                pump_status   = db1_memory[0]
                current_level = struct.unpack_from('>f', db1_memory, 2)[0]
                crash_state   = db1_memory[6]

                # --- WRITE DETECTION: compare current memory to last physics-written state ---
                # Any diff that the physics engine didn't make = external attacker write
                current_raw = bytearray(db1_memory)
                for byte_idx in range(DB_SIZE):
                    if current_raw[byte_idx] != last_physics_state[byte_idx]:
                        log_s7_interaction(
                            "DB1_WRITE_DETECTED",
                            f"Attacker wrote to DB1 byte {byte_idx}: "
                            f"{last_physics_state[byte_idx]}  {current_raw[byte_idx]}",
                            {"byte_offset": byte_idx,
                             "old_value":   last_physics_state[byte_idx],
                             "new_value":   current_raw[byte_idx]}
                        )

                if crash_state == 1:
                    # EXPLOIT ACTIVE: safety bypassed, pump stuck ON
                    if not exploit_logged:
                        log_s7_interaction(
                            "EXPLOIT_TRIGGERED",
                            "CVE-2021-37185 DOS: Memory write bypassed safety logic. Pump forced ON."
                        )
                        exploit_logged = True

                    pump_status    = 1
                    current_level += 5.0 + random.uniform(-0.2, 0.2)

                    if current_level >= OVERFLOW_THRESHOLD and not overflow_logged:
                        log_s7_interaction(
                            "CRITICAL_OVERFLOW_ALARM",
                            f"Tank exceeded {OVERFLOW_THRESHOLD}L. ESD triggered.",
                            {"level_at_esd": round(current_level, 2)}
                        )
                        overflow_logged = True
                        print(f"OVERFLOW! ESD triggered at {current_level:.1f}L")

                    if current_level > OVERFLOW_THRESHOLD:
                        current_level = OVERFLOW_THRESHOLD

                    # --- AUTO-RESET: schedule restoration once overflow fires ---
                    if overflow_logged and not reset_scheduled:
                        reset_scheduled = True
                        reset_thread = threading.Thread(
                            target=do_exploit_reset, daemon=True
                        )
                        reset_thread.start()
                        print(f"  Auto-reset scheduled in {RESET_DELAY_SEC}s...")

                    print(f"CVE ACTIVE | Pump: ON | Level: {current_level:.1f}L/{OVERFLOW_THRESHOLD:.0f}L MAX")

                else:
                    # NORMAL OPERATION: pump cycles between 20–100L
                    if pump_status == 1:
                        current_level += 2.0 + random.uniform(-0.1, 0.1)
                        if current_level >= TANK_MAX_CAPACITY:
                            pump_status   = 0
                            current_level = TANK_MAX_CAPACITY
                    else:
                        current_level -= 0.5 + random.uniform(-0.05, 0.05)
                        if current_level < REFILL_THRESHOLD:
                            pump_status   = 1
                            current_level = REFILL_THRESHOLD

                    print(f"[PLC] Pump: {'ON ' if pump_status else 'OFF'} | Level: {current_level:.1f}L | State: NORMAL")

                # Write updated state back to PLC memory
                db1_memory[0] = pump_status
                struct.pack_into('>f', db1_memory, 2, current_level)
                db1_memory[6] = crash_state

                # Snapshot what I just wrote — next tick, any byte that
                # differs from this was changed externally by an attacker.
                last_physics_state[:] = bytearray(db1_memory)

                # If a reset just fired (crash_state went back to 0), reset
                # all exploit tracking flags so the next attack is fully logged.
                if crash_state == 0 and exploit_logged:
                    exploit_logged  = False
                    overflow_logged = False
                    reset_scheduled = False

            time.sleep(1)

        except Exception as e:
            print(f"Physics Engine Error: {e}")
            time.sleep(1)

physics_thread = threading.Thread(target=physics_loop, daemon=True)
physics_thread.start()

# --- 5. Supplemental Services ---
print("Launching Web Portal Simulation...")
http_proc = subprocess.Popen(["python3", "services/web_server.py"])

print("Launching SNMP Agent Simulation...")
snmp_proc = subprocess.Popen(["python3", "services/snmp_agent.py"])

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n Shutting down s7pot...")
    server.stop()
    server.destroy()
    http_proc.terminate()
    snmp_proc.terminate()