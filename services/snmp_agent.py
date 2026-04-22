import socket
import json
import time
import logging
import os
import binascii

PORT = 161
logging.basicConfig(level=logging.INFO, format='%(asctime)s - SNMP Agent - %(message)s')
os.makedirs("logs", exist_ok=True)

# A static, pre-calculated BER-encoded SNMPv2c trap or response can be sent,
# but for high-interaction logging, just intercepting the UDP port 161 and logging
# the connection intent is highly valuable. Shodan sends specific bytes.

def log_interaction(addr, port, hex_payload):
    log_entry = {
        "timestamp": time.time(),
        "source": addr,
        "port": port,
        "protocol": "SNMP",
        "intent": "SNMP_SCAN_OR_WALK",
        "details": f"Payload: {hex_payload}"
    }
    with open("logs/interaction.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def run_snmp_agent():
    global PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", PORT))
        logging.info("Serving SNMP Agent Honeypot on port %d...", PORT)
    except PermissionError:
        logging.warning(f"Permission denied for port {PORT}. Falling back to port 16161...")
        PORT = 16161
        sock.bind(("0.0.0.0", PORT))
        logging.info("Serving SNMP Agent Honeypot on port %d...", PORT)
        
    try:
        while True:
            data, addr = sock.recvfrom(2048)
            hex_data = binascii.hexlify(data).decode('utf-8')
            log_interaction(addr[0], addr[1], hex_data)
            logging.info(f"SNMP probe logged from {addr[0]}:{addr[1]}")
            
    except PermissionError:
        logging.error("Permission denied for port 161. Try running as sudo or use a port > 1024.")
    except Exception as e:
        logging.error(f"SNMP Server error: {e}")

if __name__ == "__main__":
    run_snmp_agent()
