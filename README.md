# S7pot Honeypot

## What I Have
A high-interaction industrial control system (ICS) honeypot that simulates a Siemens S7-1200 PLC running a water treatment process. Built for research and deception, it accurately represents a real production environment. The simulation includes three core services:
- **S7comm PLC** (port 102): The main controller simulation.
- **Web Portal** (port 80): A simulated Siemens SIMATIC interface for HTTP reconnaissance.
- **SNMP Agent** (port 161/udp): A network management node for discovery.

The entire environment is containerized using Docker for easy deployment and streams telemetry to a local Grafana dashboard for full observability.

## How It Works
- **Deception via Binary Patching**: The underlying S7 communication library is hot-patched during deployment to present authentic Siemens S7-1200 firmware identifiers to network scanners (like Nmap), effectively evading detection as a honeypot.
- **Dynamic Physics Simulation**: A background engine runs a live model of a water tank filling and emptying cycle. This provides attackers with dynamic, changing memory data that is indistinguishable from a real ICS network process.
- **Immediate Exploit Detection**: The platform natively monitors its simulated PLC memory blocks. It catches and logs any unauthorized write interactions instantly, allowing us to track every phase of an attack—from initial connection to process manipulation and emergency safety bypasses.

All attacker interactions are captured natively and logged to JSON for telemetry analysis and visualization.

## Fast Setup
To run the honeypot and observability stack (Grafana/Loki/Promtail) fully dockerized:

```bash
# 1. Bring up the honeypot and logging stack
docker-compose up -d --build

# 2. View the telemetry dashboard
# Open your browser to http://localhost:3000 (username: admin / password: admin)

# 3. Simulate an attack
# (Requires Python 3 & python-snap7 on your host)
python3 full_attack_demo.py

# 4. Stop and clean up the environment when finished
docker-compose down -v
```
