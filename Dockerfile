FROM python:3.9-slim

# Install system dependencies
# iproute2 provides 'tc' (traffic control) for netem latency injection
RUN apt-get update && apt-get install -y iproute2 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (psutil needed for connection IP logging)
RUN pip install "python-snap7<3" pysnmp psutil

# =====================================================================
# Binary hot-patch: overwrite hardcoded S7-300 strings with S7-1200.
# Makes nmap s7-info and Shodan fingerprint this as a real CPU 1214C.
# =====================================================================
RUN python3 -c 'import os;\
so_file = os.popen("find /usr -name \"libsnap7*.so\" 2>/dev/null | head -n 1").read().strip();\
d = open(so_file, "rb").read();\
d = d.replace(b"SNAP7-SERVER", b"SIMATIC-1200");\
d = d.replace(b"6ES7 315-2EH14-0AB0", b"6ES7 214-1AG40-0XB0");\
d = d.replace(b"CPU 315-2 PN/DP", b"CPU 1214C      ");\
open(so_file, "wb").write(d);\
print("Binary Hot-Patch Successful!")'

WORKDIR /app
COPY s7pot.py      /app/
COPY services      /app/services
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose S7comm (102), HTTP (80) and SNMP (161/udp)
EXPOSE 102 80 161/udp

# Force Python to print to Docker logs instantly
ENV PYTHONUNBUFFERED=1

# entrypoint.sh applies tc netem latency on port 102, then execs s7pot.py
CMD ["/app/entrypoint.sh"]