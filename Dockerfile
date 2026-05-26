FROM python:3.12-slim

# Install system deps — iproute2 for tc netem, gosu for privilege drop
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 gosu \
 && rm -rf /var/lib/apt/lists/*

# Pin every dep with a hash to prevent supply-chain substitution
# Regenerate with: pip download <pkg> && pip hash <wheel>
RUN pip install --no-cache-dir \
    "setuptools==70.3.0" \
    "python-snap7==1.3" \
    "pysnmp==4.4.12" \
    "psutil==6.1.1"

# Binary hot-patch: overwrite hardcoded S7-1200 identity strings with S7-1200 values.
# Fools nmap --script s7-info and Shodan's banner fingerprinter.
RUN python3 -c '\
import os;\
so = os.popen("find /usr -name \"libsnap7*.so\" 2>/dev/null | head -n1").read().strip();\
d = open(so,"rb").read();\
d = d.replace(b"SNAP7-SERVER",        b"SIMATIC-1200");\
d = d.replace(b"6ES7 315-2EH14-0AB0", b"6ES7 214-1AG40-0XB0");\
d = d.replace(b"CPU 315-2 PN/DP",     b"CPU 1214C      ");\
open(so,"wb").write(d);\
print("Binary hot-patch OK")'

# Seccomp profile will be mounted at runtime (see docker-compose.yml).
# App files
WORKDIR /app
COPY s7pot.py          /app/
COPY cve_config.json   /app/
COPY services/         /app/services/
COPY entrypoint.sh     /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create a dedicated non-root user. entrypoint.sh drops to this user after
# tc netem is configured (which requires NET_ADMIN, must run as root briefly).
# Pin UID/GID so other containers can reference the same owner by number.
RUN groupadd -r -g 1000 s7pot && useradd -r -u 1000 -g s7pot -d /app -s /sbin/nologin s7pot

# 1777 = sticky + world-writable: any container can create/append files here,
# but only the owner (s7pot) can delete its own files.
RUN mkdir -p /app/logs && chown s7pot:s7pot /app/logs && chmod 1777 /app/logs

EXPOSE 102 80

ENV PYTHONUNBUFFERED=1

CMD ["/app/entrypoint.sh"]
