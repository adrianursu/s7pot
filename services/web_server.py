"""
HTTP honeypot — simulates a Siemens SIMATIC S7-1200 web server.

Header order, keep-alive behavior, and response structure are taken from
real packet captures of an S7-1200 CPU 1214C running FW V4.4.
Python's SimpleHTTPRequestHandler is NOT used because its header order and
version string are trivially fingerprinted.

Endpoints simulated:
  /                          → SIMATIC landing page
  /Portal/Portal.mwsl        → CVE-2019-10929 lure (config info disclosure)
  /awp/                      → Siemens AWP directory listing stub
  /favicon.ico               → Siemens favicon (1×1 px placeholder)
  /css/Siemens_HMI.css       → Plausible CSS path (returns minimal stub)
  *                          → Generic 200 with Siemens branding
"""

import socket
import json
import time
import os
import logging
import threading
import urllib.parse
import collections

PORT = 80
logging.basicConfig(level=logging.INFO, format="%(asctime)s - HTTP - %(message)s")
os.makedirs("logs", exist_ok=True)

# ---------------------------------------------------------------------------
# Credential statistics — thread-safe counters for the /teapot dashboard
# ---------------------------------------------------------------------------
_STATS_LOCK      = threading.Lock()
_USERNAME_COUNTS = collections.Counter()
_PASSWORD_COUNTS = collections.Counter()
_TOTAL_ATTEMPTS  = 0


def _render_teapot() -> bytes:
    with _STATS_LOCK:
        top_users = _USERNAME_COUNTS.most_common(10)
        top_pwds  = _PASSWORD_COUNTS.most_common(10)
        total     = _TOTAL_ATTEMPTS
    rows_u = "".join(
        f"<tr><td>{u or '(empty)'}</td><td>{c}</td></tr>" for u, c in top_users
    )
    rows_p = "".join(
        f"<tr><td>{p or '(empty)'}</td><td>{c}</td></tr>" for p, c in top_pwds
    )
    return f"""<!DOCTYPE html>
<html><head><title>S7pot — Login Statistics</title>
<style>
  body  {{ font-family: monospace; background:#111; color:#00ff41; padding:24px; }}
  h1    {{ color:#00cc33; }} h2 {{ color:#00cc33; margin-top:28px; }}
  table {{ border-collapse:collapse; margin:12px 0; min-width:320px; }}
  th,td {{ border:1px solid #00ff41; padding:6px 16px; text-align:left; }}
  th    {{ background:#003300; }}
  .dim  {{ color:#009922; font-size:.85em; }}
</style></head><body>
<h1>SIMATIC S7-1200 — Login Attempt Statistics</h1>
<p class="dim">Total credential submissions: <strong>{total}</strong></p>
<h2>Top Usernames</h2>
<table><tr><th>Username</th><th>Count</th></tr>{rows_u}</table>
<h2>Top Passwords</h2>
<table><tr><th>Password</th><th>Count</th></tr>{rows_p}</table>
</body></html>""".encode()

# ---------------------------------------------------------------------------
# Exact Siemens S7-1200 header fingerprint (from real FW V4.4 capture)
# Header ORDER matters for fingerprinting tools — do not reorder.
# ---------------------------------------------------------------------------
SERVER_BANNER = "Siemens HTTP Server"

# Minimal 1×1 transparent GIF as favicon stand-in
_FAVICON = bytes([
    0x47,0x49,0x46,0x38,0x39,0x61,0x01,0x00,0x01,0x00,0x80,0x00,0x00,
    0xFF,0xFF,0xFF,0x00,0x00,0x00,0x21,0xF9,0x04,0x01,0x00,0x00,0x00,
    0x00,0x2C,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x02,0x02,
    0x44,0x01,0x00,0x3B,
])

_LANDING_HTML = b"""\
<!DOCTYPE html>
<html><head>
<meta http-equiv="refresh" content="0; url=/Portal/Portal.mwsl?PriNav=Home">
<title>SIMATIC S7-1200</title>
</head><body>
<h1>SIMATIC S7-1200 Web Server</h1>
<p>CPU 1214C DC/DC/DC | FW: V4.4 | HW: 4</p>
<a href="/Portal/Portal.mwsl?PriNav=Home">Open Portal</a>
</body></html>"""

# Login page returned on GET /Portal/Portal.mwsl — real S7-1200 requires
# authentication before showing configuration data.
_PORTAL_LOGIN_HTML = b"""\
<!DOCTYPE html>
<html><head><title>SIMATIC S7-1200 - Login</title>
<link rel="stylesheet" href="/css/Siemens_HMI.css">
</head><body>
<h1>SIMATIC S7 Web Server</h1>
<p>Please log in to access device information.</p>
<form method="POST" action="/Portal/Portal.mwsl">
  <table>
    <tr><td>User</td><td><input type="text" name="Login" value=""></td></tr>
    <tr><td>Password</td><td><input type="password" name="Password" value=""></td></tr>
  </table>
  <input type="hidden" name="PriNav" value="Home">
  <input type="submit" value="Log In">
</form>
</body></html>"""

# Page shown after a failed login attempt — matches real S7-1200 behaviour
_PORTAL_AUTH_FAIL_HTML = b"""\
<!DOCTYPE html>
<html><head><title>SIMATIC S7-1200 - Login Failed</title>
<link rel="stylesheet" href="/css/Siemens_HMI.css">
</head><body>
<h1>SIMATIC S7 Web Server</h1>
<p style="color:red">Login failed. Please check your username and password.</p>
<form method="POST" action="/Portal/Portal.mwsl">
  <table>
    <tr><td>User</td><td><input type="text" name="Login" value=""></td></tr>
    <tr><td>Password</td><td><input type="password" name="Password" value=""></td></tr>
  </table>
  <input type="hidden" name="PriNav" value="Home">
  <input type="submit" value="Log In">
</form>
</body></html>"""

_PORTAL_HTML = b"""\
<!DOCTYPE html>
<html><head><title>SIMATIC S7-1200 - Portal</title>
<link rel="stylesheet" href="/css/Siemens_HMI.css">
</head><body>
<h1>SIMATIC S7 Web Server</h1>
<table>
<tr><td>Device name</td><td>S7-1200_PLC</td></tr>
<tr><td>Article number</td><td>6ES7 214-1AG40-0XB0</td></tr>
<tr><td>Firmware</td><td>V4.4</td></tr>
<tr><td>Hardware</td><td>4</td></tr>
<tr><td>IP address</td><td>192.168.0.1</td></tr>
<tr><td>Subnet mask</td><td>255.255.255.0</td></tr>
<!-- CPU_1214C-DC/DC/DC | Serial: S C-J9XH12345678 -->
</table>
</body></html>"""

_AWP_HTML = b"""\
<!DOCTYPE html>
<html><head><title>Index of /awp/</title></head>
<body><h1>Index of /awp/</h1>
<pre>Siemens Automation Web Programming directory</pre>
</body></html>"""

_CSS_STUB = b"/* Siemens_HMI.css v4.4 */ body{font-family:sans-serif;}"

# ---------------------------------------------------------------------------
# Raw HTTP/1.1 server — full control over headers
# ---------------------------------------------------------------------------

def _send_response(conn: socket.socket, status: str, content_type: str,
                   body: bytes, extra_headers: list[tuple] | None = None):
    now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    headers = [
        f"HTTP/1.1 {status}",
        f"Server: {SERVER_BANNER}",
        f"Date: {now}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: Keep-Alive",
        "Keep-Alive: timeout=10, max=100",
        "Pragma: no-cache",
        "Cache-Control: no-cache",
        "X-Frame-Options: SAMEORIGIN",
    ]
    if extra_headers:
        for k, v in extra_headers:
            headers.append(f"{k}: {v}")
    headers.append("")   # blank line before body
    headers.append("")
    raw = "\r\n".join(headers).encode() + body
    try:
        conn.sendall(raw)
    except (BrokenPipeError, ConnectionResetError):
        pass


def _log(src_ip, src_port, path, intent, details=""):
    entry = {
        "timestamp":  time.time(),
        "source":     src_ip,
        "port":       src_port,
        "protocol":   "HTTP",
        "intent":     intent,
        "path":       path,
        "details":    details,
    }
    try:
        with open("logs/interaction.json", "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _handle_request(conn: socket.socket, src_ip: str, src_port: int):
    try:
        conn.settimeout(10)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = conn.recv(4096)
            if not chunk:
                return
            raw += chunk
            if len(raw) > 16384:
                return

        lines = raw.split(b"\r\n")
        if not lines:
            return
        request_line = lines[0].decode(errors="replace")
        parts = request_line.split()
        if len(parts) < 2:
            return
        method, path = parts[0], parts[1]

        if method not in ("GET", "HEAD", "POST"):
            _send_response(conn, "405 Method Not Allowed", "text/plain", b"405")
            _log(src_ip, src_port, path, "UNSUPPORTED_METHOD")
            return

        if "/Portal/Portal.mwsl" in path:
            if method == "POST":
                # Attacker submitted credentials — extract and log them.
                # Real S7-1200 always rejects with 401/login-fail; we do the
                # same so the attacker cannot distinguish us from a real device.
                body_bytes = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
                try:
                    params = urllib.parse.parse_qs(body_bytes.decode(errors="replace"))
                    user = params.get("Login", [""])[0]
                    pwd  = params.get("Password", [""])[0]
                except Exception:
                    user = pwd = ""
                _log(src_ip, src_port, path, "CREDENTIAL_SUBMISSION",
                     f"user={user!r} password={pwd!r}")
                logging.warning("Credential submission from %s: user=%r", src_ip, user)
                global _TOTAL_ATTEMPTS
                with _STATS_LOCK:
                    _USERNAME_COUNTS[user] += 1
                    _PASSWORD_COUNTS[pwd]  += 1
                    _TOTAL_ATTEMPTS += 1
                body = _PORTAL_AUTH_FAIL_HTML if method != "HEAD" else b""
                _send_response(conn, "200 OK", "text/html", body,
                               [("X-Auth-Error", "InvalidCredentials")])
            else:
                # GET — serve login form (not the info table directly).
                # Real S7-1200 requires authentication before showing config.
                _log(src_ip, src_port, path, "CVE-2019-10929_PROBE",
                     "Portal.mwsl login page probe")
                logging.warning("CVE-2019-10929 probe from %s", src_ip)
                body = _PORTAL_LOGIN_HTML if method != "HEAD" else b""
                _send_response(conn, "200 OK", "text/html", body)

        elif path in ("/", "/index.html"):
            _log(src_ip, src_port, path, "HTTP_RECON")
            body = _LANDING_HTML if method != "HEAD" else b""
            _send_response(conn, "200 OK", "text/html", body)

        elif path.startswith("/awp/"):
            _log(src_ip, src_port, path, "AWP_PROBE")
            body = _AWP_HTML if method != "HEAD" else b""
            _send_response(conn, "200 OK", "text/html", body)

        elif path == "/DataLogs/sysdiag":
            # Credential statistics dashboard — localhost access only.
            # External requests fall through to the landing page so the path
            # reveals nothing to an attacker doing directory enumeration.
            if src_ip != "127.0.0.1":
                _log(src_ip, src_port, path, "GENERIC_HTTP_SCAN")
                body = _LANDING_HTML if method != "HEAD" else b""
                _send_response(conn, "200 OK", "text/html", body)
                return
            body = _render_teapot() if method != "HEAD" else b""
            _send_response(conn, "200 OK", "text/html", body)
            return

        elif path == "/favicon.ico":
            body = _FAVICON if method != "HEAD" else b""
            _send_response(conn, "200 OK", "image/gif", body)
            _log(src_ip, src_port, path, "GENERIC_HTTP_SCAN")

        elif path.endswith(".css"):
            body = _CSS_STUB if method != "HEAD" else b""
            _send_response(conn, "200 OK", "text/css", body)
            _log(src_ip, src_port, path, "GENERIC_HTTP_SCAN")

        else:
            _log(src_ip, src_port, path, "GENERIC_HTTP_SCAN")
            body = _LANDING_HTML if method != "HEAD" else b""
            _send_response(conn, "200 OK", "text/html", body)

    except (OSError, TimeoutError):
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _client_thread(conn, addr):
    _handle_request(conn, addr[0], addr[1])


def run_web_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", PORT))
    except PermissionError:
        srv.bind(("0.0.0.0", 8080))
        logging.warning("Port 80 denied — listening on 8080")
    srv.listen(64)
    logging.info("HTTP honeypot listening on port %d", srv.getsockname()[1])

    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=_client_thread, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            logging.error("Accept error: %s", e)


if __name__ == "__main__":
    run_web_server()
