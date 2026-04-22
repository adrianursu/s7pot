import http.server
import socketserver
import logging
import json
import time
import os

PORT = 80

logging.basicConfig(level=logging.INFO, format='%(asctime)s - HTTP Server - %(message)s')

# Ensure logs dir exists
os.makedirs("logs", exist_ok=True)

class HoneypotHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    
    def log_interaction(self, intent, details=""):
        log_entry = {
            "timestamp": time.time(),
            "source": self.client_address[0],
            "port": self.client_address[1],
            "protocol": "HTTP",
            "intent": intent,
            "path": self.path,
            "details": details
        }
        with open("logs/interaction.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            
    def do_GET(self):
        # MWSL stands for Mini Web Server Language, typical in old Siemens PLCs.
        if "/Portal/Portal.mwsl" in self.path:
            # We are simulating a known CVE endpoint
            # The attacker scans for this endpoint to find vulnerable S7 Web servers.
            self.log_interaction("CVE-2019-10929 PROBE", "Attacker attempting to access Siemens Portal.mwsl endpoint without proper authorization.")
            
            # Respond with a simulated "leak" or a fake interface
            self.send_response(200)
            self.send_header("Server", "Siemens S7-1200 Web Server")
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>SIMATIC S7-1200 Web Server</h1>")
            self.wfile.write(b"<p>System Diagnostic Log</p>")
            self.wfile.write(b"<!-- Configuration payload leaked -> CPU_1214C-DC/DC/DC -->")
            self.wfile.write(b"</body></html>")
            logging.warning(f"CVE-2019-10929 Probe logged from {self.client_address[0]}")
        else:
            self.log_interaction("GENERIC HTTP SCAN")
            self.send_response(200)
            self.send_header("Server", "Siemens S7-1200 Web Server")
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<!DOCTYPE html><html><head><title>Siemens S7 PLC</title></head>")
            self.wfile.write(b"<body><h1>SIMATIC S7-1200 Web Server</h1><p>Running.</p></body></html>")
            
    def log_message(self, format, *args):
        # Overriding to prevent standard http.server from spamming stdout
        pass

class QuietTCPServer(socketserver.TCPServer):
    """Suppress ConnectionResetError spam caused by scanners (e.g. Nmap) probing
    HTTP port with non-HTTP data then dropping the connection."""
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        import sys
        exc = sys.exc_info()[1]
        # Silently discard expected scanner-induced connection drops
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return
        # Log everything else
        super().handle_error(request, client_address)

def run_web_server():
    Handler = HoneypotHTTPRequestHandler
    try:
        with QuietTCPServer(("0.0.0.0", PORT), Handler) as httpd:
            logging.info("Serving Siemens HTTP App on port %d...", PORT)
            httpd.serve_forever()
    except OSError as e:
        if "Address already in use" in str(e):
            with QuietTCPServer(("0.0.0.0", 8080), Handler) as httpd:
                logging.warning("Port 80 in use, serving HTTP Honeypot on port 8080...")
                httpd.serve_forever()
        else:
            logging.error(f"HTTP Server error: {e}")

if __name__ == "__main__":
    run_web_server()
