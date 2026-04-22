import socket
import select
import time
import json
import os
import threading

PROXY_PORT = 102
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 10200
LATENCY_SEC = 0.08

os.makedirs("logs", exist_ok=True)

def log_interaction(ip_address, data_size):
    log_entry = {
        "timestamp": time.time(),
        "protocol": "S7COMM",
        "intent": "SCAN_OR_CONNECT_DETECTED",
        "details": f"Connection from {ip_address} with {data_size} bytes payload intercepted by proxy."
    }
    try:
        with open("logs/interaction.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception:
        pass

def handle_client(client_socket, addr):
    ip_address = addr[0]
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.connect((TARGET_HOST, TARGET_PORT))
    except Exception as e:
        print(f"S7 Proxy: Backend server unreachable: {e}")
        client_socket.close()
        return

    first_packet = True
    sockets = [client_socket, server_socket]
    
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [])
            for s in readable:
                data = s.recv(4096)
                if not data:
                    # Connection closed by one of the peers
                    return
                
                if s is client_socket:
                    if first_packet:
                        log_interaction(ip_address, len(data))
                        first_packet = False
                        if LATENCY_SEC > 0:
                            time.sleep(LATENCY_SEC)
                    server_socket.sendall(data)
                else:
                    client_socket.sendall(data)
    except Exception:
        pass
    finally:
        client_socket.close()
        server_socket.close()

def run_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("0.0.0.0", PROXY_PORT))
        server.listen(5)
        print(f"S7 TCP Proxy LIVE on port {PROXY_PORT} (Routing to {TARGET_PORT} with {LATENCY_SEC}s latency)")
        
        while True:
            client_sock, addr = server.accept()
            threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
    except Exception as e:
        print(f" S7 Proxy Error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    run_proxy()
