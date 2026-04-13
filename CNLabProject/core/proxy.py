import socket
import threading
from utils.logger import log
from core.rules import should_block
from core.database import log_activity

CONFIG_PATH = "config/settings.json"

#Global variables
server_socket = None
proxy_running = False
proxy_status = "STOPPED" # STOPPED, RUNNING, ERROR
proxy_error = ""

active_sockets = set()
sockets_lock = threading.Lock()

def register_socket(sock):
    with sockets_lock:
        active_sockets.add(sock)

def unregister_socket(sock):
    with sockets_lock:
        active_sockets.discard(sock)

def clear_all_connections():
    with sockets_lock:
        for sock in list(active_sockets):
            try:
                sock.close()
            except:
                pass
        active_sockets.clear()


# ---------------- CONFIG ----------------
# Removed load_config JSON dependency


# ---------------- DPI ----------------
def dpi_inspect(data, client_ip):
    text = data.decode("utf-8", "ignore").lower()
    
    host = ""
    for line in text.split("\r\n"):
        if line.startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    if not host: 
        return "ALLOW", ""

    # Check Rules
    blocked, reason = should_block(host)
    
    # Keyword detection (Keeping existing feature)
    for keyword in ["password", "login"]:
        if keyword in text:
            log(f"[ALERT] Keyword '{keyword}' from {client_ip}")

    # Root keyword search (Extra safety for related CDNs)
    if not blocked:
        # Check if the host contains any part of our blocked rules as a root domain
        pass # should_block already handles LIKE %domain% now

    if blocked:
        log_activity(host, "BLOCKED", reason)
        return "BLOCK", host
    
    log_activity(host, "ALLOWED")
    return "ALLOW", host


# ---------------- SAFE FORWARD ----------------
def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        pass
    finally:
        unregister_socket(src)
        unregister_socket(dst)
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass


# ---------------- CLIENT HANDLER ----------------
def handle_client(client_socket, addr):
    register_socket(client_socket)
    client_ip = addr[0]

    try:
        request = client_socket.recv(4096)
        if not request:
            client_socket.close()
            unregister_socket(client_socket)
            return

        request_text = request.decode("utf-8", "ignore")
        request_line = request_text.split("\n")[0]

        # ================= HTTPS =================
        if request_line.startswith("CONNECT"):
            host_port = request_line.split(" ")[1]
            host, port = host_port.split(":")
            port = int(port)

            # Check Rules
            blocked, reason = should_block(host)

            if blocked:
                log(f"[BLOCKED HTTPS] {client_ip} -> {host}")
                log_activity(host, "BLOCKED", reason)
                client_socket.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Parent Control")
                client_socket.close()
                unregister_socket(client_socket)
                return

            log(f"[HTTPS] {client_ip} -> {host}:{port}")
            # log_activity(host, "ALLOWED") # Removing to avoid log bloat for every HTTPS tunnel stream

            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                register_socket(remote)
                remote.connect((host, port))

                # Tell browser tunnel is ready
                client_socket.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                # Start bidirectional forwarding
                t1 = threading.Thread(target=forward, args=(client_socket, remote), daemon=True)
                t2 = threading.Thread(target=forward, args=(remote, client_socket), daemon=True)

                t1.start()
                t2.start()

            except Exception as e:
                log(f"[HTTPS ERROR] {e}")
                client_socket.close()
                unregister_socket(client_socket)

            return

        # ================= HTTP =================
        action, host = dpi_inspect(request, client_ip)

        if action == "BLOCK":
            log(f"[BLOCKED HTTP] {client_ip} -> {host}")
            client_socket.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy")
            client_socket.close()
            unregister_socket(client_socket)
            return

        log(f"[HTTP] {client_ip} -> {host}")

        # Forward HTTP request
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        register_socket(server)
        server.connect((host, 80))
        server.send(request)

        while True:
            data = server.recv(4096)
            if not data:
                break
            client_socket.send(data)

        server.close()
        unregister_socket(server)
        client_socket.close()
        unregister_socket(client_socket)

    except Exception as e:
        log(f"[ERROR] {e}")
        client_socket.close()
        unregister_socket(client_socket)


# ---------------- START PROXY ----------------
def start_proxy(host="127.0.0.1", port=8080):
    global server_socket, proxy_running, proxy_status, proxy_error

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(50)
        
        proxy_running = True
        proxy_status = "RUNNING"
        proxy_error = ""
        log(f"[PROXY STARTED] {host}:{port}")

        while proxy_running:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

    except Exception as e:
        proxy_status = "ERROR"
        proxy_error = str(e)
        log(f"[PROXY ERROR] {e}")

    finally:
        proxy_running = False
        if proxy_status != "ERROR":
            proxy_status = "STOPPED"
        if server_socket:
            server_socket.close()
        log("[PROXY STOPPED]")

def get_proxy_status():
    return proxy_status, proxy_error

# ---------------- STOP PROXY ----------------
def stop_proxy():
    global proxy_running, server_socket

    proxy_running = False

    if server_socket:
        try:
            server_socket.close()
        except:
            pass
