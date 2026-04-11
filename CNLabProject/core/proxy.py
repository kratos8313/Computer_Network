import socket
import threading
import json
from utils.logger import log

CONFIG_PATH = "config/settings.json"

#Global variables
server_socket = None
proxy_running = False


# ---------------- CONFIG ----------------
def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


# ---------------- DPI ----------------
def dpi_inspect(data, client_ip):
    text = data.decode("utf-8", "ignore").lower()
    config = load_config()

    host = ""
    for line in text.split("\r\n"):
        if line.startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    # Block sites
    for site in config["blocked_sites"]:
        if site in host:
            return "BLOCK", host

    # Keyword detection
    for keyword in ["password", "login"]:
        if keyword in text:
            log(f"[ALERT] Keyword '{keyword}' from {client_ip}")

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
    client_ip = addr[0]

    try:
        request = client_socket.recv(4096)
        if not request:
            client_socket.close()
            return

        request_text = request.decode("utf-8", "ignore")
        request_line = request_text.split("\n")[0]

        # ================= HTTPS =================
        if request_line.startswith("CONNECT"):
            host_port = request_line.split(" ")[1]
            host, port = host_port.split(":")
            port = int(port)

            config = load_config()

            # Block HTTPS domain
            if any(site in host for site in config["blocked_sites"]):
                log(f"[BLOCKED HTTPS] {client_ip} -> {host}")
                client_socket.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked")
                client_socket.close()
                return

            log(f"[HTTPS] {client_ip} -> {host}:{port}")

            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

            return

        # ================= HTTP =================
        action, host = dpi_inspect(request, client_ip)

        if action == "BLOCK":
            log(f"[BLOCKED HTTP] {client_ip} -> {host}")
            client_socket.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy")
            client_socket.close()
            return

        log(f"[HTTP] {client_ip} -> {host}")

        # Forward HTTP request
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((host, 80))
        server.send(request)

        while True:
            data = server.recv(4096)
            if not data:
                break
            client_socket.send(data)

        server.close()
        client_socket.close()

    except Exception as e:
        log(f"[ERROR] {e}")
        client_socket.close()


# ---------------- START PROXY ----------------
def start_proxy(host="127.0.0.1", port=8080):
    global server_socket, proxy_running

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(50)

    proxy_running = True
    log(f"[PROXY STARTED] {host}:{port}")

    try:
        while proxy_running:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

    except Exception as e:
        log(f"[PROXY ERROR] {e}")

    finally:
        if server_socket:
            server_socket.close()
        log("[PROXY STOPPED]")

# ---------------- STOP PROXY ----------------
def stop_proxy():
    global proxy_running, server_socket

    proxy_running = False

    if server_socket:
        try:
            server_socket.close()
        except:
            pass