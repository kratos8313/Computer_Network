import ipaddress
import socket
import threading
from urllib.parse import urlsplit
from core.database import log_activity
from core.notifications import notify_blocked_activity
from core.rules import should_block
from utils.logger import log

server_socket = None
proxy_running = False
proxy_status = 'STOPPED'
proxy_error = ''
active_sockets = set()
sockets_lock = threading.Lock()
MAX_HEADER = 65536
CONNECT_PORTS = {443, 8443}
HTTP_PORTS = {80, 8080}


def register_socket(sock):
    with sockets_lock:
        active_sockets.add(sock)


def unregister_socket(sock):
    with sockets_lock:
        active_sockets.discard(sock)


def close_socket(sock):
    unregister_socket(sock)
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def clear_all_connections():
    with sockets_lock:
        sockets = list(active_sockets)
        active_sockets.clear()
    for sock in sockets:
        close_socket(sock)


def _read_headers(sock):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_HEADER:
            raise ValueError('Request headers exceed 64 KiB')
    return bytes(data)


def _parse_authority(authority, default_port):
    parsed = urlsplit('//' + authority)
    if not parsed.hostname:
        raise ValueError('Missing destination host')
    try:
        port = parsed.port or default_port
    except ValueError as exc:
        raise ValueError('Invalid destination port') from exc
    return parsed.hostname.rstrip('.').lower(), port


def _validate_destination(host, port, allowed_ports):
    if port not in allowed_ports:
        raise ValueError(f'Destination port {port} is not allowed')
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError('Destination could not be resolved')
    for item in addresses:
        address = ipaddress.ip_address(item[4][0])
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError('Private and local destinations are not allowed')
    return addresses


def _connect_public(host, port, allowed_ports):
    addresses = _validate_destination(host, port, allowed_ports)
    family, socktype, proto, _, sockaddr = addresses[0]
    remote = socket.socket(family, socktype, proto)
    remote.settimeout(10)
    remote.connect(sockaddr)
    remote.settimeout(30)
    register_socket(remote)
    return remote


def forward(src, dst):
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            dst.sendall(data)
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        pass
    finally:
        close_socket(src)
        close_socket(dst)


def _send_error(client, status, message):
    body = message.encode('utf-8', 'replace')
    client.sendall(f'HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)


def handle_client(client_socket, addr):
    register_socket(client_socket)
    client_socket.settimeout(15)
    remote = None
    try:
        request_data = _read_headers(client_socket)
        if not request_data:
            return
        header, separator, remainder = request_data.partition(b'\r\n\r\n')
        lines = header.decode('iso-8859-1').split('\r\n')
        method, target, version = lines[0].split(' ', 2)
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        if method.upper() == 'CONNECT':
            host, port = _parse_authority(target, 443)
            blocked, reason = should_block(host)
            if blocked:
                log_activity(host, 'BLOCKED', reason)
                notify_blocked_activity(host, reason)
                _send_error(client_socket, '403 Forbidden', 'Blocked by Network Control')
                return
            remote = _connect_public(host, port, CONNECT_PORTS)
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            threading.Thread(target=forward, args=(client_socket, remote), daemon=True).start()
            threading.Thread(target=forward, args=(remote, client_socket), daemon=True).start()
            remote = None
            client_socket = None
            return

        parsed = urlsplit(target)
        authority = parsed.netloc or headers.get('host', '')
        host, port = _parse_authority(authority, 80)
        blocked, reason = should_block(host)
        if blocked:
            log_activity(host, 'BLOCKED', reason)
            notify_blocked_activity(host, reason)
            _send_error(client_socket, '403 Forbidden', 'Blocked by Network Control')
            return
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        filtered = [line for line in lines[1:] if not line.lower().startswith(('proxy-connection:', 'connection:'))]
        outbound = (f'{method} {path} {version}\r\n' + '\r\n'.join(filtered) + '\r\nConnection: close\r\n\r\n').encode('iso-8859-1') + remainder
        if headers.get('transfer-encoding', '').lower() not in {'', 'identity'}:
            raise ValueError('Chunked request bodies are not supported')
        content_length = int(headers.get('content-length', '0'))
        if content_length < 0 or content_length > 10 * 1024 * 1024:
            raise ValueError('Request body is too large')
        remote = _connect_public(host, port, HTTP_PORTS)
        remote.sendall(outbound)
        remaining = max(0, content_length - len(remainder))
        while remaining:
            chunk = client_socket.recv(min(16384, remaining))
            if not chunk:
                raise ValueError('Incomplete request body')
            remote.sendall(chunk)
            remaining -= len(chunk)
        log_activity(host, 'ALLOWED')
        while True:
            data = remote.recv(16384)
            if not data:
                break
            client_socket.sendall(data)
    except (ValueError, socket.timeout) as exc:
        log(f'[REQUEST REJECTED] {addr[0]}: {exc}')
        try:
            _send_error(client_socket, '400 Bad Request', str(exc))
        except OSError:
            pass
    except Exception as exc:
        log(f'[PROXY ERROR] {addr[0]}: {exc}')
        try:
            _send_error(client_socket, '502 Bad Gateway', 'Proxy request failed')
        except OSError:
            pass
    finally:
        if remote is not None:
            close_socket(remote)
        if client_socket is not None:
            close_socket(client_socket)


def start_proxy(ready_event=None, startup_error=None, host='127.0.0.1', port=8080):
    global server_socket, proxy_running, proxy_status, proxy_error
    ready_event = ready_event or threading.Event()
    startup_error = startup_error if startup_error is not None else []
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(50)
        server_socket.settimeout(1)
        proxy_running = True
        proxy_status = 'RUNNING'
        proxy_error = ''
        ready_event.set()
        log(f'[PROXY STARTED] {host}:{port}')
        while proxy_running:
            try:
                client, addr = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if not proxy_running:
                    break
                raise
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except Exception as exc:
        proxy_status = 'ERROR'
        proxy_error = str(exc)
        startup_error.append(str(exc))
        ready_event.set()
        log(f'[PROXY ERROR] {exc}')
    finally:
        proxy_running = False
        if proxy_status != 'ERROR':
            proxy_status = 'STOPPED'
        if server_socket:
            close_socket(server_socket)
            server_socket = None
        log('[PROXY STOPPED]')


def get_proxy_status():
    return proxy_status, proxy_error


def stop_proxy():
    global proxy_running, server_socket
    proxy_running = False
    if server_socket:
        close_socket(server_socket)
    clear_all_connections()
