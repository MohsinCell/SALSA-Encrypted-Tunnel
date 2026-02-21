import json
import logging
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from config import SalsaConfig, hash_password
from deimos_wrapper import DeimosCipher, EncryptionSession, _find_dll
from protocol import PacketType, read_framed_message, send_framed_message
from tunnel_manager import TunnelManager, TunnelState, create_server_tunnel_manager

logger = logging.getLogger(__name__)

@dataclass
class ClientSession:
    sock: socket.socket
    client_id: str
    username: str
    address: tuple
    session_key: bytes
    tunnel_manager: Optional[TunnelManager] = None
    assigned_ip: str = ""
    connected_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    authenticated: bool = False

class VPNServer:

    def __init__(self, config: Optional[SalsaConfig] = None):
        self.config = config or SalsaConfig()
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.start_time: Optional[float] = None
        self.clients: Dict[str, ClientSession] = {}
        self._client_lock = threading.Lock()

        self.dll_path = _find_dll()
        self._handshake_psk = "salsa-handshake-psk-v1"

        self._ip_pool: List[str] = [f"10.0.0.{i}" for i in range(2, 255)]
        self._assigned_ips: Dict[str, str] = {}

        self._auth_failures: Dict[str, tuple] = {}
        self._auth_lock = threading.Lock()

        self.on_client_connect: Optional[Callable[[ClientSession], None]] = None
        self.on_client_disconnect: Optional[Callable[[str], None]] = None
        self.on_log: Optional[Callable[[str, str], None]] = None

        if not self.config.users:
            self.config.add_user("admin", "admin123")

    def _log(self, msg: str, level: str = "INFO") -> None:
        getattr(logger, level.lower(), logger.info)(msg)
        if self.on_log:
            try:
                self.on_log(msg, level)
            except Exception:
                pass

    def _assign_ip(self, client_id: str) -> Optional[str]:
        with self._client_lock:
            for ip in self._ip_pool:
                if ip not in self._assigned_ips.values():
                    self._assigned_ips[client_id] = ip
                    return ip
        return None

    def _release_ip(self, client_id: str) -> None:
        with self._client_lock:
            self._assigned_ips.pop(client_id, None)

    def _check_rate_limit(self, ip: str) -> bool:
        with self._auth_lock:
            info = self._auth_failures.get(ip)
            if info is None:
                return True
            fail_count, last_fail = info
            if fail_count >= self.config.max_failed_auth_per_ip:
                if time.time() - last_fail < self.config.auth_lockout_seconds:
                    return False
                del self._auth_failures[ip]
            return True

    def _record_auth_failure(self, ip: str) -> None:
        with self._auth_lock:
            info = self._auth_failures.get(ip, (0, 0))
            self._auth_failures[ip] = (info[0] + 1, time.time())

    def _clear_auth_failures(self, ip: str) -> None:
        with self._auth_lock:
            self._auth_failures.pop(ip, None)

    def start_server(self) -> bool:
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.server_host, self.config.server_port))
            self.server_socket.listen(self.config.max_clients)
            self.server_socket.settimeout(1.0)
            self.running = True
            self.start_time = time.time()
            self._log(f"Server started on {self.config.server_host}:{self.config.server_port}")

            threading.Thread(target=self._cleanup_worker, daemon=True, name="srv-cleanup").start()
            return True
        except Exception as e:
            self._log(f"Failed to start server: {e}", "ERROR")
            return False

    def stop_server(self) -> None:
        self._log("Stopping server...")
        self.running = False

        with self._client_lock:
            for client_id in list(self.clients.keys()):
                self._disconnect_client(client_id, notify=True)

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        self._log("Server stopped")

    def accept_connections(self) -> None:
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                self._log(f"New connection from {client_addr}")
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                    name=f"client-{client_addr[0]}:{client_addr[1]}",
                )
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self._log(f"Accept error: {e}", "ERROR")

    def _handle_client(self, sock: socket.socket, addr: tuple) -> None:
        client_id = None
        try:
            session = self._perform_handshake(sock, addr)
            if session is None:
                sock.close()
                return

            client_id = session.client_id
            with self._client_lock:
                self.clients[client_id] = session

            self._log(f"Client {session.username} ({client_id}) authenticated, IP={session.assigned_ip}")
            if self.on_client_connect:
                self.on_client_connect(session)

            self._run_client_tunnel(session)

        except Exception as e:
            self._log(f"Error handling client {addr}: {e}", "ERROR")
        finally:
            if client_id:
                self._disconnect_client(client_id)

    def _perform_handshake(self, sock: socket.socket, addr: tuple) -> Optional[ClientSession]:
        client_ip = addr[0]

        if not self._check_rate_limit(client_ip):
            self._log(f"Rate limited: {client_ip}", "WARNING")
            try:
                error_payload = json.dumps({"status": "error", "message": "Too many failed attempts"}).encode()
                cipher = DeimosCipher(dll_path=self.dll_path)
                encrypted_resp = cipher.encrypt_bytes(error_payload, self._handshake_psk)
                send_framed_message(sock, PacketType.HANDSHAKE_RESP, encrypted_resp)
            except Exception:
                pass
            return None

        try:
            sock.settimeout(self.config.timeout)

            ptype, encrypted_payload = read_framed_message(sock, timeout=self.config.timeout)
            if ptype != PacketType.HANDSHAKE_REQ:
                self._log(f"Expected HANDSHAKE_REQ, got {ptype}", "ERROR")
                return None

            cipher = DeimosCipher(dll_path=self.dll_path)
            try:
                decrypted = cipher.decrypt_bytes(encrypted_payload, self._handshake_psk)
                request = json.loads(decrypted.decode("utf-8"))
            except Exception as e:
                self._log(f"Handshake decryption failed from {addr}: {e}", "ERROR")
                self._record_auth_failure(client_ip)
                return None

            username = request.get("username", "")
            password = request.get("password", "")

            if not username or not password:
                self._send_handshake_error(sock, cipher, "Missing credentials")
                self._record_auth_failure(client_ip)
                return None

            if not self.config.authenticate(username, password):
                self._send_handshake_error(sock, cipher, "Authentication failed")
                self._record_auth_failure(client_ip)
                self._log(f"Auth failed for '{username}' from {client_ip}", "WARNING")
                return None

            self._clear_auth_failures(client_ip)

            session_key = secrets.token_bytes(32)
            client_id = secrets.token_hex(8)
            assigned_ip = self._assign_ip(client_id)
            if assigned_ip is None:
                self._send_handshake_error(sock, cipher, "No IPs available")
                return None

            response = {
                "status": "success",
                "client_id": client_id,
                "session_key": session_key.hex(),
                "assigned_ip": assigned_ip,
                "server_version": "2.0",
            }
            resp_bytes = json.dumps(response).encode("utf-8")
            encrypted_resp = cipher.encrypt_bytes(resp_bytes, self._handshake_psk)
            send_framed_message(sock, PacketType.HANDSHAKE_RESP, encrypted_resp)

            session = ClientSession(
                sock=sock,
                client_id=client_id,
                username=username,
                address=addr,
                session_key=session_key,
                assigned_ip=assigned_ip,
                authenticated=True,
            )

            tunnel_config_payload = json.dumps(self.config.get_tunnel_config_payload()).encode("utf-8")
            enc_session = EncryptionSession.from_session_key(session_key, dll_path=self.dll_path)
            encrypted_config = enc_session.seal(tunnel_config_payload)
            send_framed_message(sock, PacketType.TUNNEL_CONFIG, encrypted_config)

            sock.settimeout(None)
            return session

        except Exception as e:
            self._log(f"Handshake error with {addr}: {e}", "ERROR")
            return None

    def _send_handshake_error(self, sock: socket.socket, cipher: DeimosCipher, message: str) -> None:
        try:
            error = json.dumps({"status": "error", "message": message}).encode("utf-8")
            encrypted = cipher.encrypt_bytes(error, self._handshake_psk)
            send_framed_message(sock, PacketType.HANDSHAKE_RESP, encrypted)
        except Exception:
            pass

    def _run_client_tunnel(self, session: ClientSession) -> None:
        tunnel = create_server_tunnel_manager(
            session_key=session.session_key,
            sock=session.sock,
            config={
                "mtu": self.config.mtu,
                "keepalive_interval": self.config.keepalive_interval,
                "timeout": self.config.timeout,
                "buffer_size": self.config.buffer_size,
                "subnet": self.config.tunnel_subnet,
                "dns_servers": self.config.dns_servers,
            },
            dll_path=self.dll_path,
        )
        session.tunnel_manager = tunnel

        def on_data(data: bytes, ptype: PacketType) -> None:
            session.last_activity = time.time()
            session.bytes_received += len(data)

            if ptype == PacketType.SOCKS_CONNECT:
                self._handle_socks_connect(session, data)
            elif ptype == PacketType.SOCKS_DATA:
                self._handle_socks_data(session, data)
            elif ptype == PacketType.SOCKS_CLOSE:
                self._handle_socks_close(session, data)
            elif ptype == PacketType.DATA:
                logger.debug(f"Data from {session.client_id}: {len(data)} bytes")

        tunnel.on_data_received = on_data
        tunnel.start()

        while self.running and tunnel.is_connected():
            time.sleep(0.5)

    def _handle_socks_connect(self, session: ClientSession, data: bytes) -> None:
        try:
            request = json.loads(data.decode("utf-8"))
            conn_id = request["conn_id"]
            host = request["host"]
            port = request["port"]

            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10)
            remote_sock.connect((host, port))
            remote_sock.settimeout(None)

            if not hasattr(session, "_socks_conns"):
                session._socks_conns = {}
            session._socks_conns[conn_id] = remote_sock

            resp = json.dumps({"conn_id": conn_id, "status": "connected"}).encode("utf-8")
            session.tunnel_manager.send_over_socket(resp, PacketType.SOCKS_CONNECT)

            t = threading.Thread(
                target=self._relay_remote_to_client,
                args=(session, conn_id, remote_sock),
                daemon=True,
            )
            t.start()

        except Exception as e:
            logger.error(f"SOCKS connect failed: {e}")
            try:
                resp = json.dumps({"conn_id": request.get("conn_id", ""), "status": "error", "error": str(e)}).encode()
                session.tunnel_manager.send_over_socket(resp, PacketType.SOCKS_CONNECT)
            except Exception:
                pass

    def _handle_socks_data(self, session: ClientSession, data: bytes) -> None:
        try:
            conn_id = data[:16].decode("ascii")
            payload = data[16:]
            conns = getattr(session, "_socks_conns", {})
            remote_sock = conns.get(conn_id)
            if remote_sock:
                remote_sock.sendall(payload)
        except Exception as e:
            logger.error(f"SOCKS data relay failed: {e}")

    def _handle_socks_close(self, session: ClientSession, data: bytes) -> None:
        try:
            conn_id = data.decode("utf-8")
            conns = getattr(session, "_socks_conns", {})
            remote_sock = conns.pop(conn_id, None)
            if remote_sock:
                remote_sock.close()
        except Exception as e:
            logger.error(f"SOCKS close failed: {e}")

    def _relay_remote_to_client(self, session: ClientSession, conn_id: str, remote_sock: socket.socket) -> None:
        try:
            while self.running and session.authenticated:
                try:
                    data = remote_sock.recv(4096)
                    if not data:
                        break
                    payload = conn_id.encode("ascii") + data
                    session.tunnel_manager.send_over_socket(payload, PacketType.SOCKS_DATA)
                    session.bytes_sent += len(data)
                except (ConnectionError, OSError):
                    break
        except Exception as e:
            logger.error(f"Remote relay error: {e}")
        finally:
            try:
                remote_sock.close()
            except Exception:
                pass
            try:
                session.tunnel_manager.send_over_socket(conn_id.encode("utf-8"), PacketType.SOCKS_CLOSE)
            except Exception:
                pass

    def _disconnect_client(self, client_id: str, notify: bool = False) -> None:
        with self._client_lock:
            session = self.clients.pop(client_id, None)
        if session is None:
            return

        if session.tunnel_manager:
            session.tunnel_manager.stop()

        for sock in getattr(session, "_socks_conns", {}).values():
            try:
                sock.close()
            except Exception:
                pass

        try:
            session.sock.close()
        except Exception:
            pass

        self._release_ip(client_id)
        self._log(f"Client {session.username} ({client_id}) disconnected")
        if self.on_client_disconnect:
            self.on_client_disconnect(client_id)

    def _cleanup_worker(self) -> None:
        while self.running:
            now = time.time()
            timed_out = []
            with self._client_lock:
                for cid, session in self.clients.items():
                    if now - session.last_activity > self.config.client_timeout:
                        timed_out.append(cid)
            for cid in timed_out:
                self._log(f"Client {cid} timed out", "WARNING")
                self._disconnect_client(cid)
            time.sleep(self.config.cleanup_interval)

    def get_server_stats(self) -> Dict[str, Any]:
        with self._client_lock:
            client_list = []
            for s in self.clients.values():
                tunnel_stats = s.tunnel_manager.get_stats() if s.tunnel_manager else {}
                client_list.append({
                    "client_id": s.client_id,
                    "username": s.username,
                    "address": f"{s.address[0]}:{s.address[1]}",
                    "assigned_ip": s.assigned_ip,
                    "connected_at": s.connected_at,
                    "last_activity": s.last_activity,
                    "bytes_sent": s.bytes_sent,
                    "bytes_received": s.bytes_received,
                    "tunnel_state": tunnel_stats.get("state", "unknown"),
                })
            return {
                "running": self.running,
                "uptime": (time.time() - self.start_time) if self.start_time else 0,
                "active_clients": len(self.clients),
                "max_clients": self.config.max_clients,
                "clients": client_list,
            }

    def get_aggregate_tunnel_stats(self) -> Dict[str, Any]:
        totals = {
            "bytes_sent": 0, "bytes_received": 0,
            "packets_sent": 0, "packets_received": 0,
            "encryption_time": 0.0, "decryption_time": 0.0,
            "encryption_errors": 0, "decryption_errors": 0,
        }
        with self._client_lock:
            for s in self.clients.values():
                if s.tunnel_manager:
                    st = s.tunnel_manager.get_stats()
                    for k in totals:
                        totals[k] += st.get(k, 0)
        return totals

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    config = SalsaConfig()
    config.add_user("testuser", "testpass")
    config.add_user("admin", "admin123")
    server = VPNServer(config=config)
    try:
        if server.start_server():
            print(f"Salsa VPN Server running on {config.server_host}:{config.server_port}")
            print("Press Ctrl+C to stop")
            server.accept_connections()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop_server()

if __name__ == "__main__":
    main()
