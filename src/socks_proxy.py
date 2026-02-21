import logging
import socket
import struct
import threading
import time
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_NO_ACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

class SOCKSProxy:

    def __init__(self, vpn_client: Any):
        self.vpn_client = vpn_client
        self.host = "127.0.0.1"
        self.port = 1080
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self._lock = threading.Lock()

        self.stats = {
            "active_connections": 0,
            "total_connections": 0,
            "bytes_proxied": 0,
            "failed_connections": 0,
        }

        self.require_auth = False
        self.auth_username = ""
        self.auth_password = ""

        self.on_log: Optional[Callable[[str, str], None]] = None

    def _log(self, msg: str, level: str = "INFO") -> None:
        getattr(logger, level.lower(), logger.info)(msg)
        if self.on_log:
            try:
                self.on_log(msg, level)
            except Exception:
                pass

    def start(self, host: str = "127.0.0.1", port: int = 1080) -> bool:
        self.host = host
        self.port = port
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(128)
            self.server_socket.settimeout(1.0)
            self.running = True

            accept_thread = threading.Thread(target=self._accept_loop, daemon=True, name="socks-accept")
            accept_thread.start()

            self._log(f"SOCKS5 proxy started on {self.host}:{self.port}")
            return True
        except Exception as e:
            self._log(f"Failed to start SOCKS5 proxy: {e}", "ERROR")
            return False

    def stop(self) -> None:
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        self._log("SOCKS5 proxy stopped")

    def _accept_loop(self) -> None:
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                self.stats["total_connections"] += 1
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self._log(f"SOCKS accept error: {e}", "ERROR")

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple) -> None:
        with self._lock:
            self.stats["active_connections"] += 1
        try:
            client_sock.settimeout(30)

            if not self._negotiate_auth(client_sock):
                return

            host, port = self._read_connect_request(client_sock)
            if host is None:
                return

            self._log(f"SOCKS CONNECT {host}:{port} from {client_addr}")

            conn_id = self.vpn_client.socks_connect(host, port)
            if conn_id is None:
                self._send_reply(client_sock, REP_HOST_UNREACHABLE)
                self.stats["failed_connections"] += 1
                return

            self._send_reply(client_sock, REP_SUCCESS)

            self._relay(client_sock, conn_id)

        except Exception as e:
            logger.debug(f"SOCKS client error: {e}")
            self.stats["failed_connections"] += 1
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            with self._lock:
                self.stats["active_connections"] -= 1

    def _negotiate_auth(self, sock: socket.socket) -> bool:
        data = sock.recv(2)
        if len(data) < 2 or data[0] != SOCKS_VERSION:
            return False

        nmethods = data[1]
        methods = sock.recv(nmethods)
        if len(methods) != nmethods:
            return False

        if self.require_auth:
            if AUTH_USERPASS not in methods:
                sock.sendall(bytes([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]))
                return False
            sock.sendall(bytes([SOCKS_VERSION, AUTH_USERPASS]))
            return self._authenticate_userpass(sock)
        else:
            if AUTH_NONE in methods:
                sock.sendall(bytes([SOCKS_VERSION, AUTH_NONE]))
                return True
            else:
                sock.sendall(bytes([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]))
                return False

    def _authenticate_userpass(self, sock: socket.socket) -> bool:
        ver = sock.recv(1)
        if not ver or ver[0] != 0x01:
            return False

        ulen_b = sock.recv(1)
        if not ulen_b:
            return False
        ulen = ulen_b[0]
        username = sock.recv(ulen).decode("utf-8", errors="replace")

        plen_b = sock.recv(1)
        if not plen_b:
            return False
        plen = plen_b[0]
        password = sock.recv(plen).decode("utf-8", errors="replace")

        if username == self.auth_username and password == self.auth_password:
            sock.sendall(bytes([0x01, 0x00]))
            return True
        else:
            sock.sendall(bytes([0x01, 0x01]))
            return False

    def _read_connect_request(self, sock: socket.socket) -> tuple:
        header = sock.recv(4)
        if len(header) < 4:
            return None, None

        ver, cmd, _, atyp = header

        if ver != SOCKS_VERSION:
            return None, None

        if cmd != CMD_CONNECT:
            self._send_reply(sock, REP_COMMAND_NOT_SUPPORTED)
            return None, None

        if atyp == ATYP_IPV4:
            addr_bytes = sock.recv(4)
            if len(addr_bytes) < 4:
                return None, None
            host = socket.inet_ntoa(addr_bytes)
        elif atyp == ATYP_DOMAIN:
            domain_len = sock.recv(1)
            if not domain_len:
                return None, None
            domain = sock.recv(domain_len[0])
            if len(domain) != domain_len[0]:
                return None, None
            host = domain.decode("utf-8", errors="replace")
        elif atyp == ATYP_IPV6:
            self._send_reply(sock, REP_ADDRESS_TYPE_NOT_SUPPORTED)
            return None, None
        else:
            self._send_reply(sock, REP_ADDRESS_TYPE_NOT_SUPPORTED)
            return None, None

        port_bytes = sock.recv(2)
        if len(port_bytes) < 2:
            return None, None
        port = struct.unpack("!H", port_bytes)[0]

        return host, port

    def _send_reply(self, sock: socket.socket, rep: int) -> None:
        reply = struct.pack("!BBBB4sH", SOCKS_VERSION, rep, 0x00, ATYP_IPV4, b"\x00\x00\x00\x00", 0)
        try:
            sock.sendall(reply)
        except Exception:
            pass

    def _relay(self, client_sock: socket.socket, conn_id: str) -> None:
        closed = threading.Event()

        def on_tunnel_data(data: bytes) -> None:
            if not data:
                closed.set()
                return
            try:
                client_sock.sendall(data)
                self.stats["bytes_proxied"] += len(data)
            except Exception:
                closed.set()

        self.vpn_client.socks_set_callback(conn_id, on_tunnel_data)

        def client_to_tunnel() -> None:
            try:
                while not closed.is_set():
                    try:
                        data = client_sock.recv(4096)
                        if not data:
                            break
                        self.vpn_client.socks_send(conn_id, data)
                        self.stats["bytes_proxied"] += len(data)
                    except (ConnectionError, OSError):
                        break
            finally:
                closed.set()
                self.vpn_client.socks_close(conn_id)

        relay_thread = threading.Thread(target=client_to_tunnel, daemon=True)
        relay_thread.start()

        closed.wait()
        relay_thread.join(timeout=5)

    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()
