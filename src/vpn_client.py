import json
import logging
import secrets
import socket
import threading
import time
from typing import Any, Callable, Dict, Optional

from deimos_wrapper import DeimosCipher, EncryptionSession, _find_dll
from protocol import PacketType, read_framed_message, send_framed_message
from tunnel_manager import TunnelManager, TunnelState, create_client_tunnel_manager

logger = logging.getLogger(__name__)

class VPNClient:

    def __init__(self, server_host: str = "127.0.0.1", server_port: int = 8080):
        self.server_host = server_host
        self.server_port = server_port
        self.sock: Optional[socket.socket] = None
        self.tunnel_manager: Optional[TunnelManager] = None
        self.running = False
        self.authenticated = False
        self.session_key: Optional[bytes] = None
        self.client_id: Optional[str] = None
        self.assigned_ip: Optional[str] = None

        self.dll_path = _find_dll()
        self._handshake_psk = "salsa-handshake-psk-v1"

        self.tunnel_config: Dict[str, Any] = {}

        self._reconnect_enabled = False
        self._reconnect_thread: Optional[threading.Thread] = None
        self._credentials: Optional[tuple] = None

        self._socks_callbacks: Dict[str, Callable[[bytes], None]] = {}
        self._socks_events: Dict[str, threading.Event] = {}
        self._socks_results: Dict[str, Any] = {}
        self._socks_lock = threading.Lock()

        self.on_status_change: Optional[Callable[[str, str], None]] = None
        self.on_log: Optional[Callable[[str, str], None]] = None
        self.on_tunnel_data: Optional[Callable[[bytes, PacketType], None]] = None

    def _log(self, msg: str, level: str = "INFO") -> None:
        getattr(logger, level.lower(), logger.info)(msg)
        if self.on_log:
            try:
                self.on_log(msg, level)
            except Exception:
                pass

    def _notify_status(self, status: str, detail: str = "") -> None:
        if self.on_status_change:
            try:
                self.on_status_change(status, detail)
            except Exception:
                pass

    def connect(self, username: str, password: str, auto_reconnect: bool = False) -> bool:
        self._credentials = (username, password)
        self._reconnect_enabled = auto_reconnect

        try:
            self._notify_status("connecting", f"Connecting to {self.server_host}:{self.server_port}")

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(15)
            self.sock.connect((self.server_host, self.server_port))
            self._log(f"TCP connected to {self.server_host}:{self.server_port}")

            if not self._perform_handshake(username, password):
                self.disconnect()
                return False

            self._receive_tunnel_config()

            self.tunnel_manager = create_client_tunnel_manager(
                session_key=self.session_key,
                sock=self.sock,
                config=self.tunnel_config,
                dll_path=self.dll_path,
            )
            self.tunnel_manager.on_data_received = self._on_tunnel_data
            self.tunnel_manager.on_state_change = self._on_tunnel_state_change

            self.running = True
            self.tunnel_manager.start()

            self._notify_status("connected", f"IP: {self.assigned_ip}")
            self._log(f"VPN connected. Client ID: {self.client_id}, IP: {self.assigned_ip}")
            return True

        except Exception as e:
            self._log(f"Connection failed: {e}", "ERROR")
            self._notify_status("error", str(e))
            self.disconnect()
            if auto_reconnect:
                self._start_reconnect()
            return False

    def _perform_handshake(self, username: str, password: str) -> bool:
        try:
            cipher = DeimosCipher(dll_path=self.dll_path)

            creds = json.dumps({
                "username": username,
                "password": password,
                "client_version": "2.0",
            }).encode("utf-8")
            encrypted_creds = cipher.encrypt_bytes(creds, self._handshake_psk)
            send_framed_message(self.sock, PacketType.HANDSHAKE_REQ, encrypted_creds)

            ptype, encrypted_resp = read_framed_message(self.sock, timeout=15)
            if ptype != PacketType.HANDSHAKE_RESP:
                self._log(f"Expected HANDSHAKE_RESP, got {ptype}", "ERROR")
                return False

            resp_bytes = cipher.decrypt_bytes(encrypted_resp, self._handshake_psk)
            response = json.loads(resp_bytes.decode("utf-8"))

            if response.get("status") != "success":
                self._log(f"Auth failed: {response.get('message', 'Unknown')}", "ERROR")
                self._notify_status("auth_failed", response.get("message", ""))
                return False

            self.client_id = response["client_id"]
            self.session_key = bytes.fromhex(response["session_key"])
            self.assigned_ip = response.get("assigned_ip", "")
            self.authenticated = True
            self._log(f"Handshake OK. Client: {self.client_id}")
            return True

        except Exception as e:
            self._log(f"Handshake error: {e}", "ERROR")
            return False

    def _receive_tunnel_config(self) -> None:
        try:
            ptype, encrypted_config = read_framed_message(self.sock, timeout=10)
            if ptype != PacketType.TUNNEL_CONFIG:
                self._log(f"Expected TUNNEL_CONFIG, got {ptype}", "WARNING")
                return

            enc_session = EncryptionSession.from_session_key(self.session_key, dll_path=self.dll_path)
            config_bytes = enc_session.open(encrypted_config)
            self.tunnel_config = json.loads(config_bytes.decode("utf-8"))
            self._log(f"Tunnel config received: subnet={self.tunnel_config.get('subnet')}")
        except Exception as e:
            self._log(f"Failed to receive tunnel config: {e}", "WARNING")

    def _on_tunnel_data(self, data: bytes, ptype: PacketType) -> None:
        if ptype == PacketType.SOCKS_CONNECT:
            self._handle_socks_connect_response(data)
        elif ptype == PacketType.SOCKS_DATA:
            self._handle_socks_data_from_server(data)
        elif ptype == PacketType.SOCKS_CLOSE:
            self._handle_socks_close_from_server(data)
        elif ptype == PacketType.DATA:
            if self.on_tunnel_data:
                self.on_tunnel_data(data, ptype)

    def _on_tunnel_state_change(self, state: TunnelState) -> None:
        if state == TunnelState.ERROR:
            self._log("Tunnel connection lost", "ERROR")
            self.running = False
            self.authenticated = False
            self._notify_status("disconnected", "Server closed the connection")
            if self._reconnect_enabled:
                self._start_reconnect()
        elif state == TunnelState.DISCONNECTED:
            self.running = False
            self.authenticated = False
            self._notify_status("disconnected", "Tunnel closed")

    def socks_connect(self, host: str, port: int) -> Optional[str]:
        conn_id = secrets.token_hex(8)
        event = threading.Event()
        with self._socks_lock:
            self._socks_events[conn_id] = event
            self._socks_results[conn_id] = None

        request = json.dumps({"conn_id": conn_id, "host": host, "port": port}).encode("utf-8")
        if not self.tunnel_manager or not self.tunnel_manager.send_over_socket(request, PacketType.SOCKS_CONNECT):
            return None

        if not event.wait(timeout=15):
            self._log(f"SOCKS connect timeout for {host}:{port}", "ERROR")
            return None

        result = self._socks_results.pop(conn_id, None)
        self._socks_events.pop(conn_id, None)

        if result and result.get("status") == "connected":
            return conn_id
        return None

    def socks_send(self, conn_id: str, data: bytes) -> bool:
        if not self.tunnel_manager:
            return False
        payload = conn_id.encode("ascii") + data
        return self.tunnel_manager.send_over_socket(payload, PacketType.SOCKS_DATA)

    def socks_close(self, conn_id: str) -> None:
        with self._socks_lock:
            self._socks_callbacks.pop(conn_id, None)
        if self.tunnel_manager:
            self.tunnel_manager.send_over_socket(conn_id.encode("utf-8"), PacketType.SOCKS_CLOSE)

    def socks_set_callback(self, conn_id: str, callback: Callable[[bytes], None]) -> None:
        with self._socks_lock:
            self._socks_callbacks[conn_id] = callback

    def _handle_socks_connect_response(self, data: bytes) -> None:
        try:
            result = json.loads(data.decode("utf-8"))
            conn_id = result.get("conn_id", "")
            with self._socks_lock:
                self._socks_results[conn_id] = result
                event = self._socks_events.get(conn_id)
            if event:
                event.set()
        except Exception as e:
            logger.error(f"SOCKS connect response error: {e}")

    def _handle_socks_data_from_server(self, data: bytes) -> None:
        try:
            conn_id = data[:16].decode("ascii")
            payload = data[16:]
            with self._socks_lock:
                cb = self._socks_callbacks.get(conn_id)
            if cb:
                cb(payload)
        except Exception as e:
            logger.error(f"SOCKS data from server error: {e}")

    def _handle_socks_close_from_server(self, data: bytes) -> None:
        try:
            conn_id = data.decode("utf-8")
            with self._socks_lock:
                cb = self._socks_callbacks.pop(conn_id, None)
            if cb:
                cb(b"")
        except Exception as e:
            logger.error(f"SOCKS close from server error: {e}")

    def _start_reconnect(self) -> None:
        if self._reconnect_thread and self._reconnect_thread.is_alive():
            return
        self._reconnect_thread = threading.Thread(target=self._reconnect_loop, daemon=True)
        self._reconnect_thread.start()

    def _reconnect_loop(self) -> None:
        delay = 1
        max_delay = 60
        while self._reconnect_enabled and not self.authenticated:
            self._log(f"Reconnecting in {delay}s...", "INFO")
            self._notify_status("reconnecting", f"Retry in {delay}s")
            time.sleep(delay)
            if not self._reconnect_enabled:
                break
            if self._credentials:
                if self.connect(self._credentials[0], self._credentials[1], auto_reconnect=True):
                    return
            delay = min(delay * 2, max_delay)

    def disconnect(self) -> None:
        self._reconnect_enabled = False
        self.running = False

        if self.tunnel_manager:
            self.tunnel_manager.stop()
            self.tunnel_manager = None

        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        self.authenticated = False
        self.session_key = None
        self.client_id = None
        self.assigned_ip = None

        with self._socks_lock:
            self._socks_callbacks.clear()
            self._socks_events.clear()
            self._socks_results.clear()

        self._notify_status("disconnected")
        self._log("VPN client disconnected")

    def get_status(self) -> Dict[str, Any]:
        tunnel_stats = self.tunnel_manager.get_stats() if self.tunnel_manager else {}
        return {
            "connected": self.running and self.authenticated,
            "server": f"{self.server_host}:{self.server_port}",
            "client_id": self.client_id,
            "assigned_ip": self.assigned_ip,
            "tunnel_state": tunnel_stats.get("state", "disconnected"),
            "bytes_sent": tunnel_stats.get("bytes_sent", 0),
            "bytes_received": tunnel_stats.get("bytes_received", 0),
            "packets_sent": tunnel_stats.get("packets_sent", 0),
            "packets_received": tunnel_stats.get("packets_received", 0),
            "encryption_time": tunnel_stats.get("encryption_time", 0),
            "decryption_time": tunnel_stats.get("decryption_time", 0),
            "uptime": tunnel_stats.get("uptime", 0),
        }

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    client = VPNClient()
    try:
        if client.connect("testuser", "testpass"):
            print("VPN connected!")
            print("Status:", client.get_status())
            while client.running and client.authenticated:
                time.sleep(1)
        else:
            print("Failed to connect")
    except KeyboardInterrupt:
        print("\nDisconnecting...")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
