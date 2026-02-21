import logging
import socket
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from deimos_wrapper import EncryptionSession
from protocol import PacketType, frame_message, read_framed_message, send_framed_message

logger = logging.getLogger(__name__)

class TunnelState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"

@dataclass
class TunnelConfig:
    mtu: int = 1500
    keepalive_interval: int = 30
    timeout: int = 30
    buffer_size: int = 4096
    subnet: str = "10.0.0.0/24"
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])

    @classmethod
    def from_dict(cls, d: dict) -> "TunnelConfig":
        valid = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in d.items() if k in valid})

    def update(self, d: dict) -> None:
        valid = {f.name for f in self.__dataclass_fields__.values()}
        for k, v in d.items():
            if k in valid:
                setattr(self, k, v)

class TunnelManager:

    SEQ_HEADER = 4

    def __init__(
        self,
        session: EncryptionSession,
        sock: socket.socket,
        config: Optional[TunnelConfig] = None,
        is_server: bool = False,
    ):
        self.session = session
        self.sock = sock
        self.config = config or TunnelConfig()
        self.is_server = is_server

        self.state = TunnelState.DISCONNECTED
        self.running = False
        self.start_time: Optional[float] = None
        self._lock = threading.Lock()
        self._threads: List[threading.Thread] = []

        self._send_seq: int = 0
        self._recv_seq: int = 0

        self._bw_window: deque = deque(maxlen=120)

        self.stats: Dict = {
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets_sent": 0,
            "packets_received": 0,
            "encryption_time": 0.0,
            "decryption_time": 0.0,
            "encryption_errors": 0,
            "decryption_errors": 0,
            "sequence_errors": 0,
            "keepalives_sent": 0,
            "keepalives_received": 0,
        }

        self.on_state_change: Optional[Callable[[TunnelState], None]] = None
        self.on_error: Optional[Callable[[Exception], None]] = None
        self.on_data_received: Optional[Callable[[bytes, PacketType], None]] = None

    def _set_state(self, new: TunnelState) -> None:
        if self.state != new:
            old = self.state
            self.state = new
            logger.info(f"Tunnel state: {old.value} -> {new.value}")
            if self.on_state_change:
                try:
                    self.on_state_change(new)
                except Exception:
                    pass

    def is_connected(self) -> bool:
        return self.state == TunnelState.CONNECTED

    def is_active(self) -> bool:
        return self.is_connected()

    def _encrypt(self, data: bytes) -> bytes:
        t0 = time.time()
        try:
            enc = self.session.seal(data)
            self.stats["encryption_time"] += time.time() - t0
            return enc
        except Exception as e:
            self.stats["encryption_errors"] += 1
            raise

    def _decrypt(self, data: bytes) -> bytes:
        t0 = time.time()
        try:
            dec = self.session.open(data)
            self.stats["decryption_time"] += time.time() - t0
            return dec
        except Exception as e:
            self.stats["decryption_errors"] += 1
            raise

    def _next_seq(self) -> int:
        with self._lock:
            self._send_seq += 1
            return self._send_seq

    def _validate_seq(self, seq: int) -> bool:
        if seq <= self._recv_seq:
            self.stats["sequence_errors"] += 1
            logger.warning(f"Sequence error: got {seq}, expected > {self._recv_seq}")
            return False
        self._recv_seq = seq
        return True

    def _fragment(self, data: bytes) -> List[bytes]:
        max_chunk = self.config.mtu - 100
        if max_chunk <= 0:
            max_chunk = 1400
        if len(data) <= max_chunk:
            return [data]
        return [data[i : i + max_chunk] for i in range(0, len(data), max_chunk)]

    def send_over_socket(self, data: bytes, ptype: PacketType = PacketType.DATA) -> bool:
        try:
            fragments = self._fragment(data) if ptype == PacketType.DATA else [data]
            for frag in fragments:
                seq = self._next_seq()
                payload_with_seq = struct.pack("!I", seq) + frag
                encrypted = self._encrypt(payload_with_seq)
                send_framed_message(self.sock, ptype, encrypted)
                self.stats["bytes_sent"] += len(encrypted)
                self.stats["packets_sent"] += 1
            return True
        except Exception as e:
            logger.error(f"send_over_socket failed: {e}")
            if self.on_error:
                self.on_error(e)
            return False

    def recv_from_socket(self) -> Optional[Tuple[PacketType, bytes]]:
        recv_timeout = self.config.keepalive_interval * 3
        try:
            ptype, encrypted = read_framed_message(self.sock, timeout=recv_timeout)
            decrypted = self._decrypt(encrypted)

            if len(decrypted) < self.SEQ_HEADER:
                logger.error("Decrypted payload too short for sequence header")
                return None
            seq = struct.unpack("!I", decrypted[: self.SEQ_HEADER])[0]
            payload = decrypted[self.SEQ_HEADER :]

            self._validate_seq(seq)

            self.stats["bytes_received"] += len(encrypted)
            self.stats["packets_received"] += 1

            self._bw_window.append((time.time(), len(encrypted)))

            if ptype == PacketType.KEEPALIVE:
                self.stats["keepalives_received"] += 1
            elif ptype == PacketType.KEEPALIVE_ACK:
                self.stats["keepalives_received"] += 1

            return ptype, payload
        except socket.timeout:
            raise
        except ConnectionError as e:
            logger.debug(f"recv_from_socket connection closed: {e}")
            return None
        except OSError as e:
            logger.debug(f"recv_from_socket OS error: {e}")
            return None
        except Exception as e:
            logger.error(f"recv_from_socket failed: {e}")
            return None

    def _keepalive_worker(self) -> None:
        while self.running:
            try:
                self.send_over_socket(b"ping", PacketType.KEEPALIVE)
                self.stats["keepalives_sent"] += 1
            except Exception as e:
                logger.error(f"Keepalive error: {e}")
            for _ in range(self.config.keepalive_interval * 10):
                if not self.running:
                    return
                time.sleep(0.1)

    def _recv_worker(self) -> None:
        while self.running:
            try:
                result = self.recv_from_socket()
            except socket.timeout:
                continue
            if result is None:
                if self.running:
                    logger.warning("Connection lost in recv_worker")
                    self._set_state(TunnelState.ERROR)
                break

            ptype, payload = result

            if ptype == PacketType.KEEPALIVE:
                try:
                    self.send_over_socket(b"pong", PacketType.KEEPALIVE_ACK)
                except Exception:
                    pass
            elif ptype == PacketType.DISCONNECT:
                logger.info("Received DISCONNECT from peer")
                self.running = False
                break
            else:
                if self.on_data_received:
                    try:
                        self.on_data_received(payload, ptype)
                    except Exception as e:
                        logger.error(f"on_data_received callback error: {e}")

    def start(self) -> bool:
        try:
            self._set_state(TunnelState.CONNECTING)
            self.start_time = time.time()
            self.running = True

            recv_t = threading.Thread(target=self._recv_worker, daemon=True, name="tunnel-recv")
            ka_t = threading.Thread(target=self._keepalive_worker, daemon=True, name="tunnel-keepalive")
            recv_t.start()
            ka_t.start()
            self._threads = [recv_t, ka_t]

            self._set_state(TunnelState.CONNECTED)
            logger.info("Tunnel started")
            return True
        except Exception as e:
            logger.error(f"Failed to start tunnel: {e}")
            self._set_state(TunnelState.ERROR)
            return False

    def stop(self) -> None:
        if not self.running:
            return
        self._set_state(TunnelState.DISCONNECTING)
        self.running = False

        try:
            self.send_over_socket(b"bye", PacketType.DISCONNECT)
        except Exception:
            pass

        for t in self._threads:
            t.join(timeout=3)
        self._threads.clear()
        self._set_state(TunnelState.DISCONNECTED)
        logger.info("Tunnel stopped")

    def get_bandwidth(self) -> Tuple[float, float]:
        now = time.time()
        cutoff = now - 10
        recent = [(t, b) for t, b in self._bw_window if t >= cutoff]
        if not recent:
            return 0.0, 0.0
        total_bytes = sum(b for _, b in recent)
        duration = now - recent[0][0]
        if duration <= 0:
            return 0.0, 0.0
        bps = total_bytes / duration
        return bps * 0.5, bps * 0.5

    def get_stats(self) -> Dict:
        stats = self.stats.copy()
        stats["state"] = self.state.value
        stats["uptime"] = (time.time() - self.start_time) if self.start_time else 0
        bw_in, bw_out = self.get_bandwidth()
        stats["bandwidth_in_bps"] = bw_in
        stats["bandwidth_out_bps"] = bw_out
        return stats

def create_server_tunnel_manager(
    session_key: bytes,
    sock: socket.socket,
    config: Optional[dict] = None,
    dll_path: Optional[str] = None,
) -> TunnelManager:
    enc_session = EncryptionSession.from_session_key(session_key, dll_path=dll_path)
    tc = TunnelConfig.from_dict(config) if config else TunnelConfig()
    return TunnelManager(session=enc_session, sock=sock, config=tc, is_server=True)

def create_client_tunnel_manager(
    session_key: bytes,
    sock: socket.socket,
    config: Optional[dict] = None,
    dll_path: Optional[str] = None,
) -> TunnelManager:
    enc_session = EncryptionSession.from_session_key(session_key, dll_path=dll_path)
    tc = TunnelConfig.from_dict(config) if config else TunnelConfig()
    return TunnelManager(session=enc_session, sock=sock, config=tc, is_server=False)
