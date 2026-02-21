import struct
import socket
from enum import IntEnum
from typing import Tuple, Optional

class PacketType(IntEnum):
    HANDSHAKE_REQ = 0x01
    HANDSHAKE_RESP = 0x02
    DATA = 0x10
    KEEPALIVE = 0x20
    KEEPALIVE_ACK = 0x21
    DISCONNECT = 0x30
    TUNNEL_CONFIG = 0x40
    SOCKS_CONNECT = 0x50
    SOCKS_DATA = 0x51
    SOCKS_CLOSE = 0x52
    ERROR = 0xFF

HEADER_SIZE = 5
MAX_PAYLOAD_SIZE = 4 * 1024 * 1024

def frame_message(ptype: PacketType, payload: bytes) -> bytes:
    body_length = 1 + len(payload)
    return struct.pack("!IB", body_length, int(ptype)) + payload

def read_exact(sock: socket.socket, n: int, timeout: Optional[float] = None) -> bytes:
    if timeout is not None:
        sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed (read {len(buf)}/{n} bytes)")
        buf.extend(chunk)
    return bytes(buf)

def read_framed_message(sock: socket.socket, timeout: Optional[float] = None) -> Tuple[PacketType, bytes]:
    length_bytes = read_exact(sock, 4, timeout)
    body_length = struct.unpack("!I", length_bytes)[0]

    if body_length < 1:
        raise ValueError("Invalid frame: body_length < 1")
    if body_length - 1 > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload too large: {body_length - 1} bytes")

    body = read_exact(sock, body_length, timeout)
    ptype = PacketType(body[0])
    payload = body[1:]
    return ptype, payload

def send_framed_message(sock: socket.socket, ptype: PacketType, payload: bytes) -> None:
    sock.sendall(frame_message(ptype, payload))
