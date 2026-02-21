import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

PBKDF2_ITERATIONS = 600_000
PBKDF2_HASH = "sha256"
SALT_LENGTH = 32

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    dk = hashlib.pbkdf2_hmac(PBKDF2_HASH, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex() + ":" + dk.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac(PBKDF2_HASH, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        return secrets.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False

@dataclass
class SalsaConfig:
    server_host: str = "0.0.0.0"
    server_port: int = 8080
    max_clients: int = 100
    client_timeout: int = 300
    cleanup_interval: int = 60

    tunnel_subnet: str = "10.0.0.0/24"
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])
    mtu: int = 1500
    buffer_size: int = 4096

    keepalive_interval: int = 30
    timeout: int = 30

    socks_host: str = "127.0.0.1"
    socks_port: int = 1080
    socks_enabled: bool = True

    max_failed_auth_per_ip: int = 5
    auth_lockout_seconds: int = 300

    users: Dict[str, str] = field(default_factory=dict)

    def add_user(self, username: str, password: str) -> None:
        self.users[username] = hash_password(password)

    def remove_user(self, username: str) -> bool:
        return self.users.pop(username, None) is not None

    def authenticate(self, username: str, password: str) -> bool:
        stored = self.users.get(username)
        if stored is None:
            return False
        return verify_password(password, stored)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SalsaConfig":
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_host": self.server_host,
            "server_port": self.server_port,
            "max_clients": self.max_clients,
            "client_timeout": self.client_timeout,
            "tunnel_subnet": self.tunnel_subnet,
            "dns_servers": self.dns_servers,
            "mtu": self.mtu,
            "buffer_size": self.buffer_size,
            "keepalive_interval": self.keepalive_interval,
            "timeout": self.timeout,
            "socks_host": self.socks_host,
            "socks_port": self.socks_port,
            "socks_enabled": self.socks_enabled,
        }

    def get_tunnel_config_payload(self) -> dict:
        return {
            "subnet": self.tunnel_subnet,
            "dns_servers": self.dns_servers,
            "mtu": self.mtu,
            "buffer_size": self.buffer_size,
            "keepalive_interval": self.keepalive_interval,
        }
