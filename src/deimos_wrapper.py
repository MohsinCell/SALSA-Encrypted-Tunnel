import base64
import ctypes
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

class DeimosError(Exception):
    pass

class EncryptedData(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("length", ctypes.c_size_t),
    ]

class DecryptedData(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_char_p),
        ("length", ctypes.c_size_t),
        ("success", ctypes.c_int),
    ]

def _find_dll() -> Optional[str]:
    src_dir = Path(__file__).parent
    candidates = [
        src_dir / "deimos_cipher.dll",
        src_dir.parent / "src" / "deimos_cipher.dll",
        Path("deimos_cipher.dll"),
    ]
    for p in candidates:
        if p.exists():
            return str(p.resolve())
    return None

class DeimosCipher:

    def __init__(self, dll_path: Optional[str] = None):
        if dll_path is None:
            dll_path = _find_dll()
        if dll_path is None or not os.path.exists(dll_path):
            raise DeimosError(
                "DLL not found. Searched standard locations. "
                "Place deimos_cipher.dll next to this script or pass dll_path explicitly."
            )

        try:
            self.lib = ctypes.CDLL(str(dll_path))
        except OSError as e:
            raise DeimosError(f"Failed to load DLL at {dll_path}: {e}")

        self._setup_function_signatures()
        self._initialize()
        logger.info(f"Deimos cipher loaded from {dll_path}")

    def _setup_function_signatures(self) -> None:
        self.lib.deimos_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.deimos_encrypt.restype = ctypes.POINTER(EncryptedData)

        self.lib.deimos_decrypt.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_char_p
        ]
        self.lib.deimos_decrypt.restype = ctypes.POINTER(DecryptedData)

        self.lib.free_encrypted_data.argtypes = [ctypes.POINTER(EncryptedData)]
        self.lib.free_encrypted_data.restype = None

        self.lib.free_decrypted_data.argtypes = [ctypes.POINTER(DecryptedData)]
        self.lib.free_decrypted_data.restype = None

        self.lib.deimos_init.argtypes = []
        self.lib.deimos_init.restype = ctypes.c_int

    def _initialize(self) -> None:
        result = self.lib.deimos_init()
        if result not in (0, 1):
            raise DeimosError(f"Failed to initialize libsodium (code {result})")

    def encrypt(self, plaintext: str, password: str) -> bytes:
        if not isinstance(plaintext, str):
            raise DeimosError("Plaintext must be a string")
        if not isinstance(password, str):
            raise DeimosError("Password must be a string")

        result_ptr = self.lib.deimos_encrypt(
            plaintext.encode("utf-8"), password.encode("utf-8")
        )
        if not result_ptr:
            raise DeimosError("Encryption failed (null result)")

        try:
            result = result_ptr.contents
            return bytes(result.data[i] for i in range(result.length))
        finally:
            self.lib.free_encrypted_data(result_ptr)

    def decrypt(self, ciphertext: bytes, password: str) -> str:
        if not isinstance(ciphertext, bytes):
            raise DeimosError("Ciphertext must be bytes")
        if not isinstance(password, str):
            raise DeimosError("Password must be a string")

        ciphertext_array = (ctypes.c_uint8 * len(ciphertext)).from_buffer_copy(ciphertext)
        result_ptr = self.lib.deimos_decrypt(
            ciphertext_array, len(ciphertext), password.encode("utf-8")
        )
        if not result_ptr:
            raise DeimosError("Decryption failed (null result)")

        try:
            result = result_ptr.contents
            if not result.success:
                error_msg = result.data.decode("utf-8") if result.data else "Unknown error"
                raise DeimosError(f"Decryption failed: {error_msg}")
            return result.data.decode("utf-8") if result.data else ""
        finally:
            self.lib.free_decrypted_data(result_ptr)

    def encrypt_bytes(self, plaintext: bytes, password: str) -> bytes:
        b64 = base64.b64encode(plaintext).decode("ascii")
        return self.encrypt(b64, password)

    def decrypt_bytes(self, ciphertext: bytes, password: str) -> bytes:
        b64 = self.decrypt(ciphertext, password)
        return base64.b64decode(b64)

class EncryptionSession:

    def __init__(self, password: str, dll_path: Optional[str] = None):
        self.cipher = DeimosCipher(dll_path=dll_path)
        self._password = password

    def seal(self, data: bytes) -> bytes:
        return self.cipher.encrypt_bytes(data, self._password)

    def open(self, data: bytes) -> bytes:
        return self.cipher.decrypt_bytes(data, self._password)

    @classmethod
    def from_session_key(cls, session_key: bytes, dll_path: Optional[str] = None) -> "EncryptionSession":
        return cls(password=session_key.hex(), dll_path=dll_path)

_cipher_instance: Optional[DeimosCipher] = None

def get_cipher() -> DeimosCipher:
    global _cipher_instance
    if _cipher_instance is None:
        _cipher_instance = DeimosCipher()
    return _cipher_instance

def encrypt(plaintext: str, password: str) -> bytes:
    return get_cipher().encrypt(plaintext, password)

def decrypt(ciphertext: bytes, password: str) -> str:
    return get_cipher().decrypt(ciphertext, password)

def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    return get_cipher().encrypt_bytes(plaintext, password)

def decrypt_bytes(ciphertext: bytes, password: str) -> bytes:
    return get_cipher().decrypt_bytes(ciphertext, password)
