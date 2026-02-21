# SALSA - Encrypted Tunnel

Salsa is a research-focused encrypted tunnel built with a Python control plane and a C++ cipher backend. It includes a VPN-style server and client, an encrypted tunnel manager, SOCKS5 forwarding, and a desktop GUI for operations and monitoring.

## Project Scope

This project currently provides:

- Encrypted client/server transport using the Deimos cipher DLL.
- Handshake, session key setup, and per-packet framing.
- Tunnel management with keepalive and bandwidth stats.
- Optional SOCKS5 proxy over the encrypted tunnel.
- GUI workflow for starting/stopping server and client, viewing traffic and logs.

## Repository Layout

```text
src/
  core.cpp                 C++ cipher core implementation
  deimos_dll_wrapper.cpp   C exports for Python ctypes
  deimos_cipher.h          C++ header
  deimos_cipher.dll        Runtime cipher DLL (loaded by Python)

  deimos_wrapper.py        Python ctypes wrapper around DLL
  protocol.py              Packet framing and message types
  tunnel_manager.py        Encrypted tunnel state and workers
  vpn_server.py            Server implementation
  vpn_client.py            Client implementation
  socks_proxy.py           Local SOCKS5 proxy over tunnel
  gui_manager.py           Tkinter GUI
  config.py                Server config and password hashing
```

## Requirements

- Python 3.10+
- Windows/Linux/macOS environment that can run Python
- If rebuilding the DLL: OpenSSL + libsodium development libraries

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Quick Start

Clone and set up:

```bash
git clone https://github.com/MohsinCell/Salsa-Encrypted-Tunnel.git
cd "Salsa - Encrypted Tunnel"
python -m venv .venv
```

Activate virtual environment:

```bash
# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the GUI:

```bash
python src/gui_manager.py
```

## CLI Usage

Start server:

```bash
python src/vpn_server.py
```

Start client:

```bash
python src/vpn_client.py
```

Default local test credentials:

- `testuser / testpass`
- `admin / admin123`

## SOCKS5 Mode

When the client is connected, you can start SOCKS5 forwarding (GUI or code path) on:

- Host: `127.0.0.1`
- Port: `1080` (default)

Point browser/tools to that SOCKS endpoint to route traffic through the encrypted tunnel.

## Configuration

Core settings are in `src/config.py` (`SalsaConfig`), including:

- Server bind host/port
- Max clients and timeout windows
- Tunnel subnet, DNS, MTU, buffer size
- SOCKS defaults
- Auth lockout controls

Passwords are stored as PBKDF2-HMAC-SHA256 hashes with random salt.

## Rebuilding `deimos_cipher.dll` (Optional)

If you need to rebuild the cipher DLL, run from `src/` with your compiler configured for OpenSSL and libsodium.

Example with MinGW g++:

```bash
g++ -O2 -std=c++17 -shared -o deimos_cipher.dll deimos_dll_wrapper.cpp core.cpp -lsodium -lcrypto -lssl
```

The Python wrapper (`src/deimos_wrapper.py`) searches for `deimos_cipher.dll` in standard local paths.

## Security Notice

This codebase is intended for internal testing and learning. Do not expose it directly to untrusted public networks without a full security review, hardening, and protocol-level validation.

## License

MIT License. See `LICENSE`.
