> [!WARNING]
> **Disclaimer**
> This software is provided "as is". While it implements strong cryptographic primitives, the security of your data ultimately depends on the strength of your password and the physical security of the host machine (which could be compromised by keyloggers or malware). Always keep backups of your encrypted vaults.

---

# Dynamic Secure Portable Volume (DSPV)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange)](https://www.rust-lang.org/)
[![GitHub release](https://img.shields.io/github/v/release/g3noce/Dynamic-Secure-Portable-Volume)](https://github.com/g3noce/Dynamic-Secure-Portable-Volume/releases)

> A portable, cross-platform encrypted container that creates a secure workspace on any USB drive or local folder without leaving traces on the host machine.

## Overview

DSPV transforms any standard folder into an **encrypted vault**. By placing the executable in a directory or USB drive, all files placed inside the designated secure folder are encrypted on disk.

Access is provided transparently via a local WebDAV server. You interact with your files through your OS's native file explorer, and DSPV handles the encryption and decryption on the fly in memory.

Gate to **encrypted vault**:

<img width="480" height="368" alt="image" src="https://github.com/user-attachments/assets/cc1f72e7-b89c-44fd-afe6-66418e095af8" />

**Encrypted vault**:

<img width="392" height="247" alt="image" src="https://github.com/user-attachments/assets/6bc775ae-f614-4f87-b7ab-aac1a37fc039" />

## Core Features

- **True Portability** — Single standalone executable. No drivers or administrative privileges required on the host machine.
- **On-the-Fly Cryptography** — Uses **AES-256-XTS** for disk encryption, the same standard used by VeraCrypt and BitLocker.
- **Strong Key Derivation** — Master keys are derived using **Argon2id** (m=64 MiB, t=3, p=4) with a random 32-byte salt to thwart brute-force attacks.
- **Per-File Integrity** — Every encrypted file carries an **HMAC-SHA256** tag binding the ciphertext to its vault-relative path. Tampering, bit-flips, and path-swap attacks are all detected.
- **Secure Memory Management** — Cryptographic keys and plaintext buffers use `Zeroize`/`ZeroizeOnDrop`; sensitive data is wiped from RAM immediately after use.
- **Chunk-Based I/O** — Files are streamed and encrypted in 64 KiB chunks; large files are handled with a minimal memory footprint.
- **Concurrency-Safe Cache** — A per-process `FileCache` pools open file handles behind per-path mutexes. Idle entries are evicted after 5 minutes.

## Usage Workflow

### 1. Initialization

1. Copy the `dspv` executable to the root of your USB drive or target folder.
2. Launch the executable.
3. Enter a **volume encryption key** when prompted.
4. A `secure_volume/` directory (or a custom path via `--path`) is created and locked with a `dspv.meta` file.

### 2. Accessing Files

Once unlocked, DSPV hosts a local WebDAV server at `http://127.0.0.1:8080` (port configurable with `--port`).

- **Windows** — A network drive window opens automatically.
- **Linux** — Mount via your file manager's "Connect to Server" (`dav://127.0.0.1:8080`) or `davfs2`.
- **macOS** — Finder → Go → Connect to Server → `http://localhost:8080`.

### 3. Closing the Vault

Press `CTRL+C`. The server flushes all pending writes to disk, purges keys from RAM, and unmounts the network connection.

## Building from Source

### Prerequisites

- [Rust and Cargo](https://www.rust-lang.org/tools/install) (edition 2024)

### Compilation

```bash
git clone https://github.com/g3noce/Dynamic-Secure-Portable-Volume.git
cd Dynamic-Secure-Portable-Volume
cargo build --release
```

The binary is at `target/release/dspv`.

### Tests

```bash
cargo test --release          # full suite (68 tests)
cargo test --release <name>   # single test by function name
cargo clippy --release --all-targets
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full description of the four-layer design (crypto → storage → protocol → OS), the cryptographic invariants, the file-format layout, and the concurrency model.

## Security Notes

- `dspv.meta` and all dotfiles are invisible to WebDAV clients and cannot be read, renamed, or deleted through the protocol.
- Copying a file to itself (`COPY A → A`) is rejected with `403 Forbidden`.
- A file handle that is still open when a concurrent truncate occurs is poisoned: its next read returns an explicit error rather than silently producing garbage.
- Renaming a file re-binds its HMAC tag to the new path; renaming a tampered file is rejected before the move.
