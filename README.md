> [!WARNING]
> **Disclaimer**
> This software is provided "as is". While it implements strong cryptographic primitives, the security of your data ultimately depends on the strength of your password and the physical security of the host machine (which could be compromised by keyloggers or malware). Always keep backups of your encrypted vaults.

---

# 🔐 Dynamic Secure Portable Volume (DSPV)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange)](https://www.rust-lang.org/)
[![GitHub release](https://img.shields.io/github/v/release/g3noce/Dynamic-Secure-Portable-Volume)](https://github.com/g3noce/Dynamic-Secure-Portable-Volume/releases)

> A portable, cross-platform encrypted container that creates a secure workspace on any USB drive or local folder without leaving traces on the host machine.

## ✨ Overview

DSPV transforms any standard folder into an **encrypted vault**. By placing the executable in a directory or USB drive, all files placed inside the designated secure folder are encrypted on disk. 

Access is provided transparently via a local WebDAV server. You interact with your files through your OS's native file explorer, and DSPV handles the encryption and decryption on the fly in memory.

Gate to **encrypted vault** :

<img width="480" height="368" alt="image" src="https://github.com/user-attachments/assets/cc1f72e7-b89c-44fd-afe6-66418e095af8" />

**encrypted vault** :

<img width="392" height="247" alt="image" src="https://github.com/user-attachments/assets/6bc775ae-f614-4f87-b7ab-aac1a37fc039" />

## 🛡️ Core Features

* **True Portability:** Single standalone executable. No drivers or administrative privileges required on the host machine.
* **On-the-Fly Cryptography:** Uses **AES-256-XTS** for robust disk encryption, identical to standards used by VeraCrypt and BitLocker.
* **Strong Key Derivation:** Master keys are derived using **Argon2id** with a random 32-byte salt to thwart brute-force attacks.
* **Secure Memory Management:** Cryptographic keys and plain-text buffers are managed with strict `Zeroize` traits, ensuring sensitive data is securely wiped from RAM immediately after use.
* **Chunk-Based I/O:** Files are not fully loaded into RAM. Read/Write operations are streamed and encrypted in chunks, allowing for the manipulation of massive files with minimal memory footprint.

## 🚀 Usage Workflow

### 1. Initialization
1. Copy the `dspv` executable to the root of your USB drive or desired folder.
2. Launch the executable.
3. You will be prompted to enter a **volume encryption key**.
4. A folder named `secure_volume` (or a custom name) is automatically created and locked with a `dspv.meta` file.

### 2. Accessing Files
Once unlocked, DSPV hosts a local WebDAV server acting as a gateway.

* **Windows:** A network drive window opens automatically. Drag, drop, and edit files directly.
* **Linux / macOS:** The server starts at `http://127.0.0.1:8080`.
  * **Linux:** Mount using `davfs2` or your file manager's "Connect to Server" feature (`dav://127.0.0.1:8080`).
  * **macOS:** Open Finder → Go → Connect to Server → `http://localhost:8080`.

*Note: Automatic native mounting for Linux and macOS is currently being refined.*

### 3. Closing the Vault
Simply press `CTRL+C` in the terminal running DSPV. The server will gracefully shut down, flush all pending operations to disk, and purge the RAM.

## 🛠️ Building from Source

### Prerequisites
* [Rust and Cargo](https://www.rust-lang.org/tools/install) (1.70+)

### Compilation
```bash
git clone [https://github.com/g3noce/Dynamic-Secure-Portable-Volume.git](https://github.com/g3noce/Dynamic-Secure-Portable-Volume.git)
cd Dynamic-Secure-Portable-Volume
cargo build --release
```
The compiled binary will be located at `target/release/dspv`.

### Running Tests
The project includes an extensive suite of critical resilience and cryptographic tests.
```bash
cargo test
```
