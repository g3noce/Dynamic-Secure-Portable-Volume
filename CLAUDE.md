# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

DSPV (Dynamic Secure Portable Volume) is a single-binary Rust application that turns any folder into an AES-256-XTS encrypted vault, exposed as a local WebDAV server on `127.0.0.1`. The OS file explorer mounts the WebDAV endpoint and reads/writes files transparently — encryption happens on the fly in RAM, the on-disk bytes are always ciphertext.

## Commands

```bash
cargo build --release          # Binary lands at target/release/dspv
cargo test --release           # Runs all 68 tests
cargo test --release <module::path>          # Single module, e.g. storage::vault
cargo test --release <fn_name>               # Single test by name
cargo clippy --release --all-targets         # Lint (2 cosmetic warnings expected)
cargo run --release -- --port 8080 <vault_path>   # Launch the WebDAV server
```

The first launch creates `<vault_path>/dspv.meta` from a prompted password (Argon2id); subsequent launches re-derive the master key from the same password.

## Architecture

The code is organized as **four layers** stacked from low-level crypto to user-facing protocol. Each layer's internal split lives in a directory `name/` with `mod.rs` + `errors.rs` + impl files + `tests/`.

```
crypto/          ← primitives only, no I/O
  cipher/        AES-256-XTS over a SecureKey (uses bytes 0..64 of master key)
  kdf/           Argon2id (m=64MiB, t=3, p=4) → 96-byte master key
  mac/           HMAC-SHA256 helper + streaming MacBuilder
storage/         ← on-disk format, no protocol concerns
  header/        FileHeader: IV(16) | logical_size(8) | reserved(8) | mac_tag(32) = 64B
  chunk_io/      EncryptedFile<C>: read/write encrypted chunks, MAC verify on open
  vault/         dspv.meta layout: magic | salt | verify_block | meta_hmac
  cache/         FileCache: process-wide singleton Arc<Mutex<EncryptedFile>> per path
protocol/        ← stateless adapters
  auth/          HTTP Basic auth with random per-session credentials
  webdav/        DavFileSystem impl wrapping the cache
os/              Per-platform helpers to launch/close the OS file manager
main.rs          Binary entry: KDF prompt → cache → Hyper http1 + DavHandler
utils/memory.rs  SecureKey / SecureBuffer (Zeroize + ZeroizeOnDrop)
```

### Cryptographic invariants worth understanding

- **Master key split**: Argon2id outputs 96 bytes. `SecureKey::split_xts_mac()` carves it into a 64-byte XTS key (cipher) and a 32-byte HMAC-SHA256 key (per-file integrity). The same 32-byte MAC key also authenticates `dspv.meta`.
- **Per-file MAC AAD**: every encrypted file binds its HMAC to its **vault-relative path** (`WebDavFS::mac_aad_for`). Swapping ciphertext between two paths invalidates both files; tests live in `chunk_io/tests/integrity.rs` and `webdav/tests/security.rs`.
- **Rename re-MAC** (`WebDavFS::rename`): verify source under `from_aad`, drop handle, `fs::rename`, then `EncryptedFile::open_unverified` + `flush()` to write a fresh tag under `to_aad`. `open_unverified` is intentionally bypass-only for this path — do not call it elsewhere.
- **Self-copy guard** (`WebDavFS::copy`): if `from_path == to_path`, returns `FsError::Forbidden` immediately (RFC 4918 §9.8.3). Without this guard, the truncate of the destination would wipe the source before the copy loop could read it.
- **MAC is recomputed on `flush()` and `Drop`**, only if `dirty`. A poisoned file (MAC failed at open) refuses all subsequent I/O and Drop skips the tag rewrite so we never stamp a valid tag over compromised data.

### Append-mode ordering

`WebDavFile` carries an `append: bool` flag. When set, `write_bytes` queries `logical_size()` **inside the `Mutex` lock** to determine the actual write offset at call time. This ensures two handles opened in append mode before any write still serialize correctly — the second write sees the updated size left by the first.

### Truncate poisoning

When `get_or_open` evicts a cache entry for a truncate (new IV, new content), it calls `EncryptedFile::poison()` on the old handle before removing it from the map. Any reader still holding an Arc to the old handle receives an explicit error on its next I/O call rather than silently decrypting new ciphertext with the stale IV.

### FileCache concurrency contract

`FileCache::get_or_open` is a five-phase dance because `EncryptedFile::open` streams O(N) ciphertext to verify the MAC:

1. **Fast path**: read-only DashMap lookup, return cached if access mode satisfies.
2. **Per-path Mutex acquire**: a separate `creation_locks: DashMap<PathBuf, Arc<Mutex<()>>>` serializes concurrent first-opens of the *same* path without blocking other paths/shards.
3. **Re-check** cache inside the per-path critical section (another thread may have just published).
4. **Slow I/O** (MAC verify) outside any DashMap bucket lock.
5. **Publish** into the cache.

Idle eviction runs every 30s and drops entries unused for 5 minutes (`IDLE_TIMEOUT_SECS`). The `creation_locks` map is GC'd in `remove()` and `sweep_idle()`.

### What is *not* persisted

WebDAV dead properties (`PROPPATCH`) are accepted with HTTP 200 but silently discarded — there is no slot in our file format for them. `set_modified` is also a no-op. This is required to keep Nautilus/Finder paste flows from erroring out after a successful PUT.

## Conventions

- **Errors**: each module has its own `errors.rs` with a structured enum (`VaultError`, `ChunkIoError`, `WebDavError`, …) and the message format `"mod: <name>, function: <fn>, cause: <text>"`. Always go through these instead of `io::Error::other(...)` with ad-hoc strings.
- **Tests are split by concern** when they exceed ~200 lines: see `chunk_io/tests/{io,integrity}.rs` and `webdav/tests/{io,fs_ops,metadata,security,bugs}.rs`. Shared fixtures go in the test directory's `mod.rs`. The `bugs` module contains regression tests for previously identified defects.
- **Security tests are first-class.** New crypto code must come with both a happy-path test and a tampering test (bit-flip, IV swap, wrong key, path swap). Look at `chunk_io/tests/integrity.rs` for the pattern.
- **Memory hygiene**: anything carrying plaintext or key material lives in `SecureKey` / `SecureBuffer` (Zeroize on drop). Ciphertext buffers don't need this — they're already on disk.

## File format compatibility

There is **no version byte** in `dspv.meta` or `FileHeader`. Any change to either layout is a hard break — vaults must be re-created. Notable historical breaks:
- Header grew from 32 → 64 bytes (added 32-byte HMAC tag slot)
- `dspv.meta` grew from 68 → 100 bytes (added 32-byte HMAC tag)
- Argon2 output grew from 64 → 96 bytes (added 32-byte MAC key region)
