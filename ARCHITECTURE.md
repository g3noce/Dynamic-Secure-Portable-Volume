# Architecture — Dynamic Secure Portable Volume (DSPV)

## Overview

DSPV is a single-binary Rust application. It turns any directory into an AES-256-XTS encrypted vault exposed as a local WebDAV server on `127.0.0.1`. The OS file explorer mounts the endpoint and reads/writes files transparently; encryption happens on the fly in RAM, and on-disk bytes are always ciphertext.

```
┌─────────────────────────────────────────────────┐
│            OS file explorer (WebDAV client)     │
└───────────────────────┬─────────────────────────┘
                        │ HTTP/1.1 + Basic Auth
                        ▼
┌─────────────────────────────────────────────────┐
│  protocol/   — stateless WebDAV/HTTP adapters   │
│    auth.rs        HTTP Basic auth (per-session) │
│    webdav/        DavFileSystem impl            │
│      fs.rs        open/read/write/rename/copy   │
│      file.rs      DavFile  (pos + append flag)  │
│      guard.rs     path filtering (dspv.meta, .) │
│      metadata.rs  logical-size resolution       │
└───────────────────────┬─────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│  storage/    — on-disk format, no protocol deps │
│    cache/         FileCache  (Arc<Mutex<>> pool)│
│    chunk_io/      EncryptedFile<C>              │
│    header/        FileHeader  (64-byte struct)  │
│    vault/         dspv.meta  lifecycle          │
└───────────────────────┬─────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│  crypto/     — primitives only, no I/O          │
│    cipher/        AES-256-XTS  (xts-mode crate) │
│    kdf/           Argon2id  → 96-byte master key│
│    mac/           HMAC-SHA256  (streaming)      │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│  utils/memory.rs  — SecureKey / SecureBuffer    │
│                      (Zeroize + ZeroizeOnDrop)  │
└─────────────────────────────────────────────────┘
```

---

## Cryptographic design

### Master key derivation

```
password + 32-byte random salt
        │
        ▼  Argon2id (m=64 MiB, t=3, p=4)
        │
96-byte master key
  ├─ bytes  0..64  → AES-256-XTS key  (two 256-bit halves)
  └─ bytes 64..96  → HMAC-SHA256 key  (per-file integrity + vault HMAC)
```

`SecureKey::split_xts_mac()` performs this split. Both halves are clones; the original is zeroized on drop.

### Per-file encryption (AES-256-XTS)

Each encrypted file starts with a 64-byte header followed by ciphertext:

```
bytes  0..16  — IV  (random, regenerated on truncate)
bytes 16..24  — logical_size  (plaintext byte count, little-endian u64)
bytes 24..32  — reserved  (zeroed)
bytes 32..64  — HMAC-SHA256 tag
bytes 64..N   — ciphertext  (AES-256-XTS, 16-byte sectors)
```

The XTS sector index for a block at `logical_offset` is:

```
sector_index = (logical_offset / 16) wrapping_add IV_as_u128
```

This embeds the per-file IV into the tweak so that two files that happen to share ciphertext blocks at the same offset are still distinguishable.

### Integrity (HMAC-SHA256)

The MAC covers:

```
HMAC-SHA256(mac_key,
    LE32(len(aad)) || aad || header_plaintext_bytes || ciphertext
)
```

Where `aad` is the vault-relative DAV path of the file. This binding prevents:
- **Ciphertext tampering** — any bit-flip invalidates the tag.
- **IV tampering** — the IV is part of `header_plaintext_bytes`.
- **Path-swap attacks** — moving ciphertext to another path changes the AAD and invalidates the tag.

The tag is verified once at `open()` time. Writes update the tag on `flush()` and on `Drop` (best-effort).

### Vault metadata (`dspv.meta`)

```
bytes  0..4    — magic "DSPM"
bytes  4..36   — 32-byte random salt
bytes 36..68   — XTS-encrypted verify block (32 zero bytes under derived key)
bytes 68..100  — HMAC-SHA256 of bytes 0..68
```

The HMAC prevents salt or verify-block tampering from silently deriving a wrong master key. A failed HMAC (whether from wrong password or tampering) surfaces uniformly as "wrong password" to avoid leaking oracle information.

---

## FileCache concurrency model

`FileCache` is a process-wide singleton (`Arc<FileCache>`) shared across all WebDAV connections. It maps `PathBuf → Arc<Mutex<EncryptedFile>>`.

`get_or_open` is a five-phase protocol:

| Phase | Description |
|-------|-------------|
| 1 | **Fast path** — read-only DashMap lookup; returns cached entry if the access mode is satisfied. No lock contention across shards. |
| 2 | **Per-path Mutex** — a separate `creation_locks` DashMap holds one `Arc<Mutex<()>>` per path. Acquiring it serializes concurrent first-opens of the *same* path without blocking other paths. |
| 3 | **Re-check** — inside the per-path critical section another thread may have already populated the cache. |
| 4 | **Slow I/O** — `EncryptedFile::open` streams O(N) ciphertext to verify the HMAC. Runs outside any DashMap shard lock. |
| 5 | **Publish** — insert the new entry; no race because the per-path lock is still held. |

**Truncate poisoning** — when `get_or_open` evicts an entry for a truncate, it calls `EncryptedFile::poison()` on the old handle before removing it from the map. Any reader still holding an Arc to that handle will receive an explicit error on its next I/O call instead of silently decrypting new ciphertext with a stale IV.

**Idle eviction** — a background sweep runs at most every 30 s and drops entries idle for more than 5 minutes. The `creation_locks` entry is garbage-collected alongside its cache entry.

---

## Append-mode correctness

`WebDavFile` carries an `append: bool` flag set at open time. When `true`, each call to `write_bytes` queries `logical_size()` **inside the `Mutex` lock** to determine the actual write offset. This guarantees that two handles opened in append mode before any write still serialize correctly: the second write always sees the updated size left by the first.

---

## Rename re-MAC protocol

The WebDAV `rename` operation follows a three-step protocol to keep the path-bound MAC invariant intact:

1. **Verify source** — open source under `from_aad`, verify MAC, drop handle.
2. **Move bytes** — `fs::rename` at the OS level.
3. **Re-bind tag** — `open_unverified` + `flush()` writes a fresh tag under `to_aad`.

`open_unverified` bypasses MAC verification and is intentionally restricted to this rename path. Any other use would introduce an integrity bypass.

---

## Security boundaries and known limitations

| Item | Status |
|------|--------|
| Ciphertext confidentiality | AES-256-XTS per sector |
| Per-file integrity | HMAC-SHA256, verified at open |
| Path-binding (swap/rename attacks) | DAV path mixed into HMAC AAD |
| Vault metadata integrity | Separate HMAC on `dspv.meta` |
| Memory hygiene | `Zeroize` on all key/plaintext types |
| Self-copy (`COPY A → A`) | Rejected with `403 Forbidden` |
| Concurrent append ordering | Serialized inside the `Mutex` lock |
| Stale reader after truncate | Poisoned; returns explicit error |
| `PROPPATCH` / dead DAV props | Accepted silently, not persisted |
| `set_modified` | No-op (keeps paste flows working) |
| File format versioning | No version byte; any layout change is a hard break |
