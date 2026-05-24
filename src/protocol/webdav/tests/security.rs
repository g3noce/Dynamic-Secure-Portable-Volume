//! Security-focused integration tests:
//! - `dspv.meta` and dotfiles must be invisible across every DAV handler
//! - A legitimate WebDAV rename re-binds the MAC tag (P0.2 contract)
//! - An external file-swap on disk is rejected on next open

use super::setup_test_env;
use bytes::Bytes;
use dav_server::davpath::DavPath;
use dav_server::fs::{DavFileSystem, OpenOptions};
use std::fs;
use std::path::PathBuf;

/// `dspv.meta` and dotfiles must be unreachable via every DAV verb.
#[tokio::test]
async fn test_webdav_blocks_meta_and_dotfiles() {
    let root = "test_meta_protection";
    let (dav_fs, _) = setup_test_env(root);

    fs::write(PathBuf::from(root).join("dspv.meta"), b"FAKE_META").unwrap();
    fs::write(PathBuf::from(root).join(".secret"), b"shh").unwrap();

    let p_meta = DavPath::new("/dspv.meta").unwrap();
    let p_dot = DavPath::new("/.secret").unwrap();
    let p_nested = DavPath::new("/sub/dspv.meta").unwrap();
    let p_ok = DavPath::new("/safe.enc").unwrap();

    assert!(dav_fs.metadata(&p_meta).await.is_err());
    assert!(dav_fs.metadata(&p_dot).await.is_err());
    assert!(dav_fs.metadata(&p_nested).await.is_err());

    let open_opts = || OpenOptions {
        read: true,
        ..Default::default()
    };
    assert!(dav_fs.open(&p_meta, open_opts()).await.is_err());
    assert!(dav_fs.open(&p_dot, open_opts()).await.is_err());

    assert!(dav_fs.remove_file(&p_meta).await.is_err());
    assert!(
        PathBuf::from(root).join("dspv.meta").exists(),
        "CRITICAL: dspv.meta was deleted through WebDAV!"
    );

    {
        let mut f = dav_fs
            .open(
                &p_ok,
                OpenOptions {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::from("data")).await.unwrap();
    }
    assert!(dav_fs.rename(&p_ok, &p_meta).await.is_err());
    assert!(dav_fs.copy(&p_ok, &p_meta).await.is_err());

    let p_steal = DavPath::new("/stolen.bin").unwrap();
    assert!(dav_fs.rename(&p_meta, &p_steal).await.is_err());
    assert!(dav_fs.copy(&p_meta, &p_steal).await.is_err());

    let _ = fs::remove_dir_all(root);
}

/// A legitimate rename via WebDAV must produce a file that is still openable
/// under the NEW path (MAC tag re-computed with the new AAD), and the old
/// path must no longer be openable.
#[tokio::test]
async fn test_webdav_rename_rebinds_mac() {
    let root = "test_rename_remac";
    let (dav_fs, _) = setup_test_env(root);

    let p_old = DavPath::new("/old.enc").unwrap();
    let p_new = DavPath::new("/new.enc").unwrap();

    {
        let mut f = dav_fs
            .open(
                &p_old,
                OpenOptions {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::from("important")).await.unwrap();
        f.flush().await.unwrap();
    }

    dav_fs.cache.remove(&PathBuf::from(root).join("old.enc"));

    dav_fs.rename(&p_old, &p_new).await.unwrap();

    let mut f = dav_fs
        .open(
            &p_new,
            OpenOptions {
                read: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let bytes = f.read_bytes(9).await.unwrap();
    assert_eq!(
        bytes.as_ref(),
        b"important",
        "Renamed file did not survive MAC re-bind"
    );

    assert!(dav_fs.metadata(&p_old).await.is_err());

    let _ = fs::remove_dir_all(root);
}

/// P1: If an attacker tampers with a file's on-disk content before the user
/// renames it, the rename MUST fail rather than blindly re-MAC the garbage
/// (which would otherwise make the substituted content authenticate cleanly
/// under the new path).
#[tokio::test]
async fn test_webdav_rename_rejects_tampered_source() {
    let root = "test_rename_tamper";
    let (dav_fs, _) = setup_test_env(root);

    let p_src = DavPath::new("/legit.enc").unwrap();
    let p_dst = DavPath::new("/legit.bak.enc").unwrap();
    let phys_src = PathBuf::from(root).join("legit.enc");

    // Create a real, MAC-valid file via WebDAV.
    {
        let mut f = dav_fs
            .open(
                &p_src,
                OpenOptions {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::from("legit-content")).await.unwrap();
        f.flush().await.unwrap();
    }
    dav_fs.cache.remove(&phys_src);

    // Adversary corrupts the ciphertext on disk.
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut handle = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&phys_src)
            .unwrap();
        // Past the 64-byte header into the ciphertext.
        handle.seek(SeekFrom::Start(64 + 4)).unwrap();
        let mut b = [0u8; 1];
        handle.read_exact(&mut b).unwrap();
        b[0] ^= 0x80;
        handle.seek(SeekFrom::Start(64 + 4)).unwrap();
        handle.write_all(&b).unwrap();
    }

    // Rename must fail because the pre-rename MAC verification rejects the
    // tampered source.
    let result = dav_fs.rename(&p_src, &p_dst).await;
    assert!(
        result.is_err(),
        "CRITICAL: tampered source was silently re-MAC'd into a fresh valid tag at the destination"
    );

    // And the destination must not exist (rename never happened).
    assert!(
        fs::metadata(PathBuf::from(root).join("legit.bak.enc")).is_err(),
        "Destination file was created despite the integrity check failing"
    );

    let _ = fs::remove_dir_all(root);
}

/// If an attacker swaps two encrypted files on disk (without going through
/// our rename re-MAC path), the next access via WebDAV must reject both files.
#[tokio::test]
async fn test_webdav_detects_external_file_swap() {
    let root = "test_external_swap";
    let (dav_fs, _) = setup_test_env(root);

    let p_a = DavPath::new("/alice.enc").unwrap();
    let p_b = DavPath::new("/bob.enc").unwrap();

    for (path, content) in [(&p_a, "for-alice"), (&p_b, "for-bob")] {
        let mut f = dav_fs
            .open(
                path,
                OpenOptions {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::from(content.as_bytes().to_vec()))
            .await
            .unwrap();
        f.flush().await.unwrap();
    }
    dav_fs.cache.remove(&PathBuf::from(root).join("alice.enc"));
    dav_fs.cache.remove(&PathBuf::from(root).join("bob.enc"));

    let tmp = PathBuf::from(root).join("tmp.enc");
    fs::rename(PathBuf::from(root).join("alice.enc"), &tmp).unwrap();
    fs::rename(PathBuf::from(root).join("bob.enc"), PathBuf::from(root).join("alice.enc"))
        .unwrap();
    fs::rename(tmp, PathBuf::from(root).join("bob.enc")).unwrap();

    let open_a = dav_fs
        .open(
            &p_a,
            OpenOptions {
                read: true,
                ..Default::default()
            },
        )
        .await;
    let open_b = dav_fs
        .open(
            &p_b,
            OpenOptions {
                read: true,
                ..Default::default()
            },
        )
        .await;
    assert!(
        open_a.is_err(),
        "CRITICAL: external file-swap was accepted at path alice.enc"
    );
    assert!(
        open_b.is_err(),
        "CRITICAL: external file-swap was accepted at path bob.enc"
    );

    let _ = fs::remove_dir_all(root);
}
