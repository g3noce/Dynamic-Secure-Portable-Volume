use super::setup_test_env;
use bytes::Bytes;
use dav_server::davpath::DavPath;
use dav_server::fs::{DavFileSystem, OpenOptions};
use std::fs;
use std::path::PathBuf;

/// Metadata resolution comes from the RAM cache while the file is open, and
/// falls back to the on-disk header once the cache is evicted. Also smoke-tests
/// the `get_quota` path.
#[tokio::test]
async fn test_webdav_metadata_cache_and_quota() {
    let root = "test_meta_quota";
    let (dav_fs, _) = setup_test_env(root);
    let path = DavPath::new("/cache_test.enc").unwrap();
    let phys_path = PathBuf::from(root).join("cache_test.enc");

    {
        let mut file = dav_fs
            .open(
                &path,
                OpenOptions {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        file.write_bytes(Bytes::from("Data")).await.unwrap();

        assert_eq!(
            dav_fs.metadata(&path).await.unwrap().len(),
            4,
            "Resolution did not use the RAM cache"
        );
    }

    dav_fs.cache.remove(&phys_path);

    let mut f = fs::OpenOptions::new().write(true).open(&phys_path).unwrap();

    let mut header = crate::storage::header::FileHeader::generate_new();
    header.logical_size = 999;
    std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(0)).unwrap();
    header.write_to(&mut f).unwrap();
    drop(f);

    assert_eq!(
        dav_fs.metadata(&path).await.unwrap().len(),
        999,
        "The size was not read from the physical FileHeader"
    );

    let quota_result = dav_fs.get_quota().await;
    assert!(quota_result.is_ok(), "The OS quota API failed");

    let (used, total) = quota_result.unwrap();
    assert!(total.unwrap() > 0, "The total disk size cannot be 0");
    assert!(
        used <= total.unwrap(),
        "Used space cannot exceed total space"
    );

    let _ = fs::remove_dir_all(root);
}
