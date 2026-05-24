use super::setup_test_env;
use bytes::Bytes;
use dav_server::davpath::DavPath;
use dav_server::fs::{DavFileSystem, OpenOptions};
use std::fs;
use std::io::SeekFrom;

/// Full lifecycle of a file: creation, append, read, seek, truncate.
#[tokio::test]
async fn test_webdav_file_lifecycle_and_io() {
    let root = "test_io";
    let (dav_fs, _) = setup_test_env(root);
    let path = DavPath::new("/lifecycle.enc").unwrap();

    {
        let mut f = dav_fs
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
        f.write_bytes(Bytes::from("Hello")).await.unwrap();
    }

    {
        let mut f = dav_fs
            .open(
                &path,
                OpenOptions {
                    append: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::from(" World")).await.unwrap();
    }

    {
        let mut f = dav_fs
            .open(
                &path,
                OpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            f.metadata().await.unwrap().len(),
            11,
            "Logical size should be 11 after appending"
        );

        f.seek(SeekFrom::Start(0)).await.unwrap();
        assert_eq!(
            f.read_bytes(11).await.unwrap().as_ref(),
            b"Hello World",
            "The decrypted content is incorrect"
        );

        assert_eq!(f.seek(SeekFrom::End(-5)).await.unwrap(), 6);
        assert_eq!(f.seek(SeekFrom::Current(2)).await.unwrap(), 8);
        assert!(f.flush().await.is_ok());
    }

    {
        let mut f = dav_fs
            .open(
                &path,
                OpenOptions {
                    truncate: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::from("NEW")).await.unwrap();
    }

    assert_eq!(
        dav_fs.metadata(&path).await.unwrap().len(),
        3,
        "Truncate did not reset the logical size"
    );

    let _ = fs::remove_dir_all(root);
}
