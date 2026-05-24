use super::setup_test_env;
use bytes::Bytes;
use dav_server::davpath::DavPath;
use dav_server::fs::{DavFileSystem, OpenOptions, ReadDirMeta};
use futures_util::stream;
use std::fs;
use std::path::PathBuf;

/// Filtered listing, rename, copy, delete on the directory tree.
#[tokio::test]
async fn test_webdav_fs_operations() {
    let root = "test_fs_ops";
    let (dav_fs, _) = setup_test_env(root);

    let p_vis = DavPath::new("/visible.enc").unwrap();

    {
        let mut f = dav_fs
            .open(
                &p_vis,
                OpenOptions {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::from("test")).await.unwrap();
    }

    fs::File::create(PathBuf::from(root).join(".hidden")).unwrap();

    let root_path = DavPath::new("/").unwrap();
    let entries = dav_fs
        .read_dir(&root_path, ReadDirMeta::None)
        .await
        .unwrap();
    let names: Vec<String> = stream::StreamExt::collect::<Vec<_>>(entries)
        .await
        .into_iter()
        .map(|e| String::from_utf8(e.unwrap().name()).unwrap())
        .collect();

    assert!(names.contains(&"visible.enc".to_string()));
    assert!(
        !names.contains(&".hidden".to_string()),
        "Hidden files must be ignored"
    );

    let p_copy = DavPath::new("/copy.enc").unwrap();
    let p_rename = DavPath::new("/rename.enc").unwrap();

    dav_fs.copy(&p_vis, &p_copy).await.unwrap();
    assert!(
        fs::metadata(PathBuf::from(root).join("copy.enc")).is_ok(),
        "Copy failed"
    );

    dav_fs.rename(&p_copy, &p_rename).await.unwrap();
    assert!(
        fs::metadata(PathBuf::from(root).join("copy.enc")).is_err(),
        "The old file still exists post-rename"
    );
    assert!(
        fs::metadata(PathBuf::from(root).join("rename.enc")).is_ok(),
        "The new file does not exist"
    );

    dav_fs.remove_file(&p_vis).await.unwrap();
    dav_fs.remove_file(&p_rename).await.unwrap();
    assert!(fs::metadata(PathBuf::from(root).join("visible.enc")).is_err());

    let d_dir = DavPath::new("/dir").unwrap();
    dav_fs.create_dir(&d_dir).await.unwrap();
    dav_fs.remove_dir(&d_dir).await.unwrap();
    assert!(fs::metadata(PathBuf::from(root).join("dir")).is_err());

    let _ = fs::remove_dir_all(root);
}
