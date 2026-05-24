//! Tests de régression pour les bugs identifiés par analyse statique.
//! Ces tests sont intentionnellement conçus pour ÉCHOUER sur le code actuel
//! et prouver l'existence des défauts signalés dans le rapport.

use super::setup_test_env;
use bytes::Bytes;
use dav_server::davpath::DavPath;
use dav_server::fs::{DavFileSystem, OpenOptions};
use std::fs;
use std::io::SeekFrom;
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// BUG-1 : copy(A, A) détruit silencieusement les données
// ─────────────────────────────────────────────────────────────────────────────
//
// Cause : `copy` ouvre d'abord la source en lecture, puis ouvre la
// destination avec `truncate=true`. Quand src == dst, le truncate vide le
// fichier sur disque avant que la boucle de copie ne commence à lire.
// La source en mémoire déclare un logical_size > 0 mais lit 0 octets
// (fichier vidé), donc la destination reste vide. `copy` renvoie Ok(()).
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_bug_self_copy_destroys_data() {
    let root = "bug_test_self_copy";
    let (dav_fs, _) = setup_test_env(root);
    let path = DavPath::new("/original.enc").unwrap();
    let phys = PathBuf::from(root).join("original.enc");
    let original: &[u8] = b"this content must survive a self-copy";

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
        f.write_bytes(Bytes::copy_from_slice(original)).await.unwrap();
        f.flush().await.unwrap();
    }
    dav_fs.cache.remove(&phys);

    // Auto-copie : doit soit échouer, soit laisser le fichier intact.
    let copy_result = dav_fs.copy(&path, &path).await;

    // Si copy retourne Ok, le fichier DOIT contenir les données d'origine.
    // Le bug actuel : copy retourne Ok mais le fichier est maintenant vide.
    if copy_result.is_ok() {
        dav_fs.cache.remove(&phys);
        let mut f = dav_fs
            .open(
                &path,
                OpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await
            .expect("le fichier doit encore exister après une auto-copie");
        let size = f.metadata().await.unwrap().len();
        assert_eq!(
            size,
            original.len() as u64,
            "BUG-1 : copy(A,A) a tronqué le fichier à {} octet(s) au lieu de {}",
            size,
            original.len()
        );
        let content = f.read_bytes(original.len()).await.unwrap();
        assert_eq!(
            content.as_ref(),
            original,
            "BUG-1 : copy(A,A) a effacé le contenu du fichier"
        );
    }

    let _ = fs::remove_dir_all(root);
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-2 : mode append — position capturée à l'ouverture, pas à l'écriture
// ─────────────────────────────────────────────────────────────────────────────
//
// Cause : `WebDavFS::open` calcule `initial_pos = logical_size()` une seule
// fois à l'ouverture du handle. Deux handles ouverts simultanément en mode
// append avant toute écriture capturent tous les deux `pos = 0`. La seconde
// écriture écrase la première au lieu de la compléter.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_bug_concurrent_appends_overwrite_each_other() {
    let root = "bug_test_concurrent_append";
    let (dav_fs, _) = setup_test_env(root);
    let path = DavPath::new("/shared.enc").unwrap();
    let phys = PathBuf::from(root).join("shared.enc");

    // Créer un fichier vide.
    {
        let _ = dav_fs
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
    }

    let append_opts = || OpenOptions {
        append: true,
        write: true,
        ..Default::default()
    };

    // Ouvrir deux handles en append AVANT toute écriture.
    // Les deux capturent initial_pos = 0 (taille du fichier = 0).
    let mut f1 = dav_fs.open(&path, append_opts()).await.unwrap();
    let mut f2 = dav_fs.open(&path, append_opts()).await.unwrap();

    // f1 écrit en premier → fichier = "AAAA" (4 octets).
    f1.write_bytes(Bytes::from_static(b"AAAA")).await.unwrap();
    f1.flush().await.unwrap();

    // f2 écrit en second — mais f2.pos == 0 (pos capturée à l'ouverture),
    // donc il écrase offset 0 au lieu d'aller en offset 4.
    f2.write_bytes(Bytes::from_static(b"BBBB")).await.unwrap();
    f2.flush().await.unwrap();

    // Lecture du contenu final.
    dav_fs.cache.remove(&phys);
    let mut reader = dav_fs
        .open(
            &path,
            OpenOptions {
                read: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let size = reader.metadata().await.unwrap().len();
    let content = reader.read_bytes(16).await.unwrap();

    // Attendu : 8 octets "AAAABBBB" (les deux écritures conservées).
    // Résultat du bug : 4 octets "BBBB" (f2 a écrasé les données de f1).
    assert_eq!(
        size, 8,
        "BUG-2 : les appends concurrents ont produit {} octet(s) au lieu de 8 \
         — le second append a écrasé le premier",
        size
    );
    assert_eq!(
        content.as_ref(),
        b"AAAABBBB",
        "BUG-2 : contenu final incorrect après appends concurrents : {:?}",
        content.as_ref()
    );

    let _ = fs::remove_dir_all(root);
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-3 : lecture obsolète après truncate → déchiffrement avec mauvais IV
// ─────────────────────────────────────────────────────────────────────────────
//
// Cause : un handle de lecture (Arc<EncryptedFile>) conserve l'IV capturé à
// l'ouverture. Quand un autre handle tronque et réécrit le même fichier
// (nouveau IV aléatoire), l'OS partage l'inode et le vieux handle lit le
// nouveau chiffré. Le déchiffrement avec l'ancien IV produit des données
// corrompues, sans qu'aucune erreur ne soit levée.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_bug_stale_reader_after_truncate_returns_garbage() {
    let root = "bug_test_stale_reader";
    let (dav_fs, _) = setup_test_env(root);
    let path = DavPath::new("/file.enc").unwrap();
    let original: &[u8] = b"original secret content here";

    // Écrire le contenu initial.
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
        f.write_bytes(Bytes::copy_from_slice(original)).await.unwrap();
        f.flush().await.unwrap();
    }

    // Ouvrir un handle de lecture AVANT le truncate (capturant l'ancien IV).
    let mut stale_reader = dav_fs
        .open(
            &path,
            OpenOptions {
                read: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Tronquer et réécrire via un handle séparé (nouveau IV généré).
    let new_content: &[u8] = b"NEW";
    {
        let mut writer = dav_fs
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
        writer
            .write_bytes(Bytes::copy_from_slice(new_content))
            .await
            .unwrap();
        writer.flush().await.unwrap();
    }

    // Le handle obsolète lit depuis le début.
    stale_reader.seek(SeekFrom::Start(0)).await.unwrap();
    let result = stale_reader.read_bytes(original.len()).await;

    // Comportements acceptables après la correction :
    //   • Err(_)  → le handle est explicitement invalidé (comportement idéal)
    //   • Ok(buf) → contenu cohérent : original, nouveau, ou vide
    //
    // Comportement du bug original (code non corrigé) : Ok(garbage) — le vieux
    // IV est appliqué au nouveau chiffré et retourne des données corrompues.
    match result {
        Err(_) => {
            // Correct : le handle empoisonné a bien rejeté la lecture.
        }
        Ok(buf) => {
            let is_original = buf.as_ref() == original;
            let is_new_prefix = buf.len() >= new_content.len()
                && &buf.as_ref()[..new_content.len()] == new_content;
            let is_empty = buf.is_empty();
            assert!(
                is_original || is_new_prefix || is_empty,
                "BUG-3 : le handle obsolète a retourné {} octet(s) de garbage après truncate : {:?}",
                buf.len(),
                buf.as_ref()
            );
        }
    }

    let _ = fs::remove_dir_all(root);
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-4 : write_chunk utilise read() au lieu de read_exact() pour le RMW
// ─────────────────────────────────────────────────────────────────────────────
//
// Cause : lors d'un Read-Modify-Write, `write_chunk` utilise `file.read()`
// qui peut retourner moins d'octets que demandé (short read). Si le dernier
// bloc partiel n'est pas entièrement lu, les octets manquants restent à
// zéro dans le buffer et sont ré-chiffrés, corrompant silencieusement les
// données du bloc.
//
// Ce bug est difficile à reproduire sur un système de fichiers local (les
// short reads sont rares), mais il est démontrable en comparant le résultat
// d'un overwrite partiel sur un fichier multi-blocs.
//
// Ce test vérifie que le cas nominal (écriture partielle dans un bloc
// existant) préserve correctement les octets non touchés — ce qui devrait
// PASSER si le code est correct, mais échouera si un short read survient.
#[tokio::test]
async fn test_bug_partial_block_overwrite_preserves_unmodified_bytes() {
    let root = "bug_test_partial_rmw";
    let (dav_fs, _) = setup_test_env(root);
    let path = DavPath::new("/rmw.enc").unwrap();
    let phys = PathBuf::from(root).join("rmw.enc");

    // Écrire 32 octets (2 blocs XTS de 16 octets).
    let original = b"AAAAAAAAAAAAAAAA" // bloc 0
        .iter()
        .chain(b"BBBBBBBBBBBBBBBB".iter()) // bloc 1
        .copied()
        .collect::<Vec<u8>>();

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
        f.write_bytes(Bytes::from(original.clone())).await.unwrap();
        f.flush().await.unwrap();
    }
    dav_fs.cache.remove(&phys);

    // Réécrire uniquement les 3 premiers octets du second bloc (offset 16).
    {
        let mut f = dav_fs
            .open(
                &path,
                OpenOptions {
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.seek(SeekFrom::Start(16)).await.unwrap();
        f.write_bytes(Bytes::from_static(b"XYZ")).await.unwrap();
        f.flush().await.unwrap();
    }
    dav_fs.cache.remove(&phys);

    // Relire les 32 octets et vérifier que les 13 octets non touchés du
    // second bloc ("BBBBBBBBBBBBB") sont intacts.
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
    let content = f.read_bytes(32).await.unwrap();

    let mut expected = original.clone();
    expected[16] = b'X';
    expected[17] = b'Y';
    expected[18] = b'Z';

    assert_eq!(
        content.as_ref(),
        expected.as_slice(),
        "BUG-4 : overwrite partiel d'un bloc a corrompu les octets non modifiés : {:?}",
        content.as_ref()
    );

    let _ = fs::remove_dir_all(root);
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-5 : copy ne flush pas le cache source avant de lire
// ─────────────────────────────────────────────────────────────────────────────
//
// Cause : si le fichier source est dans le cache avec dirty=true (écriture
// non flushée), son MAC sur disque est périmé. Si la source est évincée
// entre la copie et la prochaine ouverture, la vérification du MAC échoue
// alors que les données sont correctes. Ce test vérifie que les données
// copiées sont lisibles après une éviction du cache.
#[tokio::test]
async fn test_bug_copy_from_dirty_source_survives_cache_eviction() {
    let root = "bug_test_copy_dirty_src";
    let (dav_fs, _) = setup_test_env(root);
    let src_path = DavPath::new("/source.enc").unwrap();
    let dst_path = DavPath::new("/dest.enc").unwrap();
    let src_phys = PathBuf::from(root).join("source.enc");
    let dst_phys = PathBuf::from(root).join("dest.enc");
    let payload: &[u8] = b"dirty source data to copy";

    // Écrire sans flush explicite (le cache reste dirty).
    {
        let mut f = dav_fs
            .open(
                &src_path,
                OpenOptions {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::copy_from_slice(payload)).await.unwrap();
        // PAS de flush : le fichier source est dirty dans le cache.
    }

    // Copier immédiatement (source still in cache, dirty).
    dav_fs.copy(&src_path, &dst_path).await.unwrap();

    // Évincer les deux entrées du cache.
    dav_fs.cache.remove(&src_phys);
    dav_fs.cache.remove(&dst_phys);

    // Relire la destination après éviction (déclenche la vérification MAC).
    let mut f = dav_fs
        .open(
            &dst_path,
            OpenOptions {
                read: true,
                ..Default::default()
            },
        )
        .await
        .expect("BUG-5 : la destination copiée depuis une source dirty échoue à la réouverture (MAC invalide)");

    let content = f.read_bytes(payload.len()).await.unwrap();
    assert_eq!(
        content.as_ref(),
        payload,
        "BUG-5 : le contenu de la destination est incorrect après copie d'une source dirty"
    );

    let _ = fs::remove_dir_all(root);
}
