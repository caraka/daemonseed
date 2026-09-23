//! Starting Veilid with its device encryption key protected by a password.
//!
//! Veilid's table store encrypts every table under a device encryption key,
//! and keeps that key in the protected store. This crate uses the insecure
//! (on-disk) protected store, so the key sits in a file beside the tables it
//! opens unless Veilid is given a password to protect it under.
//! [`crate::config::VeilidNetConfig::device_key_password`] is that password.
//!
//! A storage directory whose key does not open under the configured password —
//! one written without a password, or under another password — makes Veilid's
//! startup fail. [`startup_protected`] recognises those failures by their
//! error, confirms each by starting once more over an empty table directory —
//! which runs the same key check and reads no table, so a failure there is the
//! key's — and only then removes this namespace's protected-store keyring and
//! tables and starts again, so Veilid creates a new key under the configured
//! password. The tables hold caches the network rebuilds; nothing daemonseed
//! keeps is in them.

use std::path::Path;

use veilid_core::{api_startup, VeilidAPI, VeilidAPIError, VeilidAPIResult, VeilidConfig};

/// The message `veilid-core` 0.5.7's table store fails its startup with when
/// the stored device encryption key was stored without a password and a
/// password is configured (`table_store/mod.rs`,
/// `maybe_unprotect_device_encryption_key`): the key has the length of an
/// unprotected one. `api_startup` reports it as [`VeilidAPIError::Internal`].
const UNPROTECTED_KEY: &str = "password protected device encryption key is not valid";

/// The message of the error the same function fails with when the key was
/// stored under another password: its AEAD decryption fails, and `api_startup`
/// reports that inner error, [`VeilidAPIError::Generic`], rather than the
/// context the table store wraps it in. A table that does not decrypt fails
/// with an AEAD error too, which is why a match is confirmed before anything
/// is removed.
const WRONG_PASSWORD: &str = "aead::Error";

/// Whether a startup failure has the shape of the table store refusing the
/// stored device encryption key under the configured password.
pub(crate) fn refuses_device_key(error: &VeilidAPIError) -> bool {
    match error {
        VeilidAPIError::Internal { message } => message.contains(UNPROTECTED_KEY),
        VeilidAPIError::Generic { message } => message.contains(WRONG_PASSWORD),
        _ => false,
    }
}

/// Remove what Veilid keeps for `namespace` in `config`'s protected-store and
/// table-store directories: the insecure keyring holding the device encryption
/// key and every table of the namespace. Files of other namespaces are left.
/// Returns how many entries were removed.
///
/// Veilid names a namespace's keyring `insecure_keyring_<namespace>` and its
/// tables `<namespace>_<table>`. An empty namespace is refused: its tables
/// carry no prefix, so no name tells them from another namespace's.
pub(crate) fn clear_namespace_storage(config: &VeilidConfig) -> std::io::Result<usize> {
    let namespace = &config.namespace;
    if namespace.is_empty() {
        return Err(std::io::Error::other(
            "an empty namespace names every table in the directory",
        ));
    }
    let keyring = format!("insecure_keyring_{namespace}");
    let mut removed = remove_matching(Path::new(&config.protected_store.directory), |name| {
        name == keyring || name.starts_with(&format!("{keyring}."))
    })?;
    let table_prefix = format!("{namespace}_");
    removed += remove_matching(Path::new(&config.table_store.directory), |name| {
        name.starts_with(&table_prefix)
    })?;
    Ok(removed)
}

/// Remove every entry of `dir` whose name `matches`, files and directories
/// alike. A directory that does not exist holds nothing to remove.
fn remove_matching(dir: &Path, matches: impl Fn(&str) -> bool) -> std::io::Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_str().is_some_and(&matches) {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
        removed += 1;
    }
    Ok(removed)
}

/// Start Veilid with `config`, and where the stored device encryption key does
/// not open under its password, clear this namespace's storage
/// ([`clear_namespace_storage`]) and start once more. Any other failure, and
/// a failure of the second start, is returned.
pub(crate) async fn startup_protected(
    update_callback: veilid_core::UpdateCallback,
    config: VeilidConfig,
) -> VeilidAPIResult<VeilidAPI> {
    match api_startup(update_callback.clone(), config.clone()).await {
        Err(error)
            if refuses_device_key(&error)
                && key_refused_without_tables(update_callback.clone(), &config).await =>
        {
            let removed = clear_namespace_storage(&config)
                .map_err(|e| VeilidAPIError::generic(e.to_string()))?;
            crate::vtrace!(
                "start: the stored device key does not open under this password; \
                 cleared {removed} storage entr(ies) of this namespace and starting again"
            );
            api_startup(update_callback, config).await
        }
        started => started,
    }
}

/// Whether the stored device encryption key is refused under `config`'s
/// password when no table is read: a start over the same protected store and a
/// fresh, empty table directory, removed afterwards. That start runs the same
/// key check, and a refusal from it can only be the key's.
async fn key_refused_without_tables(
    update_callback: veilid_core::UpdateCallback,
    config: &VeilidConfig,
) -> bool {
    let Some(tag) = crate::config::random_password(getrandom::fill) else {
        return false;
    };
    let probe_dir =
        std::env::temp_dir().join(format!("daemonseed-device-key-probe-{}", &tag[..16]));
    let mut probe = config.clone();
    probe.table_store.directory = probe_dir.join("table_store").to_string_lossy().into_owned();
    probe.block_store.directory = probe_dir.join("block_store").to_string_lossy().into_owned();
    let refused = match api_startup(update_callback, probe).await {
        Ok(api) => {
            api.shutdown().await;
            false
        }
        Err(error) => refuses_device_key(&error),
    };
    let _ = std::fs::remove_dir_all(&probe_dir);
    refused
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    /// A Veilid config over `dir` under `namespace`, protecting its device key
    /// under `password`. Nothing here attaches to a network.
    fn config(dir: &Path, namespace: &str, password: &str) -> VeilidConfig {
        let mut config = VeilidConfig::new(
            "daemonseed_veilid_net_device_key",
            "daemonseed",
            "test",
            Some(&dir.to_string_lossy()),
            None,
        );
        config.namespace = namespace.to_owned();
        config.protected_store.always_use_insecure_storage = true;
        config.protected_store.allow_insecure_fallback = true;
        config.protected_store.device_encryption_key_password = password.to_owned();
        config
    }

    fn quiet() -> veilid_core::UpdateCallback {
        Arc::new(|_| {})
    }

    /// Start the node `start` brings up, then shut it down.
    async fn start_and_stop(
        start: impl core::future::Future<Output = VeilidAPIResult<VeilidAPI>>,
    ) -> VeilidAPIResult<()> {
        let api = start.await?;
        api.shutdown().await;
        Ok(())
    }

    /// Storage created under a password does not open without it or under
    /// another one. Only the failure under another password is the one
    /// [`refuses_device_key`] recognises. The failure with no password, like a
    /// failure of another kind, is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_store_created_with_a_password_does_not_open_without_it() {
        let tmp = tempfile::tempdir().expect("a directory");
        let ns = "dk-refuse";
        start_and_stop(api_startup(
            quiet(),
            config(tmp.path(), ns, "first password"),
        ))
        .await
        .expect("the first start creates a protected key");
        start_and_stop(api_startup(
            quiet(),
            config(tmp.path(), ns, "first password"),
        ))
        .await
        .expect("the same password opens it again");
        for password in ["", "another password"] {
            let refused = api_startup(quiet(), config(tmp.path(), ns, password))
                .await
                .err()
                .unwrap_or_else(|| panic!("{password:?} opened a protected key"));
            if password.is_empty() {
                assert!(!refuses_device_key(&refused), "{refused:?}");
            } else {
                assert!(refuses_device_key(&refused), "{refused:?}");
            }
        }
        assert!(!refuses_device_key(&VeilidAPIError::internal(
            "something else"
        )));
        assert!(!refuses_device_key(&VeilidAPIError::generic(
            "something else"
        )));
    }

    /// Storage is removed only when the key itself is refused: the check over
    /// an empty table directory passes for the password the key was stored
    /// under, fails for another, and touches no table of the store. An empty
    /// namespace is refused rather than cleared.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_refused_key_is_confirmed_for_removal() {
        let tmp = tempfile::tempdir().expect("a directory");
        let ns = "dk-confirm";
        start_and_stop(api_startup(
            quiet(),
            config(tmp.path(), ns, "stored password"),
        ))
        .await
        .expect("a protected key");
        let tables = |dir: &Path| {
            std::fs::read_dir(Path::new(&config(dir, ns, "").table_store.directory))
                .map(|entries| entries.count())
                .unwrap_or(0)
        };
        let before = tables(tmp.path());
        assert!(before > 0, "the store holds tables");
        assert!(
            !key_refused_without_tables(quiet(), &config(tmp.path(), ns, "stored password")).await,
            "the key opens under its own password"
        );
        assert!(
            key_refused_without_tables(quiet(), &config(tmp.path(), ns, "another password")).await,
            "the key is refused under another password"
        );
        assert_eq!(
            tables(tmp.path()),
            before,
            "the check read and wrote no table"
        );
        assert!(clear_namespace_storage(&config(tmp.path(), "", "")).is_err());
    }

    /// Storage whose device key was stored without a password is cleared and
    /// recreated under the configured
    /// password: the start succeeds, the key is then protected, and a start
    /// under the same password opens it without clearing anything. Another
    /// namespace's files in the same directories are left in place.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_store_with_an_unprotected_key_is_recreated() {
        let tmp = tempfile::tempdir().expect("a directory");
        let ns = "dk-recreate";
        start_and_stop(api_startup(quiet(), config(tmp.path(), ns, "")))
            .await
            .expect("an unprotected key");
        let neighbour = config(tmp.path(), "dk-neighbour", "");
        std::fs::write(
            Path::new(&neighbour.table_store.directory).join("dk-neighbour_table"),
            b"kept",
        )
        .expect("a neighbour's table");

        let refused = api_startup(quiet(), config(tmp.path(), ns, "profile password"))
            .await
            .expect_err("the unprotected key does not open under a password");
        assert!(refuses_device_key(&refused), "{refused:?}");

        start_and_stop(startup_protected(
            quiet(),
            config(tmp.path(), ns, "profile password"),
        ))
        .await
        .expect("the storage is recreated and the start succeeds");
        start_and_stop(api_startup(
            quiet(),
            config(tmp.path(), ns, "profile password"),
        ))
        .await
        .expect("the recreated key opens under the password");
        let refused = api_startup(quiet(), config(tmp.path(), ns, "another password"))
            .await
            .expect_err("the recreated key is protected");
        assert!(refuses_device_key(&refused), "{refused:?}");
        assert!(
            Path::new(&neighbour.table_store.directory)
                .join("dk-neighbour_table")
                .exists(),
            "another namespace's table was removed"
        );
    }
}
