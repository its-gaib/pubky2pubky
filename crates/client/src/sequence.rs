use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{ClientError, Result};

const STATE_FILE: &str = "sequences.json";
const LOCK_FILE: &str = ".sequences.lock";
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const MAX_STATE_ENTRIES: usize = 4_096;

/// Atomically remembers the greatest authenticated generation or sequence seen for a key.
///
/// Stores must allow the same value to be observed repeatedly and reject values below the
/// stored floor. Callers must authenticate a record before passing its counter here.
#[async_trait]
pub trait SequenceStore: Send + Sync {
    /// Record an authenticated monotonic value, rejecting rollback.
    async fn record(&self, identity: &str, scope: &str, value: u64) -> Result<()>;
}

/// Allocate strictly increasing locator publication sequences.
///
/// Production callers should use [`FileSequenceStore`]. If publisher state is lost, opening an
/// old device credential must fail rather than silently restarting at one; issue a new root-signed
/// device certificate and explicitly initialize its counter instead.
#[async_trait]
pub trait PublisherSequenceStore: Send + Sync {
    /// Atomically allocate the next sequence for a certified control key.
    async fn next_locator_sequence(&self, identity: &str, control_key: &str) -> Result<u64>;
}

/// Process-local anti-rollback state for tests and ephemeral clients.
#[derive(Debug, Clone, Default)]
pub struct MemorySequenceStore {
    values: Arc<Mutex<BTreeMap<String, u64>>>,
}

#[async_trait]
impl SequenceStore for MemorySequenceStore {
    async fn record(&self, identity: &str, scope: &str, value: u64) -> Result<()> {
        if value == 0 {
            return Err(ClientError::State(
                "sequence values must be greater than zero".to_owned(),
            ));
        }
        let key = state_key(identity, scope)?;
        let mut values = self.values.lock().await;
        record_value(&mut values, key, value)
    }
}

impl MemorySequenceStore {
    /// Initialize an ephemeral publisher counter for tests.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed keys or a counter that was already initialized.
    pub async fn initialize_locator_publisher(
        &self,
        identity: &str,
        control_key: &str,
    ) -> Result<()> {
        let key = publisher_key(identity, control_key)?;
        let mut values = self.values.lock().await;
        initialize_publisher(&mut values, key)
    }
}

#[async_trait]
impl PublisherSequenceStore for MemorySequenceStore {
    async fn next_locator_sequence(&self, identity: &str, control_key: &str) -> Result<u64> {
        let key = publisher_key(identity, control_key)?;
        let mut values = self.values.lock().await;
        next_publisher_value(&mut values, &key)
    }
}

/// Durable, atomically replaced anti-rollback state for native clients.
///
/// The directory is canonicalized once. State is always stored in the fixed
/// `sequences.json` child at mode `0600`; caller-controlled identity/scope values are JSON map
/// keys and are never interpreted as path components. Updates are serialized within this
/// store instance and committed by `fsync`, rename, and directory `fsync`.
#[derive(Debug, Clone)]
pub struct FileSequenceStore {
    directory: Arc<PathBuf>,
    update_lock: Arc<Mutex<()>>,
}

impl FileSequenceStore {
    /// Open or create an anti-rollback directory.
    ///
    /// # Errors
    ///
    /// Returns an error for a symlink/non-directory path or an inaccessible directory.
    pub fn new(directory: impl AsRef<Path>) -> Result<Self> {
        let requested = directory.as_ref();
        match fs::symlink_metadata(requested) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ClientError::State(
                        "sequence-store path must be a real directory".to_owned(),
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(requested)?;
            }
            Err(error) => return Err(ClientError::State(error.to_string())),
        }
        let directory = requested
            .canonicalize()
            .map_err(|error| ClientError::State(error.to_string()))?;
        validate_private_directory(
            &fs::metadata(&directory).map_err(|error| ClientError::State(error.to_string()))?,
        )?;
        Ok(Self {
            directory: Arc::new(directory),
            update_lock: Arc::new(Mutex::new(())),
        })
    }

    fn state_path(&self) -> PathBuf {
        self.directory.join(STATE_FILE)
    }

    /// Initialize a zero counter for a freshly issued root-signed device certificate.
    ///
    /// This operation is intentionally separate from [`Self::next_locator_sequence`]. Normal
    /// startup must never call it automatically: a missing counter for an existing credential is
    /// indistinguishable from state loss and requires certificate rotation.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is malformed, already used, or durable state cannot be written.
    pub async fn initialize_locator_publisher(
        &self,
        identity: &str,
        control_key: &str,
    ) -> Result<()> {
        let key = publisher_key(identity, control_key)?;
        let _guard = self.update_lock.lock().await;
        let directory = Arc::clone(&self.directory);
        let path = self.state_path();
        tokio::task::spawn_blocking(move || {
            update_file(&directory, &path, |values| {
                initialize_publisher(values, key)
            })
        })
        .await
        .map_err(|error| ClientError::State(format!("state writer stopped: {error}")))?
    }
}

#[async_trait]
impl SequenceStore for FileSequenceStore {
    async fn record(&self, identity: &str, scope: &str, value: u64) -> Result<()> {
        if value == 0 {
            return Err(ClientError::State(
                "sequence values must be greater than zero".to_owned(),
            ));
        }
        let key = state_key(identity, scope)?;
        let _guard = self.update_lock.lock().await;
        let directory = Arc::clone(&self.directory);
        let path = self.state_path();
        tokio::task::spawn_blocking(move || {
            update_file(&directory, &path, |values| record_value(values, key, value))
        })
        .await
        .map_err(|error| ClientError::State(format!("state writer stopped: {error}")))?
    }
}

#[async_trait]
impl PublisherSequenceStore for FileSequenceStore {
    async fn next_locator_sequence(&self, identity: &str, control_key: &str) -> Result<u64> {
        let key = publisher_key(identity, control_key)?;
        let _guard = self.update_lock.lock().await;
        let directory = Arc::clone(&self.directory);
        let path = self.state_path();
        tokio::task::spawn_blocking(move || {
            update_file(&directory, &path, |values| {
                next_publisher_value(values, &key)
            })
        })
        .await
        .map_err(|error| ClientError::State(format!("state writer stopped: {error}")))?
    }
}

fn state_key(identity: &str, scope: &str) -> Result<String> {
    let parsed = identity
        .parse::<pubky::PublicKey>()
        .map_err(|_| ClientError::State("non-canonical Pubky identity".to_owned()))?;
    if parsed.z32() != identity {
        return Err(ClientError::State(
            "non-canonical Pubky identity".to_owned(),
        ));
    }
    if scope.is_empty()
        || scope.len() > 128
        || !scope
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
    {
        return Err(ClientError::State("invalid sequence scope".to_owned()));
    }
    Ok(format!("{identity}:{scope}"))
}

fn publisher_key(identity: &str, control_key: &str) -> Result<String> {
    let parsed = control_key
        .parse::<pubky::PublicKey>()
        .map_err(|_| ClientError::State("non-canonical control key".to_owned()))?;
    if parsed.z32() != control_key {
        return Err(ClientError::State("non-canonical control key".to_owned()));
    }
    state_key(identity, &format!("publisher:{control_key}"))
}

fn record_value(values: &mut BTreeMap<String, u64>, key: String, value: u64) -> Result<()> {
    if values.get(&key).is_some_and(|previous| value < *previous) {
        return Err(ClientError::State(
            "authenticated record rolled back".to_owned(),
        ));
    }
    if !values.contains_key(&key) && values.len() >= MAX_STATE_ENTRIES {
        return Err(ClientError::State(
            "sequence store reached its entry limit".to_owned(),
        ));
    }
    values.insert(key, value);
    Ok(())
}

fn initialize_publisher(values: &mut BTreeMap<String, u64>, key: String) -> Result<()> {
    if values.contains_key(&key) {
        return Err(ClientError::State(
            "publisher counter is already initialized; rotate the device certificate".to_owned(),
        ));
    }
    if values.len() >= MAX_STATE_ENTRIES {
        return Err(ClientError::State(
            "sequence store reached its entry limit".to_owned(),
        ));
    }
    values.insert(key, 0);
    Ok(())
}

fn next_publisher_value(values: &mut BTreeMap<String, u64>, key: &str) -> Result<u64> {
    let value = values.get_mut(key).ok_or_else(|| {
        ClientError::State(
            "publisher state is missing; rotate the root-signed device certificate".to_owned(),
        )
    })?;
    *value = value.checked_add(1).ok_or_else(|| {
        ClientError::State("publisher sequence exhausted; rotate the device certificate".to_owned())
    })?;
    Ok(*value)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|error| ClientError::State(error.to_string()))
}

fn update_file<T>(
    directory: &Path,
    path: &Path,
    update: impl FnOnce(&mut BTreeMap<String, u64>) -> Result<T>,
) -> Result<T> {
    let lock = open_and_lock(directory)?;
    let mut values = read_state(path)?;
    let result = update(&mut values)?;
    let encoded =
        serde_json::to_vec(&values).map_err(|error| ClientError::State(error.to_string()))?;
    if encoded.len() as u64 > MAX_STATE_BYTES {
        return Err(ClientError::State("sequence state is too large".to_owned()));
    }

    let temporary = directory.join(format!(".sequences-{}.tmp", Uuid::new_v4()));
    let write_result = (|| -> Result<()> {
        let mut file = private_create_new(&temporary)?;
        file.write_all(&encoded)
            .map_err(|error| ClientError::State(error.to_string()))?;
        file.sync_all()
            .map_err(|error| ClientError::State(error.to_string()))?;
        fs::rename(&temporary, path).map_err(|error| ClientError::State(error.to_string()))?;
        File::open(directory)
            .and_then(|directory_file| directory_file.sync_all())
            .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result?;
    fs2::FileExt::unlock(&lock).map_err(|error| ClientError::State(error.to_string()))?;
    Ok(result)
}

fn read_state(path: &Path) -> Result<BTreeMap<String, u64>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(ClientError::State(error.to_string())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_STATE_BYTES
    {
        return Err(ClientError::State("invalid sequence state file".to_owned()));
    }
    let file = no_follow_read(path)?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| ClientError::State(error.to_string()))?;
    validate_private_file(&opened_metadata)?;
    if opened_metadata.len() > MAX_STATE_BYTES {
        return Err(ClientError::State("sequence state is too large".to_owned()));
    }
    let capacity = usize::try_from(opened_metadata.len())
        .map_err(|_| ClientError::State("sequence state is too large".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ClientError::State(error.to_string()))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ClientError::State("sequence state is too large".to_owned()));
    }
    let values: BTreeMap<String, u64> =
        serde_json::from_slice(&bytes).map_err(|error| ClientError::State(error.to_string()))?;
    if values.len() > MAX_STATE_ENTRIES {
        return Err(ClientError::State(
            "sequence state has too many entries".to_owned(),
        ));
    }
    Ok(values)
}

#[cfg(unix)]
fn validate_private_directory(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(ClientError::State(
            "sequence-store directory must be owner-only".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_dir() {
        return Err(ClientError::State(
            "sequence-store path must be a directory".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        return Err(ClientError::State(
            "sequence state must be a single-link mode-0600 file".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
const fn validate_private_file(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn private_create_new(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(not(unix))]
fn private_create_new(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(unix)]
fn no_follow_read(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(unix)]
fn private_open_lock(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(not(unix))]
fn private_open_lock(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

fn open_and_lock(directory: &Path) -> Result<File> {
    let lock = private_open_lock(&directory.join(LOCK_FILE))?;
    validate_private_file(
        &lock
            .metadata()
            .map_err(|error| ClientError::State(error.to_string()))?,
    )?;
    fs2::FileExt::lock_exclusive(&lock).map_err(|error| ClientError::State(error.to_string()))?;
    Ok(lock)
}

#[cfg(not(unix))]
fn no_follow_read(path: &Path) -> Result<File> {
    File::open(path).map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use pubky::Keypair;

    use super::*;

    #[tokio::test]
    async fn memory_store_allows_repeat_and_rejects_rollback() {
        let identity = Keypair::random().public_key().z32();
        let store = MemorySequenceStore::default();
        store
            .record(&identity, "directory", 2)
            .await
            .unwrap_or_else(|error| panic!("first record: {error}"));
        store
            .record(&identity, "directory", 2)
            .await
            .unwrap_or_else(|error| panic!("repeat record: {error}"));
        assert!(store.record(&identity, "directory", 1).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_store_is_private_durable_and_rejects_symlink() {
        let base = std::env::temp_dir().join(format!("hp-v3-sequence-{}", Uuid::new_v4()));
        let identity = Keypair::random().public_key().z32();
        let store =
            FileSequenceStore::new(&base).unwrap_or_else(|error| panic!("creating store: {error}"));
        store
            .record(&identity, "locator:key", 9)
            .await
            .unwrap_or_else(|error| panic!("writing state: {error}"));
        let metadata = fs::metadata(base.join(STATE_FILE))
            .unwrap_or_else(|error| panic!("state metadata: {error}"));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let reopened = FileSequenceStore::new(&base)
            .unwrap_or_else(|error| panic!("reopening store: {error}"));
        assert!(reopened.record(&identity, "locator:key", 8).await.is_err());
        fs::remove_dir_all(&base).unwrap_or_else(|error| panic!("cleanup: {error}"));

        let target = std::env::temp_dir().join(format!("hp-v3-target-{}", Uuid::new_v4()));
        let link = std::env::temp_dir().join(format!("hp-v3-link-{}", Uuid::new_v4()));
        fs::create_dir(&target).unwrap_or_else(|error| panic!("target: {error}"));
        std::os::unix::fs::symlink(&target, &link)
            .unwrap_or_else(|error| panic!("symlink: {error}"));
        assert!(FileSequenceStore::new(&link).is_err());
        fs::remove_file(&link).unwrap_or_else(|error| panic!("remove link: {error}"));
        fs::remove_dir(&target).unwrap_or_else(|error| panic!("remove target: {error}"));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publisher_counter_requires_initialization_and_is_cross_instance_atomic() {
        let base = std::env::temp_dir().join(format!("p2p-v3-publisher-{}", Uuid::new_v4()));
        let identity = Keypair::random().public_key().z32();
        let control = Keypair::random().public_key().z32();
        let first = FileSequenceStore::new(&base)
            .unwrap_or_else(|error| panic!("creating first store: {error}"));
        assert!(
            first
                .next_locator_sequence(&identity, &control)
                .await
                .is_err(),
            "missing publisher state must fail closed"
        );
        first
            .initialize_locator_publisher(&identity, &control)
            .await
            .unwrap_or_else(|error| panic!("initializing publisher: {error}"));
        assert!(
            first
                .initialize_locator_publisher(&identity, &control)
                .await
                .is_err(),
            "an existing publisher must never be silently reset"
        );
        let second = FileSequenceStore::new(&base)
            .unwrap_or_else(|error| panic!("creating second store: {error}"));
        let (left, right) = tokio::join!(
            first.next_locator_sequence(&identity, &control),
            second.next_locator_sequence(&identity, &control)
        );
        let mut allocated = [
            left.unwrap_or_else(|error| panic!("first allocation: {error}")),
            right.unwrap_or_else(|error| panic!("second allocation: {error}")),
        ];
        allocated.sort_unstable();
        assert_eq!(allocated, [1, 2]);
        let reopened = FileSequenceStore::new(&base)
            .unwrap_or_else(|error| panic!("reopening publisher store: {error}"));
        assert_eq!(
            reopened
                .next_locator_sequence(&identity, &control)
                .await
                .unwrap_or_else(|error| panic!("third allocation: {error}")),
            3
        );
        fs::remove_dir_all(&base).unwrap_or_else(|error| panic!("cleanup: {error}"));
    }
}
