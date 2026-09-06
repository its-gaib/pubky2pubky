use std::{collections::BTreeMap, sync::Arc};

#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use tokio::sync::Mutex;
#[cfg(not(target_arch = "wasm32"))]
use uuid::Uuid;

use crate::{ClientError, Result};

#[cfg(not(target_arch = "wasm32"))]
const STATE_FILE: &str = "pubky2pubky-v1-sequences.json";
#[cfg(not(target_arch = "wasm32"))]
const LOCK_FILE: &str = ".pubky2pubky-v1-sequences.lock";
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const MAX_STATE_ENTRIES: usize = 4_096;
const PUBLISHER_SCOPE_PREFIX: &str = "v1:publisher:";

/// One authenticated monotonic record that can be committed with related observations.
///
/// Construction validates the canonical Pubky identity, scope grammar, and positive counter.
/// The digest must authenticate the complete record whose counter is being observed, not just the
/// counter itself. This lets a store reject equivocation at an already-observed counter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSequenceObservation {
    identity: String,
    scope: String,
    counter: u64,
    digest: [u8; 32],
}

impl AuthenticatedSequenceObservation {
    /// Construct a validated authenticated sequence observation.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical identity, invalid scope, or zero counter.
    pub fn new(
        identity: impl Into<String>,
        scope: impl Into<String>,
        counter: u64,
        digest: [u8; 32],
    ) -> Result<Self> {
        let identity = identity.into();
        let scope = scope.into();
        state_key(&identity, &scope)?;
        if scope.starts_with(PUBLISHER_SCOPE_PREFIX) {
            return Err(ClientError::State(
                "publisher sequence scope is reserved".to_owned(),
            ));
        }
        if counter == 0 {
            return Err(ClientError::State(
                "sequence values must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            identity,
            scope,
            counter,
            digest,
        })
    }

    /// Return the canonical Pubky identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Return the validated application scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Return the positive monotonic counter.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Return the authenticated digest of the complete observed record.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredSequence {
    Publisher { counter: u64 },
    Authenticated(AuthenticatedStoredSequence),
}

impl StoredSequence {
    const fn counter(&self) -> u64 {
        match self {
            Self::Publisher { counter } => *counter,
            Self::Authenticated(record) => record.counter,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedStoredSequence {
    counter: u64,
    digest: [u8; 32],
}

type SequenceState = BTreeMap<String, StoredSequence>;

/// Atomically remembers the greatest authenticated generation or sequence seen for a key.
///
/// Stores must allow the same value to be observed repeatedly and reject values below the
/// stored floor. Callers must authenticate a record before passing its counter here.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait SequenceStore: Send + Sync {
    /// Atomically commit digest-bound authenticated observations.
    ///
    /// The entire batch is rejected without mutation if any observation rolls back, equivocates,
    /// conflicts with another observation for the same key, or exceeds a store bound.
    async fn record_batch(&self, observations: Vec<AuthenticatedSequenceObservation>)
    -> Result<()>;
}

/// Allocate strictly increasing locator publication sequences.
///
/// Production callers must use a durable, transactional implementation. If publisher state is
/// lost, opening an old device credential must fail rather than silently restarting at one; issue
/// a new Grant-`cnf`-signed device credential and explicitly initialize its counter instead.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait PublisherSequenceStore: Send + Sync {
    /// Atomically allocate the next sequence for a certified control key.
    async fn next_locator_sequence(&self, identity: &str, control_key: &str) -> Result<u64>;
}

/// Process-local anti-rollback state for tests and disposable prototypes.
///
/// Browser applications that retain a device credential across reloads must instead provide an
/// IndexedDB-backed transactional implementation. Pairing persistent credentials with this store
/// can lose rollback protection or reuse publisher sequences after a reload.
#[derive(Debug, Clone, Default)]
pub struct MemorySequenceStore {
    values: Arc<Mutex<SequenceState>>,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SequenceStore for MemorySequenceStore {
    async fn record_batch(
        &self,
        observations: Vec<AuthenticatedSequenceObservation>,
    ) -> Result<()> {
        let observations = prepare_batch(observations)?;
        let mut values = self.values.lock().await;
        update_memory(&mut values, |staged| {
            record_authenticated_batch(staged, observations)
        })
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
        update_memory(&mut values, |staged| initialize_publisher(staged, key))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl PublisherSequenceStore for MemorySequenceStore {
    async fn next_locator_sequence(&self, identity: &str, control_key: &str) -> Result<u64> {
        let key = publisher_key(identity, control_key)?;
        let mut values = self.values.lock().await;
        update_memory(&mut values, |staged| next_publisher_value(staged, &key))
    }
}

/// Durable, atomically replaced anti-rollback state for native clients.
///
/// The directory is canonicalized once. State is always stored in the fixed
/// `pubky2pubky-v1-sequences.json` child at mode `0600`; caller-controlled identity/scope values
/// are JSON map keys and are never interpreted as path components. Updates are serialized within
/// this store instance and committed by `fsync`, rename, and directory `fsync`.
#[derive(Debug, Clone)]
#[cfg(not(target_arch = "wasm32"))]
pub struct FileSequenceStore {
    directory: Arc<PathBuf>,
    update_lock: Arc<Mutex<()>>,
}

#[cfg(not(target_arch = "wasm32"))]
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

    /// Initialize a zero counter for a freshly issued Grant-`cnf`-signed device credential.
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

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl SequenceStore for FileSequenceStore {
    async fn record_batch(
        &self,
        observations: Vec<AuthenticatedSequenceObservation>,
    ) -> Result<()> {
        let observations = prepare_batch(observations)?;
        let _guard = self.update_lock.lock().await;
        let directory = Arc::clone(&self.directory);
        let path = self.state_path();
        tokio::task::spawn_blocking(move || {
            update_file(&directory, &path, |values| {
                record_authenticated_batch(values, observations)
            })
        })
        .await
        .map_err(|error| ClientError::State(format!("state writer stopped: {error}")))?
    }
}

#[cfg(not(target_arch = "wasm32"))]
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
    state_key(identity, &format!("{PUBLISHER_SCOPE_PREFIX}{control_key}"))
}

fn prepare_batch(
    observations: Vec<AuthenticatedSequenceObservation>,
) -> Result<BTreeMap<String, (u64, [u8; 32])>> {
    let mut prepared = BTreeMap::new();
    for observation in observations {
        if observation.scope.starts_with(PUBLISHER_SCOPE_PREFIX) {
            return Err(ClientError::State(
                "publisher sequence scope is reserved".to_owned(),
            ));
        }
        let key = state_key(&observation.identity, &observation.scope)?;
        let value = (observation.counter, observation.digest);
        if let Some(previous) = prepared.insert(key, value)
            && previous != value
        {
            return Err(ClientError::State(
                "authenticated batch contains conflicting duplicate keys".to_owned(),
            ));
        }
    }
    Ok(prepared)
}

fn record_authenticated_batch(
    values: &mut SequenceState,
    observations: BTreeMap<String, (u64, [u8; 32])>,
) -> Result<()> {
    for (key, (counter, digest)) in observations {
        record_authenticated_value(values, key, counter, digest)?;
    }
    Ok(())
}

fn record_authenticated_value(
    values: &mut SequenceState,
    key: String,
    counter: u64,
    digest: [u8; 32],
) -> Result<()> {
    match values.get(&key) {
        Some(StoredSequence::Publisher { .. }) => {
            return Err(ClientError::State(
                "authenticated observation conflicts with publisher state".to_owned(),
            ));
        }
        Some(previous) if counter < previous.counter() => {
            return Err(ClientError::State(
                "authenticated record rolled back".to_owned(),
            ));
        }
        Some(StoredSequence::Authenticated(previous)) if counter == previous.counter => {
            if digest == previous.digest {
                return Ok(());
            }
            return Err(ClientError::State(
                "authenticated record equivocated at an existing counter".to_owned(),
            ));
        }
        None if values.len() >= MAX_STATE_ENTRIES => {
            return Err(ClientError::State(
                "sequence store reached its entry limit".to_owned(),
            ));
        }
        Some(_) | None => {}
    }
    values.insert(
        key,
        StoredSequence::Authenticated(AuthenticatedStoredSequence { counter, digest }),
    );
    Ok(())
}

fn initialize_publisher(values: &mut SequenceState, key: String) -> Result<()> {
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
    values.insert(key, StoredSequence::Publisher { counter: 0 });
    Ok(())
}

fn next_publisher_value(values: &mut SequenceState, key: &str) -> Result<u64> {
    let value = values.get_mut(key).ok_or_else(|| {
        ClientError::State("publisher state is missing; rotate the device credential".to_owned())
    })?;
    let StoredSequence::Publisher { counter } = value else {
        return Err(ClientError::State(
            "publisher counter conflicts with authenticated sequence state; rotate the device certificate"
                .to_owned(),
        ));
    };
    *counter = counter.checked_add(1).ok_or_else(|| {
        ClientError::State("publisher sequence exhausted; rotate the device certificate".to_owned())
    })?;
    Ok(*counter)
}

fn update_memory<T>(
    values: &mut SequenceState,
    update: impl FnOnce(&mut SequenceState) -> Result<T>,
) -> Result<T> {
    let mut staged = values.clone();
    let result = update(&mut staged)?;
    validate_state_bounds(&staged)?;
    *values = staged;
    Ok(result)
}

fn validate_state_bounds(values: &SequenceState) -> Result<()> {
    if values.len() > MAX_STATE_ENTRIES {
        return Err(ClientError::State(
            "sequence store reached its entry limit".to_owned(),
        ));
    }
    let encoded =
        serde_json::to_vec(values).map_err(|error| ClientError::State(error.to_string()))?;
    if encoded.len() as u64 > MAX_STATE_BYTES {
        return Err(ClientError::State("sequence state is too large".to_owned()));
    }
    Ok(())
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(all(not(unix), not(target_arch = "wasm32")))]
fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
fn update_file<T>(
    directory: &Path,
    path: &Path,
    update: impl FnOnce(&mut SequenceState) -> Result<T>,
) -> Result<T> {
    let lock = open_and_lock(directory)?;
    let mut values = read_state(path)?;
    let result = update(&mut values)?;
    validate_state_bounds(&values)?;
    let encoded =
        serde_json::to_vec(&values).map_err(|error| ClientError::State(error.to_string()))?;

    let temporary = directory.join(format!(".pubky2pubky-v1-sequences-{}.tmp", Uuid::new_v4()));
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

#[cfg(not(target_arch = "wasm32"))]
fn read_state(path: &Path) -> Result<SequenceState> {
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
    let values: SequenceState =
        serde_json::from_slice(&bytes).map_err(|error| ClientError::State(error.to_string()))?;
    validate_state_bounds(&values)?;
    for (key, value) in &values {
        validate_stored_entry(key, value)?;
    }
    Ok(values)
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_stored_entry(key: &str, value: &StoredSequence) -> Result<()> {
    let (identity, scope) = key
        .split_once(':')
        .ok_or_else(|| ClientError::State("invalid sequence state key".to_owned()))?;
    if state_key(identity, scope)? != key {
        return Err(ClientError::State(
            "non-canonical sequence state key".to_owned(),
        ));
    }
    match value {
        StoredSequence::Authenticated(record) if record.counter == 0 => Err(ClientError::State(
            "authenticated sequence state contains a zero counter".to_owned(),
        )),
        StoredSequence::Authenticated(_) if scope.starts_with(PUBLISHER_SCOPE_PREFIX) => Err(
            ClientError::State("authenticated sequence state uses a reserved scope".to_owned()),
        ),
        StoredSequence::Publisher { .. } if !valid_publisher_scope(scope) => Err(
            ClientError::State("publisher sequence state has an invalid scope".to_owned()),
        ),
        _ => Ok(()),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn valid_publisher_scope(scope: &str) -> bool {
    let Some(control_key) = scope.strip_prefix(PUBLISHER_SCOPE_PREFIX) else {
        return false;
    };
    control_key
        .parse::<pubky::PublicKey>()
        .is_ok_and(|parsed| parsed.z32() == control_key)
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn validate_private_directory(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(ClientError::State(
            "sequence-store directory must be owner-only".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(all(not(unix), not(target_arch = "wasm32")))]
fn validate_private_directory(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_dir() {
        return Err(ClientError::State(
            "sequence-store path must be a directory".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn validate_private_file(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        return Err(ClientError::State(
            "sequence state must be a single-link mode-0600 file".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(all(not(unix), not(target_arch = "wasm32")))]
const fn validate_private_file(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
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

#[cfg(all(not(unix), not(target_arch = "wasm32")))]
fn private_create_new(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn no_follow_read(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
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

#[cfg(all(not(unix), not(target_arch = "wasm32")))]
fn private_open_lock(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(all(not(unix), not(target_arch = "wasm32")))]
fn no_follow_read(path: &Path) -> Result<File> {
    File::open(path).map_err(|error| ClientError::State(error.to_string()))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use pubky::Keypair;

    use super::*;

    fn observation(
        identity: &str,
        scope: &str,
        counter: u64,
        digest_byte: u8,
    ) -> AuthenticatedSequenceObservation {
        AuthenticatedSequenceObservation::new(identity, scope, counter, [digest_byte; 32])
            .unwrap_or_else(|error| panic!("valid observation: {error}"))
    }

    #[test]
    fn authenticated_observation_validates_its_owned_fields() {
        let identity = Keypair::random().public_key().z32();
        let control = Keypair::random().public_key().z32();
        let record =
            AuthenticatedSequenceObservation::new(identity.clone(), "locator:device", 7, [42; 32])
                .unwrap_or_else(|error| panic!("valid observation: {error}"));
        assert_eq!(record.identity(), identity);
        assert_eq!(record.scope(), "locator:device");
        assert_eq!(record.counter(), 7);
        assert_eq!(record.digest(), &[42; 32]);
        assert!(
            AuthenticatedSequenceObservation::new(identity.clone(), "directory", 0, [0; 32])
                .is_err()
        );
        assert!(
            AuthenticatedSequenceObservation::new(identity.clone(), "invalid/scope", 1, [0; 32])
                .is_err()
        );
        assert!(
            AuthenticatedSequenceObservation::new(
                identity,
                format!("{PUBLISHER_SCOPE_PREFIX}{control}"),
                1,
                [0; 32],
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn authenticated_batch_cannot_replace_publisher_state() {
        let identity = Keypair::random().public_key().z32();
        let control = Keypair::random().public_key().z32();
        let scope = format!("{PUBLISHER_SCOPE_PREFIX}{control}");
        let store = MemorySequenceStore::default();
        store
            .initialize_locator_publisher(&identity, &control)
            .await
            .unwrap_or_else(|error| panic!("initializing publisher: {error}"));

        let forged = AuthenticatedSequenceObservation {
            identity: identity.clone(),
            scope,
            counter: 1,
            digest: [7; 32],
        };
        assert!(store.record_batch(vec![forged]).await.is_err());
        assert_eq!(
            store
                .next_locator_sequence(&identity, &control)
                .await
                .unwrap_or_else(|error| panic!("allocating publisher sequence: {error}")),
            1
        );
    }

    #[tokio::test]
    async fn memory_authenticated_batch_is_atomic_and_binds_equal_counters() {
        let identity = Keypair::random().public_key().z32();
        let store = MemorySequenceStore::default();
        let directory = observation(&identity, "directory", 2, 10);
        store
            .record_batch(vec![directory.clone()])
            .await
            .unwrap_or_else(|error| panic!("initial batch: {error}"));
        store
            .record_batch(vec![directory])
            .await
            .unwrap_or_else(|error| panic!("equal record with same digest: {error}"));
        assert!(
            store
                .record_batch(vec![observation(&identity, "directory", 2, 11)])
                .await
                .is_err(),
            "an equal counter with a different digest must be rejected"
        );
        assert!(
            store
                .record_batch(vec![observation(&identity, "directory", 1, 10)])
                .await
                .is_err(),
            "a lower counter must be rejected"
        );

        assert!(
            store
                .record_batch(vec![
                    observation(&identity, "locator:new", 1, 20),
                    observation(&identity, "directory", 1, 10),
                ])
                .await
                .is_err(),
            "one invalid observation must roll back the whole batch"
        );
        store
            .record_batch(vec![observation(&identity, "locator:new", 1, 21)])
            .await
            .unwrap_or_else(|error| panic!("rolled-back key must remain absent: {error}"));
    }

    #[tokio::test]
    async fn authenticated_batch_rejects_conflicting_duplicates() {
        let identity = Keypair::random().public_key().z32();
        let store = MemorySequenceStore::default();
        assert!(
            store
                .record_batch(vec![
                    observation(&identity, "directory", 1, 1),
                    observation(&identity, "directory", 2, 1),
                ])
                .await
                .is_err()
        );
        assert!(
            store
                .record_batch(vec![
                    observation(&identity, "directory", 1, 1),
                    observation(&identity, "directory", 1, 2),
                ])
                .await
                .is_err()
        );
        store
            .record_batch(vec![
                observation(&identity, "directory", 1, 3),
                observation(&identity, "directory", 1, 3),
            ])
            .await
            .unwrap_or_else(|error| panic!("identical duplicates are idempotent: {error}"));
    }

    #[tokio::test]
    async fn file_authenticated_batch_persists_and_rolls_back_atomically() {
        let base = std::env::temp_dir().join(format!("p2p-v1-auth-sequence-{}", Uuid::new_v4()));
        let identity = Keypair::random().public_key().z32();
        let first =
            FileSequenceStore::new(&base).unwrap_or_else(|error| panic!("creating store: {error}"));
        first
            .record_batch(vec![
                observation(&identity, "directory", 4, 30),
                observation(&identity, "locator:one", 8, 31),
            ])
            .await
            .unwrap_or_else(|error| panic!("writing batch: {error}"));

        let reopened = FileSequenceStore::new(&base)
            .unwrap_or_else(|error| panic!("reopening store: {error}"));
        reopened
            .record_batch(vec![observation(&identity, "directory", 4, 30)])
            .await
            .unwrap_or_else(|error| panic!("persisted equal observation: {error}"));
        assert!(
            reopened
                .record_batch(vec![observation(&identity, "directory", 4, 32)])
                .await
                .is_err()
        );
        assert!(
            reopened
                .record_batch(vec![
                    observation(&identity, "locator:two", 1, 40),
                    observation(&identity, "locator:one", 7, 31),
                ])
                .await
                .is_err()
        );

        let after_failed_batch = FileSequenceStore::new(&base)
            .unwrap_or_else(|error| panic!("reopening after failed batch: {error}"));
        after_failed_batch
            .record_batch(vec![observation(&identity, "locator:two", 1, 41)])
            .await
            .unwrap_or_else(|error| panic!("failed batch must not persist new key: {error}"));
        fs::remove_dir_all(&base).unwrap_or_else(|error| panic!("cleanup: {error}"));
    }

    #[tokio::test]
    async fn unpublished_state_file_is_ignored_instead_of_promoted() {
        let base = std::env::temp_dir().join(format!("p2p-v1-clean-sequence-{}", Uuid::new_v4()));
        let identity = Keypair::random().public_key().z32();
        create_private_directory(&base)
            .unwrap_or_else(|error| panic!("creating private directory: {error}"));
        let obsolete = base.join("sequences.json");
        let mut obsolete_file = private_create_new(&obsolete)
            .unwrap_or_else(|error| panic!("creating unpublished state: {error}"));
        obsolete_file
            .write_all(br#"{"unpublished":"state"}"#)
            .unwrap_or_else(|error| panic!("writing unpublished state: {error}"));
        obsolete_file
            .sync_all()
            .unwrap_or_else(|error| panic!("syncing unpublished state: {error}"));

        let store = FileSequenceStore::new(&base)
            .unwrap_or_else(|error| panic!("opening v1 store: {error}"));
        store
            .record_batch(vec![observation(&identity, "v1:locator:test", 1, 51)])
            .await
            .unwrap_or_else(|error| panic!("writing v1 state: {error}"));
        assert!(obsolete.exists());
        assert!(base.join(STATE_FILE).exists());
        fs::remove_dir_all(&base).unwrap_or_else(|error| panic!("cleanup: {error}"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_store_is_private_durable_and_rejects_symlink() {
        let base = std::env::temp_dir().join(format!("p2p-v1-sequence-{}", Uuid::new_v4()));
        let identity = Keypair::random().public_key().z32();
        let store =
            FileSequenceStore::new(&base).unwrap_or_else(|error| panic!("creating store: {error}"));
        store
            .record_batch(vec![observation(&identity, "v1:locator:key", 9, 61)])
            .await
            .unwrap_or_else(|error| panic!("writing state: {error}"));
        let metadata = fs::metadata(base.join(STATE_FILE))
            .unwrap_or_else(|error| panic!("state metadata: {error}"));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let reopened = FileSequenceStore::new(&base)
            .unwrap_or_else(|error| panic!("reopening store: {error}"));
        assert!(
            reopened
                .record_batch(vec![observation(&identity, "v1:locator:key", 8, 61)])
                .await
                .is_err()
        );
        fs::remove_dir_all(&base).unwrap_or_else(|error| panic!("cleanup: {error}"));

        let target = std::env::temp_dir().join(format!("p2p-v1-target-{}", Uuid::new_v4()));
        let link = std::env::temp_dir().join(format!("p2p-v1-link-{}", Uuid::new_v4()));
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
        let base = std::env::temp_dir().join(format!("p2p-v1-publisher-{}", Uuid::new_v4()));
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
