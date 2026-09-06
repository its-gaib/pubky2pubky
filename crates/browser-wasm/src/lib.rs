//! Browser-only Pubky delegated authentication and protected v1 device state.

#![cfg(target_arch = "wasm32")]
#![allow(
    clippy::missing_errors_doc,
    reason = "the stable JavaScript error-code contract is documented in the generated TypeScript surface"
)]

mod browser_store;
mod error;

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap, HashSet},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use browser_store::{IdentityToStore, StoredIdentity};
use futures_util::future::{AbortHandle, Abortable};
use pubky::{
    AuthFlowKind, Capabilities, ClientId, DelegatedGrantCredentialState, Pubky, PubkyGrantAuthFlow,
    PubkyHttpClient, PubkySession, PublicKey,
};
use pubky_common::auth::grant_session_responses::GrantSessionInfo;
use pubky2pubky_client::{
    ConnectionPath, IncomingV1, IrohRelayConfig, Peer, PubkyV1Resolver, PublicContactDisclosure,
    V1Client, V1ClientConfig, V1DeviceResolver, V1DiscoveryConfig, delete_v1_device_record,
    publish_v1_device_record,
};
use pubky2pubky_protocol::{
    V1_IROH_ALPN_TEXT, V1DeviceCredential, V1GrantAuthorization, now_seconds,
};
use serde::{Deserialize, Serialize};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use zeroize::Zeroizing;

use crate::error::{BrowserResult, failure, opaque_failure};

const REQUIRED_CAPABILITY: &str = "/pub/pubky2pubky/:rw";
const DEVICE_LIFETIME_SECONDS: u64 = 6 * 60 * 60;
const MAX_AUTH_RELAY_BYTES: usize = 2_048;
const MAX_AUTHORIZATION_URL_BYTES: usize = 8 * 1_024;
const MAX_TESTNET_HOST_BYTES: usize = 253;
const MAX_IROH_RELAYS: usize = 4;
const MAX_CONNECTED_PEERS: usize = 16;
const MAX_PENDING_INBOUND: usize = 16;
const MAX_PENDING_PER_IDENTITY: usize = 2;
const MAX_CHAT_BYTES: usize = 4 * 1024;
const APPLICATION: &str = "pubky2pubky/chat/1";
const LOCATOR_LIFETIME: Duration = Duration::from_mins(15);
const LOCATOR_RENEW_AFTER: Duration = Duration::from_mins(5);
const PATH_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);
const PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const PENDING_INBOUND_TTL: Duration = Duration::from_secs(10);

struct PendingAuth {
    flow: PubkyGrantAuthFlow,
    pubky: Pubky,
    key_id: String,
    client_id: String,
    expected_identity: Option<String>,
    epoch: u64,
}

#[derive(Default)]
struct BrowserState {
    pending_auth: Option<PendingAuth>,
    auth_busy: bool,
    auth_epoch: u64,
    auth_abort: Option<AbortHandle>,
    identity_busy: bool,
    pubky: Option<Pubky>,
    session: Option<PubkySession>,
    key_id: Option<String>,
    identity: Option<String>,
    client_id: Option<String>,
    device: Option<V1DeviceCredential>,
    sequence_store: Option<Arc<browser_store::BrowserSequenceStore>>,
    client: Option<V1Client>,
    current_record: Option<pubky2pubky_protocol::V1DeviceRecord>,
    peers: HashMap<String, Rc<Peer>>,
    pending_inbound: HashMap<String, IncomingV1>,
    dialing: HashSet<String>,
    going_online: bool,
    epoch: u64,
    next_request_id: u64,
    renewal_abort: Option<AbortHandle>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthRequest {
    authorization_url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityResult {
    identity: String,
    homeserver: String,
    grant_id: String,
    grant_expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceResult {
    identity: String,
    device_id: String,
    control_signing_key: String,
    iroh_endpoint_id: String,
    alpn: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OnlineResult {
    identity: String,
    device_id: String,
    alpn: &'static str,
    path: &'static str,
    e2e: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerResult {
    peer_id: String,
    peer_device_id: String,
    path: &'static str,
    e2e: bool,
    alpn: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendReceipt {
    peer_id: String,
    accepted_at: f64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreState {
    version: u8,
    grant_jws: String,
    homeserver: String,
    key_id: String,
    client_pk: String,
}

/// Browser-owned authentication, device-state, and v1 relay-only network core.
#[wasm_bindgen]
pub struct BrowserCore {
    state: Rc<RefCell<BrowserState>>,
    on_event: Rc<js_sys::Function>,
}

#[wasm_bindgen]
impl BrowserCore {
    /// Construct a browser core. No persistent or network work occurs here.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(on_event: js_sys::Function) -> Self {
        Self {
            state: Rc::new(RefCell::new(BrowserState::default())),
            on_event: Rc::new(on_event),
        }
    }

    /// Synchronous feature check for secure-context `WebCrypto` and `IndexedDB`.
    #[wasm_bindgen(js_name = isStorageAvailable)]
    #[must_use]
    pub fn is_storage_available() -> bool {
        browser_store::is_available()
    }

    /// Begin a Ring sign-in flow using one nonextractable browser-held Ed25519 key.
    #[wasm_bindgen(js_name = beginAuth)]
    pub async fn begin_auth(
        &self,
        client_id: String,
        http_relay: String,
        expected_identity: Option<String>,
        testnet_host: Option<String>,
    ) -> BrowserResult<JsValue> {
        if !browser_store::is_available() {
            return Err(failure("browser-unsupported"));
        }
        validate_client_id(&client_id)?;
        let relay = validate_auth_relay(&http_relay, testnet_host.is_some())?;
        let expected_identity = expected_identity
            .map(|identity| canonical_identity(&identity))
            .transpose()?;
        let client = build_http_client(testnet_host.as_deref())?;
        let pubky = Pubky::with_client(client.clone());
        let capabilities: Capabilities = REQUIRED_CAPABILITY.parse().map_err(opaque_failure)?;
        let client_id_value = ClientId::new(&client_id).map_err(opaque_failure)?;
        let auth_epoch = {
            let mut state = self.state.borrow_mut();
            if state.auth_busy
                || state.identity_busy
                || state.pending_auth.is_some()
                || state.session.is_some()
            {
                return Err(failure("invalid-state"));
            }
            state.auth_busy = true;
            state.auth_epoch = state.auth_epoch.wrapping_add(1);
            state.auth_epoch
        };
        let setup = async {
            let (key_id, public_key) = browser_store::ensure_grant_key(None).await?;
            let signer = browser_store::grant_signer(key_id.clone());
            let flow = match PubkyGrantAuthFlow::builder(
                &capabilities,
                AuthFlowKind::signin(),
                client_id_value,
            )
            .client(client)
            .relay(relay)
            .delegated_client_signer(key_id.clone(), public_key, signer)
            .start()
            {
                Ok(flow) => flow,
                Err(error) => {
                    let _ = browser_store::delete_grant_key(&key_id).await;
                    return Err(opaque_failure(error));
                }
            };
            BrowserResult::Ok((flow, key_id))
        }
        .await;
        let (flow, key_id) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                self.state.borrow_mut().auth_busy = false;
                return Err(error);
            }
        };
        let authorization_url = flow.authorization_url();
        if authorization_url.scheme() != "pubkyauth"
            || authorization_url.as_str().is_empty()
            || authorization_url.as_str().len() > MAX_AUTHORIZATION_URL_BYTES
        {
            self.state.borrow_mut().auth_busy = false;
            let _ = browser_store::delete_grant_key(&key_id).await;
            return Err(failure("identity-verification-failed"));
        }
        let authorization_url = authorization_url.to_string();
        let stale = {
            let mut state = self.state.borrow_mut();
            state.auth_busy = false;
            if state.auth_epoch == auth_epoch {
                state.pending_auth = Some(PendingAuth {
                    flow,
                    pubky,
                    key_id: key_id.clone(),
                    client_id,
                    expected_identity,
                    epoch: auth_epoch,
                });
                false
            } else {
                true
            }
        };
        if stale {
            let _ = browser_store::delete_grant_key(&key_id).await;
            return Err(failure("session-closed"));
        }
        to_js(&AuthRequest { authorization_url })
    }

    /// Wait for approval, validate the exact identity/grant, and persist encrypted restore data.
    #[allow(
        clippy::too_many_lines,
        reason = "approval, validation, persistence, and cancellation are one atomic auth transition"
    )]
    #[wasm_bindgen(js_name = completeAuth)]
    pub async fn complete_auth(&self) -> BrowserResult<JsValue> {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let pending = {
            let mut state = self.state.borrow_mut();
            if state.auth_busy {
                return Err(failure("invalid-state"));
            }
            let pending = state
                .pending_auth
                .take()
                .ok_or_else(|| failure("invalid-state"))?;
            if pending.epoch != state.auth_epoch {
                return Err(failure("session-closed"));
            }
            state.auth_busy = true;
            state.auth_abort = Some(abort_handle);
            pending
        };
        let key_id = pending.key_id.clone();
        let outcome = async {
            let session = Abortable::new(pending.flow.await_approval(), abort_registration)
                .await
                .map_err(|_| failure("session-closed"))?
                .map_err(opaque_failure)?;
            if !auth_epoch_is(&self.state, pending.epoch) {
                return Err(failure("session-closed"));
            }
            let identity = session.public_key().z32();
            if pending
                .expected_identity
                .as_ref()
                .is_some_and(|expected| expected != &identity)
            {
                return Err(failure("identity-mismatch"));
            }
            let (info, restore) = validate_grant_session(&session, &pending.client_id).await?;
            if restore.key_id != key_id
                || browser_store::load_grant_public_key(&key_id).await? != restore.client_pk
            {
                return Err(failure("identity-verification-failed"));
            }
            let restore_state = RestoreState {
                version: 1,
                grant_jws: restore.grant_jws.clone(),
                homeserver: restore.homeserver_pk.z32(),
                key_id: restore.key_id.clone(),
                client_pk: restore.client_pk.z32(),
            };
            V1GrantAuthorization::from_jws(&restore.grant_jws, &identity, now_seconds())
                .map_err(|_| failure("identity-verification-failed"))?;
            if !auth_epoch_is(&self.state, pending.epoch) {
                return Err(failure("session-closed"));
            }
            let encoded = Zeroizing::new(
                serde_json::to_string(&restore_state).map_err(|_| failure("internal-error"))?,
            );
            let homeserver = info.homeserver.z32();
            let grant_id = info.grant_id.as_str().to_owned();
            browser_store::save_identity(&IdentityToStore {
                identity: &identity,
                key_id: &key_id,
                client_id: &pending.client_id,
                homeserver: &homeserver,
                grant_id: &grant_id,
                grant_expires_at: info.grant_expires_at,
                restore: &encoded,
            })
            .await?;
            if !auth_epoch_is(&self.state, pending.epoch) {
                let _ = browser_store::remove_identity(&identity).await;
                return Err(failure("session-closed"));
            }
            BrowserResult::Ok((
                IdentityResult {
                    identity: identity.clone(),
                    homeserver,
                    grant_id,
                    grant_expires_at: info.grant_expires_at,
                },
                session,
                identity,
            ))
        }
        .await;
        let (result, session, identity) = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                {
                    let mut state = self.state.borrow_mut();
                    state.auth_busy = false;
                    state.auth_abort = None;
                }
                let _ = browser_store::delete_grant_key(&key_id).await;
                return Err(error);
            }
        };
        let mut state = self.state.borrow_mut();
        state.auth_busy = false;
        state.auth_abort = None;
        state.pubky = Some(pending.pubky);
        state.session = Some(session);
        state.key_id = Some(key_id);
        state.identity = Some(identity.clone());
        state.client_id = Some(pending.client_id);
        state.sequence_store = Some(Arc::new(browser_store::BrowserSequenceStore::new(identity)));
        to_js(&result)
    }

    /// Return public summaries only; encrypted restore material never leaves this core.
    #[wasm_bindgen(js_name = listLocalIdentities)]
    pub async fn list_local_identities(&self) -> BrowserResult<JsValue> {
        browser_store::list_identities().await
    }

    /// Cancel an in-memory Ring approval/restore operation and discard any unpublished key.
    #[wasm_bindgen(js_name = cancelAuth)]
    pub async fn cancel_auth(&self) {
        let (abort, pending_key) = {
            let mut state = self.state.borrow_mut();
            state.auth_epoch = state.auth_epoch.wrapping_add(1);
            let pending_key = state.pending_auth.take().map(|pending| pending.key_id);
            if pending_key.is_some() {
                state.auth_busy = false;
            }
            (state.auth_abort.take(), pending_key)
        };
        if let Some(abort) = abort {
            abort.abort();
        }
        if let Some(key_id) = pending_key {
            let _ = browser_store::delete_grant_key(&key_id).await;
        }
    }

    /// Restore a delegated session only when `IndexedDB` still has the exact nonextractable key.
    #[wasm_bindgen(js_name = restoreIdentity)]
    pub async fn restore_identity(
        &self,
        identity: String,
        client_id: String,
        testnet_host: Option<String>,
    ) -> BrowserResult<JsValue> {
        let identity = canonical_identity(&identity)?;
        validate_client_id(&client_id)?;
        let client = build_http_client(testnet_host.as_deref())?;
        let pubky = Pubky::with_client(client);
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let auth_epoch = {
            let mut state = self.state.borrow_mut();
            if state.auth_busy
                || state.identity_busy
                || state.pending_auth.is_some()
                || state.session.is_some()
            {
                return Err(failure("invalid-state"));
            }
            state.auth_busy = true;
            state.auth_epoch = state.auth_epoch.wrapping_add(1);
            state.auth_abort = Some(abort_handle);
            state.auth_epoch
        };
        let outcome = async {
            let stored = browser_store::load_identity(&identity).await?;
            validate_stored_summary(&stored, &identity, &client_id)?;
            let restore: RestoreState =
                serde_json::from_str(&stored.restore).map_err(|_| failure("storage-tampered"))?;
            if restore.version != 1
                || restore.key_id != stored.key_id
                || restore.homeserver != stored.homeserver
            {
                return Err(failure("storage-tampered"));
            }
            let homeserver = canonical_public_key(&restore.homeserver)?;
            let client_pk = canonical_public_key(&restore.client_pk)?;
            let stored_public_key = browser_store::load_grant_public_key(&restore.key_id).await?;
            if stored_public_key != client_pk {
                return Err(failure("storage-tampered"));
            }
            V1GrantAuthorization::from_jws(&restore.grant_jws, &identity, now_seconds())
                .map_err(|_| failure("identity-verification-failed"))?;
            let delegated = DelegatedGrantCredentialState {
                grant_jws: restore.grant_jws,
                homeserver_pk: homeserver,
                key_id: restore.key_id.clone(),
                client_pk,
            };
            let session = pubky
                .restore_delegated_grant_session(
                    delegated,
                    browser_store::grant_signer(restore.key_id.clone()),
                )
                .await
                .map_err(opaque_failure)?;
            let (info, _) = validate_grant_session(&session, &client_id).await?;
            if info.pubky.z32() != identity
                || info.homeserver.z32() != stored.homeserver
                || info.grant_id.as_str() != stored.grant_id
                || info.grant_expires_at != stored.grant_expires_at
            {
                return Err(failure("identity-verification-failed"));
            }
            if !auth_epoch_is(&self.state, auth_epoch) {
                return Err(failure("session-closed"));
            }
            BrowserResult::Ok((
                IdentityResult {
                    identity: identity.clone(),
                    homeserver: stored.homeserver,
                    grant_id: stored.grant_id,
                    grant_expires_at: stored.grant_expires_at,
                },
                session,
                restore.key_id,
            ))
        };
        let (result, session, key_id) = match Abortable::new(outcome, abort_registration).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => {
                let mut state = self.state.borrow_mut();
                state.auth_busy = false;
                state.auth_abort = None;
                return Err(error);
            }
            Err(_) => {
                let mut state = self.state.borrow_mut();
                state.auth_busy = false;
                state.auth_abort = None;
                return Err(failure("session-closed"));
            }
        };
        let mut state = self.state.borrow_mut();
        state.auth_busy = false;
        state.auth_abort = None;
        state.pubky = Some(pubky);
        state.session = Some(session);
        state.key_id = Some(key_id);
        state.identity = Some(identity.clone());
        state.client_id = Some(client_id);
        state.sequence_store = Some(Arc::new(browser_store::BrowserSequenceStore::new(identity)));
        to_js(&result)
    }

    /// Remove all package-owned local material for one offline identity.
    #[wasm_bindgen(js_name = removeLocalIdentity)]
    pub async fn remove_local_identity(&self, identity: String) -> BrowserResult<JsValue> {
        let identity = canonical_identity(&identity)?;
        {
            let mut state = self.state.borrow_mut();
            if state.auth_busy || state.identity_busy || state.pending_auth.is_some() {
                return Err(failure("invalid-state"));
            }
            if state.identity.as_ref() == Some(&identity)
                && (state.client.is_some() || !state.peers.is_empty() || state.going_online)
            {
                return Err(failure("identity-active"));
            }
            state.identity_busy = true;
        }
        let removed = browser_store::remove_identity(&identity).await;
        let mut state = self.state.borrow_mut();
        state.identity_busy = false;
        let removed = removed?;
        if state.identity.as_ref() == Some(&identity) {
            state.pubky = None;
            state.session = None;
            state.key_id = None;
            state.identity = None;
            state.client_id = None;
            state.device = None;
            state.sequence_store = None;
        }
        Ok(removed)
    }

    /// Prepare or restore the protected v1 device credential. This does not claim network success.
    #[wasm_bindgen(js_name = prepareDevice)]
    pub async fn prepare_device(&self, device_id: String) -> BrowserResult<JsValue> {
        let (session, key_id, identity, had_cached_device, network_active) = {
            let state = self.state.borrow();
            if state.identity_busy {
                return Err(failure("invalid-state"));
            }
            (
                state
                    .session
                    .clone()
                    .ok_or_else(|| failure("authentication-required"))?,
                state
                    .key_id
                    .clone()
                    .ok_or_else(|| failure("authentication-required"))?,
                state
                    .identity
                    .clone()
                    .ok_or_else(|| failure("authentication-required"))?,
                state.device.is_some(),
                state.client.is_some() || state.going_online,
            )
        };
        let now = now_seconds();
        let old_control_key = if let Some(encoded) =
            browser_store::load_device_state(&identity).await?
        {
            let encoded = Zeroizing::new(encoded);
            let device: V1DeviceCredential =
                serde_json::from_str(&encoded).map_err(|_| failure("storage-tampered"))?;
            if device.identity() != identity {
                return Err(failure("storage-tampered"));
            }
            let publisher_present = browser_store::has_publisher_sequence(
                &identity,
                &identity,
                device.control_signing_key(),
            )
            .await?;
            let currently_valid = device.verify(now).is_ok();
            let remaining = device.certificate.claims.expires_at.saturating_sub(now);
            let enough_for_fresh_locator =
                remaining > LOCATOR_LIFETIME.as_secs() + PEER_HANDSHAKE_TIMEOUT.as_secs();
            if currently_valid
                && publisher_present
                && enough_for_fresh_locator
                && device.device_id() == device_id
            {
                let result = device_result(&device)?;
                self.state.borrow_mut().device = Some(device);
                return Ok(result);
            }
            let claims = &device.certificate.claims;
            let historical_now = claims.expires_at.saturating_sub(1).max(claims.issued_at);
            let safely_expired = claims.expires_at <= now && device.verify(historical_now).is_ok();
            if !currently_valid && !safely_expired {
                return Err(failure("device-state-invalid"));
            }
            if network_active {
                return Err(failure("identity-active"));
            }
            Some(device.control_signing_key().to_owned())
        } else {
            if had_cached_device {
                return Err(failure("storage-key-missing"));
            }
            None
        };
        let device = issue_device(&session, &key_id, &identity, device_id, now).await?;
        let encoded =
            Zeroizing::new(serde_json::to_string(&device).map_err(|_| failure("internal-error"))?);
        if let Some(old_control_key) = old_control_key {
            browser_store::replace_device_state(
                &identity,
                &old_control_key,
                device.control_signing_key(),
                &encoded,
            )
            .await?;
        } else {
            browser_store::save_new_device_state(&identity, device.control_signing_key(), &encoded)
                .await?;
        }
        let result = device_result(&device)?;
        self.state.borrow_mut().device = Some(device);
        Ok(result)
    }

    /// Bind the relay-only endpoint, allocate/publish a locator, and start inbound processing.
    #[allow(
        clippy::too_many_lines,
        reason = "endpoint binding and first publication are one fail-closed state transition"
    )]
    #[wasm_bindgen(js_name = publishAndGoOnline)]
    pub async fn publish_and_go_online(
        &self,
        device_id: String,
        relay_urls: JsValue,
        allow_loopback_testnet: bool,
    ) -> BrowserResult<JsValue> {
        let relay_strings: Vec<String> = serde_wasm_bindgen::from_value(relay_urls)
            .map_err(|_| failure("relay-config-invalid"))?;
        let relays = validate_iroh_relays(&relay_strings, allow_loopback_testnet)?;
        let _ = self.prepare_device(device_id).await?;
        let (device, pubky, session, sequences, epoch) = {
            let mut state = self.state.borrow_mut();
            if state.identity_busy || state.going_online || state.client.is_some() {
                return Err(failure("invalid-state"));
            }
            let device = state
                .device
                .clone()
                .ok_or_else(|| failure("device-state-invalid"))?;
            let pubky = state
                .pubky
                .clone()
                .ok_or_else(|| failure("authentication-required"))?;
            let session = state
                .session
                .clone()
                .ok_or_else(|| failure("authentication-required"))?;
            let sequences = state
                .sequence_store
                .clone()
                .ok_or_else(|| failure("storage-key-missing"))?;
            state.going_online = true;
            state.epoch = state.epoch.wrapping_add(1);
            (device, pubky, session, sequences, state.epoch)
        };

        let discovery_config = V1DiscoveryConfig {
            allow_insecure_loopback_relay: allow_loopback_testnet,
            ..V1DiscoveryConfig::default()
        };
        let resolver: Arc<dyn V1DeviceResolver> = Arc::new(
            PubkyV1Resolver::new(pubky, session.clone(), sequences.clone())
                .with_config(discovery_config),
        );
        let mut config = V1ClientConfig::relay_only(
            PublicContactDisclosure::AcknowledgePreConsentRelayMetadataExposure,
            vec![APPLICATION.to_owned()],
        );
        config.trusted_relays = relays.into_iter().map(IrohRelayConfig::new).collect();
        config.allow_insecure_loopback_relay = allow_loopback_testnet;
        config.peer_handshake_timeout = PEER_HANDSHAKE_TIMEOUT;
        config.max_message_bytes = MAX_CHAT_BYTES;

        let setup = async {
            let client = V1Client::bind(device, resolver, config)
                .await
                .map_err(|_| failure("relay-unreachable"))?;
            let locator_lifetime = bounded_locator_lifetime(client.credential())?;
            let Ok(record) = client
                .next_record(sequences.as_ref(), locator_lifetime)
                .await
            else {
                client.close().await;
                return Err(failure("publication-failed"));
            };
            if publish_v1_device_record(&session, &record, allow_loopback_testnet)
                .await
                .is_err()
            {
                client.close().await;
                return Err(failure("publication-failed"));
            }
            BrowserResult::Ok((client, record))
        }
        .await;

        let (client, record) = match setup {
            Ok(value) => value,
            Err(error) => {
                let mut state = self.state.borrow_mut();
                if state.epoch == epoch {
                    state.going_online = false;
                }
                return Err(error);
            }
        };
        let (renewal_abort, renewal_registration) = AbortHandle::new_pair();
        let stale = {
            let mut state = self.state.borrow_mut();
            if state.epoch == epoch {
                state.going_online = false;
                state.current_record = Some(record.clone());
                state.client = Some(client.clone());
                state.renewal_abort = Some(renewal_abort);
                false
            } else {
                true
            }
        };
        if stale {
            let _ = delete_v1_device_record(&session, &record).await;
            client.close().await;
            return Err(failure("session-closed"));
        }
        start_incoming_loop(
            Rc::clone(&self.state),
            Rc::clone(&self.on_event),
            client.clone(),
            epoch,
        );
        start_renewal_loop(
            Rc::clone(&self.state),
            Rc::clone(&self.on_event),
            client.clone(),
            session,
            sequences,
            allow_loopback_testnet,
            epoch,
            renewal_registration,
        );
        to_js(&OnlineResult {
            identity: client.identity().to_owned(),
            device_id: client.device_id().to_owned(),
            alpn: V1_IROH_ALPN_TEXT,
            path: "relay",
            e2e: true,
        })
    }

    /// Resolve and connect to a user-selected Pubky identity. The result is withheld until the
    /// complete mutual currentness exchange succeeds.
    #[wasm_bindgen(js_name = requestPeer)]
    pub async fn request_peer(&self, peer_identity: String) -> BrowserResult<JsValue> {
        let peer_identity = canonical_identity(&peer_identity)?;
        let (client, epoch) = {
            let mut state = self.state.borrow_mut();
            if state.identity.as_ref() == Some(&peer_identity)
                || state.client.is_none()
                || state.peers.len() + state.dialing.len() >= MAX_CONNECTED_PEERS
                || state.peers.contains_key(&peer_identity)
                || !state.dialing.insert(peer_identity.clone())
            {
                return Err(failure("invalid-state"));
            }
            (
                state
                    .client
                    .clone()
                    .ok_or_else(|| failure("invalid-state"))?,
                state.epoch,
            )
        };
        let result = client.dial(&peer_identity, None, APPLICATION).await;
        {
            let mut state = self.state.borrow_mut();
            if state.epoch == epoch {
                state.dialing.remove(&peer_identity);
            }
        }
        let peer = result.map_err(|_| failure("peer-unreachable"))?;
        activate_peer(
            Rc::clone(&self.state),
            Rc::clone(&self.on_event),
            peer,
            epoch,
        )
        .await
    }

    /// Accept one offline-authenticated inbound request and run mutual live-authority proofs.
    #[wasm_bindgen(js_name = acceptInbound)]
    pub async fn accept_inbound(&self, request_id: String) -> BrowserResult<JsValue> {
        let (incoming, epoch) = {
            let mut state = self.state.borrow_mut();
            let incoming = state
                .pending_inbound
                .remove(&request_id)
                .ok_or_else(|| failure("request-expired"))?;
            (incoming, state.epoch)
        };
        let peer = incoming
            .accept()
            .await
            .map_err(|_| failure("identity-verification-failed"))?;
        activate_peer(
            Rc::clone(&self.state),
            Rc::clone(&self.on_event),
            peer,
            epoch,
        )
        .await
    }

    /// Reject one inbound request without making sender-directed Pubky network requests.
    #[wasm_bindgen(js_name = rejectInbound)]
    pub fn reject_inbound(&self, request_id: &str) -> BrowserResult<()> {
        let incoming = self
            .state
            .borrow_mut()
            .pending_inbound
            .remove(request_id)
            .ok_or_else(|| failure("request-expired"))?;
        incoming.reject();
        Ok(())
    }

    /// Send one bounded, valid UTF-8 payload over an already mutually verified QUIC peer.
    #[wasm_bindgen(js_name = sendMessage)]
    pub async fn send_message(
        &self,
        peer_identity: String,
        data: js_sys::Uint8Array,
    ) -> BrowserResult<JsValue> {
        let peer_identity = canonical_identity(&peer_identity)?;
        let bytes = data.to_vec();
        if bytes.is_empty() || bytes.len() > MAX_CHAT_BYTES || std::str::from_utf8(&bytes).is_err()
        {
            return Err(failure("message-invalid"));
        }
        let peer = self
            .state
            .borrow()
            .peers
            .get(&peer_identity)
            .cloned()
            .ok_or_else(|| failure("peer-not-connected"))?;
        peer.send(&bytes)
            .await
            .map_err(|_| failure("session-closed"))?;
        to_js(&SendReceipt {
            peer_id: peer_identity,
            accepted_at: js_sys::Date::now(),
        })
    }

    /// Close the endpoint, all peers, and pending consent requests while retaining local auth and
    /// protected device state for a later reconnect.
    pub async fn disconnect(&self) {
        shutdown_network(Rc::clone(&self.state)).await;
    }
}

impl Drop for BrowserCore {
    fn drop(&mut self) {
        let (pending_key, auth_abort) = {
            let mut state = self.state.borrow_mut();
            state.auth_epoch = state.auth_epoch.wrapping_add(1);
            (
                state.pending_auth.take().map(|pending| pending.key_id),
                state.auth_abort.take(),
            )
        };
        if let Some(auth_abort) = auth_abort {
            auth_abort.abort();
        }
        let state = Rc::clone(&self.state);
        spawn_local(async move {
            shutdown_network(state).await;
            if let Some(key_id) = pending_key {
                let _ = browser_store::delete_grant_key(&key_id).await;
            }
        });
    }
}

fn auth_epoch_is(state: &Rc<RefCell<BrowserState>>, expected: u64) -> bool {
    state.borrow().auth_epoch == expected
}

fn start_incoming_loop(
    state: Rc<RefCell<BrowserState>>,
    on_event: Rc<js_sys::Function>,
    client: V1Client,
    epoch: u64,
) {
    spawn_local(async move {
        loop {
            let Ok(incoming) = client.next_incoming().await else {
                break;
            };
            let peer_id = incoming.identity().to_owned();
            let peer_device_id = incoming.device_id().to_owned();
            let application = incoming.application().to_owned();
            let request_id = {
                let mut current = state.borrow_mut();
                let pending_for_identity = current
                    .pending_inbound
                    .values()
                    .filter(|pending| pending.identity() == peer_id)
                    .count();
                if current.epoch != epoch || current.client.is_none() {
                    drop(current);
                    incoming.reject();
                    break;
                }
                if current.pending_inbound.len() >= MAX_PENDING_INBOUND
                    || pending_for_identity >= MAX_PENDING_PER_IDENTITY
                {
                    drop(current);
                    incoming.reject();
                    continue;
                }
                current.next_request_id = current.next_request_id.wrapping_add(1);
                if current.next_request_id == 0 {
                    current.next_request_id = 1;
                }
                let request_id = format!("request-{}", current.next_request_id);
                current.pending_inbound.insert(request_id.clone(), incoming);
                request_id
            };
            start_inbound_expiry(
                Rc::clone(&state),
                Rc::clone(&on_event),
                request_id.clone(),
                epoch,
            );
            emit_json(
                &on_event,
                &serde_json::json!({
                    "type": "inbound-request",
                    "id": request_id,
                    "peerId": peer_id,
                    "peerDeviceId": peer_device_id,
                    "application": application,
                    "receivedAt": js_sys::Date::now(),
                }),
            );
        }
    });
}

fn start_inbound_expiry(
    state: Rc<RefCell<BrowserState>>,
    on_event: Rc<js_sys::Function>,
    request_id: String,
    epoch: u64,
) {
    spawn_local(async move {
        n0_future::time::sleep(PENDING_INBOUND_TTL).await;
        let incoming = {
            let mut current = state.borrow_mut();
            if current.epoch == epoch {
                current.pending_inbound.remove(&request_id)
            } else {
                None
            }
        };
        if let Some(incoming) = incoming {
            incoming.reject();
            emit_json(
                &on_event,
                &serde_json::json!({
                    "type": "inbound-request-expired",
                    "id": request_id,
                }),
            );
        }
    });
}

#[allow(
    clippy::too_many_arguments,
    reason = "renewal owns the exact endpoint, authenticated publisher, store, and epoch"
)]
fn start_renewal_loop(
    state: Rc<RefCell<BrowserState>>,
    on_event: Rc<js_sys::Function>,
    client: V1Client,
    session: PubkySession,
    sequences: Arc<browser_store::BrowserSequenceStore>,
    allow_loopback_testnet: bool,
    epoch: u64,
    registration: futures_util::future::AbortRegistration,
) {
    let renewal = async move {
        loop {
            n0_future::time::sleep(LOCATOR_RENEW_AFTER).await;
            if state.borrow().epoch != epoch || state.borrow().client.is_none() {
                break;
            }
            let Ok(locator_lifetime) = bounded_locator_lifetime(client.credential()) else {
                fail_online_endpoint(&state, &on_event, &client, &session, epoch).await;
                break;
            };
            let Ok(record) = client
                .next_record(sequences.as_ref(), locator_lifetime)
                .await
            else {
                fail_online_endpoint(&state, &on_event, &client, &session, epoch).await;
                break;
            };
            if publish_v1_device_record(&session, &record, allow_loopback_testnet)
                .await
                .is_err()
            {
                fail_online_endpoint(&state, &on_event, &client, &session, epoch).await;
                break;
            }
            let active = {
                let mut current = state.borrow_mut();
                if current.epoch == epoch && current.client.is_some() {
                    current.current_record = Some(record.clone());
                    true
                } else {
                    false
                }
            };
            if !active {
                let _ = delete_v1_device_record(&session, &record).await;
                break;
            }
        }
    };
    spawn_local(async move {
        let _ = Abortable::new(renewal, registration).await;
    });
}

async fn fail_online_endpoint(
    state: &Rc<RefCell<BrowserState>>,
    on_event: &js_sys::Function,
    client: &V1Client,
    session: &PubkySession,
    epoch: u64,
) {
    let (record, peers, pending) = {
        let mut current = state.borrow_mut();
        if current.epoch != epoch {
            return;
        }
        current.epoch = current.epoch.wrapping_add(1);
        current.going_online = false;
        current.client = None;
        current.dialing.clear();
        current.renewal_abort = None;
        (
            current.current_record.take(),
            current.peers.drain().collect::<Vec<_>>(),
            current
                .pending_inbound
                .drain()
                .map(|(_, incoming)| incoming)
                .collect::<Vec<_>>(),
        )
    };
    for incoming in pending {
        incoming.reject();
    }
    for (_, peer) in &peers {
        let _ = peer.close().await;
    }
    client.close().await;
    if let Some(record) = record {
        let _ = delete_v1_device_record(session, &record).await;
    }
    for (peer_id, _) in peers {
        emit_json(
            on_event,
            &serde_json::json!({ "type": "peer-disconnected", "peerId": peer_id }),
        );
    }
    emit_json(
        on_event,
        &serde_json::json!({ "type": "error", "code": "publication-failed" }),
    );
    emit_json(
        on_event,
        &serde_json::json!({ "type": "online-state", "online": false }),
    );
}

async fn activate_peer(
    state: Rc<RefCell<BrowserState>>,
    on_event: Rc<js_sys::Function>,
    peer: Peer,
    epoch: u64,
) -> BrowserResult<JsValue> {
    if peer
        .wait_for_path(ConnectionPath::Relayed, PATH_CONFIRM_TIMEOUT)
        .await
        != ConnectionPath::Relayed
    {
        let _ = peer.close().await;
        return Err(failure("relay-path-unverified"));
    }
    let peer_id = canonical_identity(peer.peer_identity())?;
    let peer_device_id = peer.peer_device_id().to_owned();
    let peer = Rc::new(peer);
    let activation_error = {
        let mut current = state.borrow_mut();
        if current.epoch != epoch || current.client.is_none() {
            Some("session-closed")
        } else if current.peers.len() >= MAX_CONNECTED_PEERS || current.peers.contains_key(&peer_id)
        {
            Some("peer-already-connected")
        } else {
            current.peers.insert(peer_id.clone(), Rc::clone(&peer));
            None
        }
    };
    if let Some(code) = activation_error {
        let _ = peer.close().await;
        return Err(failure(code));
    }
    emit_json(
        &on_event,
        &serde_json::json!({
            "type": "peer-verified",
            "peerId": peer_id,
            "peerDeviceId": peer_device_id,
            "path": "relay",
            "route": "relay",
            "e2e": true,
            "irohQuicEncrypted": true,
            "pubkyIdentityVerified": true,
            "protocolVersion": 1,
            "alpn": V1_IROH_ALPN_TEXT,
        }),
    );
    start_receive_loop(
        Rc::clone(&state),
        Rc::clone(&on_event),
        Rc::clone(&peer),
        peer_id.clone(),
        epoch,
    );
    to_js(&PeerResult {
        peer_id,
        peer_device_id,
        path: "relay",
        e2e: true,
        alpn: V1_IROH_ALPN_TEXT,
    })
}

fn start_receive_loop(
    state: Rc<RefCell<BrowserState>>,
    on_event: Rc<js_sys::Function>,
    peer: Rc<Peer>,
    peer_id: String,
    epoch: u64,
) {
    let session_id = peer.session_id();
    spawn_local(async move {
        loop {
            let bytes = match peer.recv().await {
                Ok(bytes)
                    if !bytes.is_empty()
                        && bytes.len() <= MAX_CHAT_BYTES
                        && std::str::from_utf8(&bytes).is_ok() =>
                {
                    bytes
                }
                Ok(_) => {
                    emit_json(
                        &on_event,
                        &serde_json::json!({ "type": "error", "code": "message-invalid" }),
                    );
                    break;
                }
                Err(_) => break,
            };
            emit_message(&on_event, &peer_id, &bytes);
        }
        let _ = peer.close().await;
        let removed = {
            let mut current = state.borrow_mut();
            if current.epoch != epoch {
                false
            } else if current
                .peers
                .get(&peer_id)
                .is_some_and(|active| active.session_id() == session_id)
            {
                current.peers.remove(&peer_id);
                true
            } else {
                false
            }
        };
        if removed {
            emit_json(
                &on_event,
                &serde_json::json!({ "type": "peer-disconnected", "peerId": peer_id }),
            );
        }
    });
}

async fn shutdown_network(state: Rc<RefCell<BrowserState>>) {
    let (client, peers, record, session, renewal) = {
        let mut current = state.borrow_mut();
        current.epoch = current.epoch.wrapping_add(1);
        current.going_online = false;
        current.dialing.clear();
        current.pending_inbound.clear();
        (
            current.client.take(),
            current
                .peers
                .drain()
                .map(|(_, peer)| peer)
                .collect::<Vec<_>>(),
            current.current_record.take(),
            current.session.clone(),
            current.renewal_abort.take(),
        )
    };
    if let Some(renewal) = renewal {
        renewal.abort();
    }
    for peer in peers {
        let _ = peer.close().await;
    }
    if let Some(client) = client {
        client.close().await;
    }
    if let (Some(record), Some(session)) = (record, session) {
        let _ = delete_v1_device_record(&session, &record).await;
    }
}

fn emit_json(on_event: &js_sys::Function, event: &serde_json::Value) {
    if let Ok(value) = serde_wasm_bindgen::to_value(event) {
        let _ = on_event.call1(&JsValue::UNDEFINED, &value);
    }
}

fn emit_message(on_event: &js_sys::Function, peer_id: &str, bytes: &[u8]) {
    let event = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&event, &"type".into(), &"message".into());
    let _ = js_sys::Reflect::set(&event, &"peerId".into(), &peer_id.into());
    let _ = js_sys::Reflect::set(&event, &"body".into(), &js_sys::Uint8Array::from(bytes));
    let _ = js_sys::Reflect::set(
        &event,
        &"receivedAt".into(),
        &JsValue::from_f64(js_sys::Date::now()),
    );
    let _ = on_event.call1(&JsValue::UNDEFINED, &event);
}

async fn issue_device(
    session: &PubkySession,
    key_id: &str,
    identity: &str,
    device_id: String,
    now: u64,
) -> BrowserResult<V1DeviceCredential> {
    let grant = session
        .as_grant()
        .ok_or_else(|| failure("identity-verification-failed"))?;
    let restore = grant
        .export_delegated_restore_state()
        .await
        .ok_or_else(|| failure("identity-verification-failed"))?;
    if restore.key_id != key_id
        || browser_store::load_grant_public_key(key_id).await? != restore.client_pk
    {
        return Err(failure("identity-verification-failed"));
    }
    let authorization = V1GrantAuthorization::from_jws(&restore.grant_jws, identity, now)
        .map_err(|_| failure("identity-verification-failed"))?;
    let claims = authorization
        .verify(identity, now)
        .map_err(|_| failure("identity-verification-failed"))?;
    let expires_at = now
        .checked_add(DEVICE_LIFETIME_SECONDS)
        .map(|expiry| expiry.min(claims.exp))
        .filter(|expiry| *expiry > now)
        .ok_or_else(|| failure("identity-verification-failed"))?;
    let draft = V1DeviceCredential::prepare(authorization, identity, device_id, now, expires_at)
        .map_err(|_| failure("device-state-invalid"))?;
    let signature = browser_store::sign_certificate(
        key_id,
        &draft
            .certificate_signing_bytes()
            .map_err(|_| failure("device-state-invalid"))?,
    )
    .await?;
    draft
        .finalize(signature)
        .map_err(|_| failure("identity-verification-failed"))
}

async fn validate_grant_session(
    session: &PubkySession,
    expected_client_id: &str,
) -> BrowserResult<(GrantSessionInfo, DelegatedGrantCredentialState)> {
    let capabilities = session.info();
    if capabilities.capabilities().len() != 1
        || capabilities.capabilities()[0].to_string() != REQUIRED_CAPABILITY
    {
        return Err(failure("identity-verification-failed"));
    }
    let grant = session
        .as_grant()
        .ok_or_else(|| failure("identity-verification-failed"))?;
    let info = grant.session_info().await;
    if info.client_id.as_str() != expected_client_id
        || info.capabilities.len() != 1
        || info.capabilities[0].to_string() != REQUIRED_CAPABILITY
        || info.pubky != session.public_key()
    {
        return Err(failure("identity-verification-failed"));
    }
    let restore = grant
        .export_delegated_restore_state()
        .await
        .ok_or_else(|| failure("identity-verification-failed"))?;
    Ok((info, restore))
}

fn validate_stored_summary(
    stored: &StoredIdentity,
    identity: &str,
    client_id: &str,
) -> BrowserResult<()> {
    if stored.identity != identity || stored.client_id != client_id {
        return Err(failure("storage-tampered"));
    }
    canonical_identity(&stored.homeserver)?;
    if stored.key_id.is_empty()
        || stored.key_id.len() > 128
        || stored.grant_id.is_empty()
        || stored.grant_id.len() > 128
    {
        return Err(failure("storage-tampered"));
    }
    if stored.grant_expires_at <= now_seconds() {
        return Err(failure("authentication-required"));
    }
    Ok(())
}

fn build_http_client(testnet_host: Option<&str>) -> BrowserResult<PubkyHttpClient> {
    let mut builder = PubkyHttpClient::builder();
    if let Some(host) = testnet_host {
        validate_testnet_host(host)?;
        builder.testnet_with_host(host);
    }
    builder.build().map_err(opaque_failure)
}

fn validate_client_id(client_id: &str) -> BrowserResult<()> {
    ClientId::new(client_id).map_err(opaque_failure)?;
    if client_id.chars().any(char::is_control) || client_id.chars().all(char::is_whitespace) {
        return Err(failure("client-id-invalid"));
    }
    Ok(())
}

fn validate_auth_relay(value: &str, allow_loopback: bool) -> BrowserResult<Url> {
    if value.is_empty() || value.len() > MAX_AUTH_RELAY_BYTES {
        return Err(failure("auth-relay-invalid"));
    }
    let url = Url::parse(value).map_err(|_| failure("auth-relay-invalid"))?;
    let loopback = is_explicit_loopback_http_origin(&url);
    let valid_scheme =
        url.scheme() == "https" || (allow_loopback && loopback && url.scheme() == "http");
    if !valid_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "/inbox" | "/inbox/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(failure("auth-relay-invalid"));
    }
    Ok(url)
}

fn validate_iroh_relays(values: &[String], allow_loopback: bool) -> BrowserResult<Vec<Url>> {
    if values.is_empty() || values.len() > MAX_IROH_RELAYS {
        return Err(failure("relay-config-invalid"));
    }
    let mut unique = BTreeSet::new();
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        if value.len() > MAX_AUTH_RELAY_BYTES {
            return Err(failure("relay-config-invalid"));
        }
        let url = Url::parse(value).map_err(|_| failure("relay-config-invalid"))?;
        let loopback = is_explicit_loopback_http_origin(&url);
        let valid_scheme =
            url.scheme() == "https" || (allow_loopback && loopback && url.scheme() == "http");
        if !valid_scheme
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !unique.insert(url.as_str().to_owned())
        {
            return Err(failure("relay-config-invalid"));
        }
        parsed.push(url);
    }
    Ok(parsed)
}

fn validate_testnet_host(host: &str) -> BrowserResult<()> {
    if host.is_empty()
        || host.len() > MAX_TESTNET_HOST_BYTES
        || host.contains(['/', '\\', '@', ':'])
        || host.chars().any(char::is_control)
    {
        return Err(failure("testnet-config-invalid"));
    }
    Ok(())
}

fn is_explicit_loopback_http_origin(url: &Url) -> bool {
    url.port().is_some() && matches!(url.host_str(), Some("127.0.0.1" | "::1"))
}

fn canonical_identity(value: &str) -> BrowserResult<String> {
    canonical_public_key(value).map(|key| key.z32())
}

fn canonical_public_key(value: &str) -> BrowserResult<PublicKey> {
    let key = PublicKey::try_from_z32(value).map_err(|_| failure("invalid-pubky"))?;
    if key.z32() != value {
        return Err(failure("invalid-pubky"));
    }
    Ok(key)
}

fn device_result(device: &V1DeviceCredential) -> BrowserResult<JsValue> {
    to_js(&DeviceResult {
        identity: device.identity().to_owned(),
        device_id: device.device_id().to_owned(),
        control_signing_key: device.control_signing_key().to_owned(),
        iroh_endpoint_id: device.iroh_endpoint_id().to_owned(),
        alpn: V1_IROH_ALPN_TEXT,
    })
}

fn bounded_locator_lifetime(device: &V1DeviceCredential) -> BrowserResult<Duration> {
    let remaining = device
        .certificate
        .claims
        .expires_at
        .saturating_sub(now_seconds())
        .saturating_sub(1);
    if remaining == 0 {
        return Err(failure("device-state-invalid"));
    }
    Ok(Duration::from_secs(
        remaining.min(LOCATOR_LIFETIME.as_secs()),
    ))
}

fn to_js(value: &impl Serialize) -> BrowserResult<JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|_| failure("internal-error"))
}
