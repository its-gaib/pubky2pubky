use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use js_sys::{Promise, Reflect, Uint8Array};
use pubky::{DelegatedSignFn, PublicKey, delegated_sign_callback};
use pubky2pubky_client::{
    AuthenticatedSequenceObservation, ClientError, PublisherSequenceStore, SequenceStore,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::error::{BrowserResult, failure, storage_failure};

#[wasm_bindgen(module = "/js/browser_store.js")]
extern "C" {
    #[wasm_bindgen(js_name = __p2pBrowserStorageAvailable)]
    fn js_storage_available() -> bool;
    #[wasm_bindgen(js_name = __p2pEnsureGrantKey)]
    fn js_ensure_grant_key(key_id: Option<String>) -> Promise;
    #[wasm_bindgen(js_name = __p2pLoadGrantPublicKey)]
    fn js_load_grant_public_key(key_id: String) -> Promise;
    #[wasm_bindgen(js_name = __p2pSignGrantInput)]
    fn js_sign_grant_input(key_id: String, input: String) -> Promise;
    #[wasm_bindgen(js_name = __p2pSignBytes)]
    fn js_sign_bytes(key_id: String, input: Uint8Array) -> Promise;
    #[wasm_bindgen(js_name = __p2pDeleteGrantKey)]
    fn js_delete_grant_key(key_id: String) -> Promise;
    #[wasm_bindgen(js_name = __p2pSaveIdentity)]
    fn js_save_identity(input: JsValue) -> Promise;
    #[wasm_bindgen(js_name = __p2pListIdentities)]
    fn js_list_identities() -> Promise;
    #[wasm_bindgen(js_name = __p2pLoadIdentity)]
    fn js_load_identity(identity: String) -> Promise;
    #[wasm_bindgen(js_name = __p2pSaveNewDeviceState)]
    fn js_save_new_device_state(identity: String, control_key: String, state: String) -> Promise;
    #[wasm_bindgen(js_name = __p2pReplaceDeviceState)]
    fn js_replace_device_state(
        identity: String,
        old_control_key: String,
        new_control_key: String,
        state: String,
    ) -> Promise;
    #[wasm_bindgen(js_name = __p2pLoadDeviceState)]
    fn js_load_device_state(identity: String) -> Promise;
    #[wasm_bindgen(js_name = __p2pHasPublisherSequence)]
    fn js_has_publisher_sequence(account: String, identity: String, control_key: String)
    -> Promise;
    #[wasm_bindgen(js_name = __p2pRemoveIdentity)]
    fn js_remove_identity(identity: String) -> Promise;
    #[wasm_bindgen(js_name = __p2pNextPublisherSequence)]
    fn js_next_publisher_sequence(
        account: String,
        identity: String,
        control_key: String,
    ) -> Promise;
    #[wasm_bindgen(js_name = __p2pRecordSequenceBatch)]
    fn js_record_sequence_batch(account: String, observations: JsValue) -> Promise;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoredIdentity {
    pub(crate) identity: String,
    pub(crate) key_id: String,
    pub(crate) client_id: String,
    pub(crate) homeserver: String,
    pub(crate) grant_id: String,
    pub(crate) grant_expires_at: u64,
    pub(crate) restore: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IdentityToStore<'a> {
    pub(crate) identity: &'a str,
    pub(crate) key_id: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) homeserver: &'a str,
    pub(crate) grant_id: &'a str,
    pub(crate) grant_expires_at: u64,
    pub(crate) restore: &'a str,
}

pub(crate) fn is_available() -> bool {
    js_storage_available()
}

pub(crate) async fn ensure_grant_key(key_id: Option<String>) -> BrowserResult<(String, PublicKey)> {
    let value = JsFuture::from(js_ensure_grant_key(key_id))
        .await
        .map_err(storage_failure)?;
    let key_id = Reflect::get(&value, &JsValue::from_str("keyId"))
        .map_err(storage_failure)?
        .as_string()
        .ok_or_else(|| failure("storage-tampered"))?;
    let public_key =
        Reflect::get(&value, &JsValue::from_str("publicKey")).map_err(storage_failure)?;
    Ok((key_id, public_key_from_js(&public_key)?))
}

pub(crate) async fn load_grant_public_key(key_id: &str) -> BrowserResult<PublicKey> {
    let value = JsFuture::from(js_load_grant_public_key(key_id.to_owned()))
        .await
        .map_err(storage_failure)?;
    public_key_from_js(&value)
}

pub(crate) fn grant_signer(key_id: String) -> DelegatedSignFn {
    delegated_sign_callback(move |signing_input| {
        let key_id = key_id.clone();
        async move {
            let value = JsFuture::from(js_sign_grant_input(key_id, signing_input))
                .await
                .map_err(|_| {
                    pubky::Error::Authentication(pubky::errors::AuthError::Validation(
                        "browser delegated signing failed".to_owned(),
                    ))
                })?;
            let signature = Uint8Array::new(&value).to_vec();
            if signature.len() != 64 {
                return Err(pubky::Error::Authentication(
                    pubky::errors::AuthError::Validation(
                        "browser delegated signing returned an invalid signature".to_owned(),
                    ),
                ));
            }
            Ok(signature)
        }
    })
}

pub(crate) async fn sign_certificate(key_id: &str, bytes: &[u8]) -> BrowserResult<Vec<u8>> {
    let input = Uint8Array::from(bytes);
    let value = JsFuture::from(js_sign_bytes(key_id.to_owned(), input))
        .await
        .map_err(storage_failure)?;
    let signature = Uint8Array::new(&value).to_vec();
    if signature.len() != 64 {
        return Err(failure("signing-failed"));
    }
    Ok(signature)
}

pub(crate) async fn delete_grant_key(key_id: &str) -> BrowserResult<()> {
    JsFuture::from(js_delete_grant_key(key_id.to_owned()))
        .await
        .map_err(storage_failure)?;
    Ok(())
}

pub(crate) async fn save_identity(input: &IdentityToStore<'_>) -> BrowserResult<()> {
    let value = serde_wasm_bindgen::to_value(input).map_err(|_| failure("storage-invalid"))?;
    JsFuture::from(js_save_identity(value))
        .await
        .map_err(storage_failure)?;
    Ok(())
}

pub(crate) async fn list_identities() -> BrowserResult<JsValue> {
    JsFuture::from(js_list_identities())
        .await
        .map_err(storage_failure)
}

pub(crate) async fn load_identity(identity: &str) -> BrowserResult<StoredIdentity> {
    let value = JsFuture::from(js_load_identity(identity.to_owned()))
        .await
        .map_err(storage_failure)?;
    serde_wasm_bindgen::from_value(value).map_err(|_| failure("storage-tampered"))
}

pub(crate) async fn save_new_device_state(
    identity: &str,
    control_key: &str,
    state: &str,
) -> BrowserResult<()> {
    JsFuture::from(js_save_new_device_state(
        identity.to_owned(),
        control_key.to_owned(),
        state.to_owned(),
    ))
    .await
    .map_err(storage_failure)?;
    Ok(())
}

pub(crate) async fn replace_device_state(
    identity: &str,
    old_control_key: &str,
    new_control_key: &str,
    state: &str,
) -> BrowserResult<()> {
    JsFuture::from(js_replace_device_state(
        identity.to_owned(),
        old_control_key.to_owned(),
        new_control_key.to_owned(),
        state.to_owned(),
    ))
    .await
    .map_err(storage_failure)?;
    Ok(())
}

pub(crate) async fn load_device_state(identity: &str) -> BrowserResult<Option<String>> {
    let value = JsFuture::from(js_load_device_state(identity.to_owned()))
        .await
        .map_err(storage_failure)?;
    if value.is_undefined() {
        return Ok(None);
    }
    value
        .as_string()
        .map(Some)
        .ok_or_else(|| failure("storage-tampered"))
}

pub(crate) async fn has_publisher_sequence(
    account: &str,
    identity: &str,
    control_key: &str,
) -> BrowserResult<bool> {
    let value = JsFuture::from(js_has_publisher_sequence(
        account.to_owned(),
        identity.to_owned(),
        control_key.to_owned(),
    ))
    .await
    .map_err(storage_failure)?;
    value.as_bool().ok_or_else(|| failure("storage-tampered"))
}

pub(crate) async fn remove_identity(identity: &str) -> BrowserResult<JsValue> {
    JsFuture::from(js_remove_identity(identity.to_owned()))
        .await
        .map_err(storage_failure)
}

fn public_key_from_js(value: &JsValue) -> BrowserResult<PublicKey> {
    let bytes = Uint8Array::new(value).to_vec();
    let inner = pubky::pkarr::PublicKey::try_from(bytes.as_slice())
        .map_err(|_| failure("storage-tampered"))?;
    Ok(PublicKey::from(inner))
}

#[derive(Debug, Clone)]
pub(crate) struct BrowserSequenceStore {
    account: String,
}

impl BrowserSequenceStore {
    pub(crate) fn new(account: String) -> Self {
        Self { account }
    }
}

#[async_trait::async_trait(?Send)]
impl PublisherSequenceStore for BrowserSequenceStore {
    async fn next_locator_sequence(
        &self,
        identity: &str,
        control_key: &str,
    ) -> pubky2pubky_client::Result<u64> {
        let value = JsFuture::from(js_next_publisher_sequence(
            self.account.clone(),
            identity.to_owned(),
            control_key.to_owned(),
        ))
        .await
        .map_err(sequence_error)?;
        number_to_counter(&value)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SequenceObservation<'a> {
    identity: &'a str,
    scope: &'a str,
    counter: u64,
    digest: String,
}

#[async_trait::async_trait(?Send)]
impl SequenceStore for BrowserSequenceStore {
    async fn record_batch(
        &self,
        observations: Vec<AuthenticatedSequenceObservation>,
    ) -> pubky2pubky_client::Result<()> {
        if observations
            .iter()
            .any(|observation| observation.counter() > JS_MAX_SAFE_COUNTER)
        {
            return Err(ClientError::State(
                "browser sequence exceeds the exact JavaScript integer range".to_owned(),
            ));
        }
        let wire: Vec<_> = observations
            .iter()
            .map(|observation| SequenceObservation {
                identity: observation.identity(),
                scope: observation.scope(),
                counter: observation.counter(),
                digest: URL_SAFE_NO_PAD.encode(observation.digest()),
            })
            .collect();
        let value = serde_wasm_bindgen::to_value(&wire)
            .map_err(|_| ClientError::State("browser sequence serialization failed".to_owned()))?;
        JsFuture::from(js_record_sequence_batch(self.account.clone(), value))
            .await
            .map_err(sequence_error)?;
        Ok(())
    }
}

const JS_MAX_SAFE_COUNTER: u64 = 9_007_199_254_740_991;

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the finite positive integer is bounded to JavaScript's exact u53 range first"
)]
fn number_to_counter(value: &JsValue) -> pubky2pubky_client::Result<u64> {
    let Some(number) = value.as_f64() else {
        return Err(ClientError::State(
            "browser publisher state is invalid".to_owned(),
        ));
    };
    if !(1.0..=9_007_199_254_740_991.0).contains(&number) || number.fract() != 0.0 {
        return Err(ClientError::State(
            "browser publisher state is invalid".to_owned(),
        ));
    }
    Ok(number as u64)
}

fn sequence_error(_value: JsValue) -> ClientError {
    ClientError::State("browser sequence transaction failed closed".to_owned())
}
