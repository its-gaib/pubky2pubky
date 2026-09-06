use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;
use pubky_common::crypto::PublicKey;
use serde::Serialize;
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{ProtocolError, Result};

/// Return Unix time in whole seconds.
#[must_use]
pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Serialize)]
struct SigningEnvelope<'a, T> {
    domain: &'a str,
    payload: &'a T,
}

pub(crate) fn canonical_for_signing<T: Serialize>(domain: &str, payload: &T) -> Result<Vec<u8>> {
    Ok(serde_jcs::to_vec(&SigningEnvelope { domain, payload })?)
}

pub(crate) fn encode_signature(signature: &Signature) -> String {
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<PublicKey> {
    let key = PublicKey::try_from_z32(encoded)
        .map_err(|_| ProtocolError::InvalidEncoding("public key"))?;
    if key.z32() != encoded {
        return Err(ProtocolError::InvalidEncoding("canonical public key"));
    }
    Ok(key)
}
