//! Pubky Grant-authorized iroh discovery and handshake protocol, version 4.
//!
//! Version 4 replaces direct root-key device signatures with the standard Pubky 0.11 Grant
//! chain: the Pubky root signs a Grant JWS, the Grant `cnf` key signs a device certificate, and
//! the independent device control key signs relay-only locators and handshake records.

use std::{collections::BTreeSet, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;
use pubky_common::{
    StoragePath,
    auth::{
        grant::GrantClaims,
        jws::{ClientId, GrantId},
    },
    capabilities::{Action, Capability},
    crypto::{Keypair, PublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    MAX_CERTIFICATE_LIFETIME_SECONDS, MAX_CLOCK_SKEW_SECONDS, ProtocolError, Result,
    identity::{canonical_for_signing, encode_signature, parse_public_key},
};

/// Pubky-to-iroh protocol version implemented by this module.
pub const V4_PROTOCOL_VERSION: u16 = 4;

/// Public-storage directory containing self-contained v4 device records.
pub const V4_DEVICE_RECORD_PATH_PREFIX: &str = "/pub/pubky2pubky/v4/devices/";

/// Public-storage directory containing short-lived v4 currentness proofs.
pub const V4_CURRENTNESS_PATH_PREFIX: &str = "/pub/pubky2pubky/v4/currentness/";

/// Text representation of the fixed v4 QUIC ALPN.
pub const V4_IROH_ALPN_TEXT: &str = "pubky2pubky/iroh/v4";

/// Fixed v4 QUIC ALPN bytes passed to iroh.
pub const V4_IROH_ALPN: &[u8] = b"pubky2pubky/iroh/v4";

/// Storage scope every v4 Grant must authorize for writing.
pub const V4_REQUIRED_STORAGE_SCOPE: &str = "/pub/pubky2pubky/";

/// Maximum accepted Pubky Grant JWS size.
pub const V4_MAX_GRANT_JWS_BYTES: usize = 16 * 1024;

/// Maximum capabilities accepted in a Pubky Grant.
pub const V4_MAX_GRANT_CAPABILITIES: usize = 32;

/// Maximum accepted Grant lifetime, matching the Pubky 0.11 default horizon.
pub const V4_MAX_GRANT_LIFETIME_SECONDS: u64 = 2 * 365 * 24 * 60 * 60;

/// Maximum lifetime of a Grant-`cnf`-signed device certificate.
pub const V4_MAX_DEVICE_CERTIFICATE_LIFETIME_SECONDS: u64 = MAX_CERTIFICATE_LIFETIME_SECONDS;

/// Maximum iroh relay URLs in one locator.
pub const V4_MAX_RELAY_URLS: usize = 4;

/// Maximum device-signed locator lifetime.
pub const V4_MAX_LOCATOR_LIFETIME_SECONDS: u64 = 15 * 60;

/// Maximum Hello or Ack lifetime.
pub const V4_MAX_HANDSHAKE_LIFETIME_SECONDS: u64 = 2 * 60;

/// Maximum currentness-proof lifetime.
pub const V4_MAX_CURRENTNESS_LIFETIME_SECONDS: u64 = 30;

/// Maximum encoded self-contained device-record size.
pub const V4_MAX_DEVICE_RECORD_BYTES: usize = 32 * 1024;

/// Maximum encoded Hello size.
pub const V4_MAX_HELLO_BYTES: usize = 48 * 1024;

/// Maximum encoded Ack size.
pub const V4_MAX_ACK_BYTES: usize = 8 * 1024;

/// Maximum encoded currentness-proof size.
pub const V4_MAX_CURRENTNESS_PROOF_BYTES: usize = 4 * 1024;

const V4_GRANT_HEADER_JSON: &[u8] = br#"{"alg":"EdDSA","typ":"pubky-grant"}"#;
const V4_GRANT_DIGEST_DOMAIN: &str = "pubky2pubky/grant-digest/v4";
const V4_CERTIFICATE_DOMAIN: &str = "pubky2pubky/device-certificate/v4";
const V4_CERTIFICATE_DIGEST_DOMAIN: &str = "pubky2pubky/device-certificate-digest/v4";
const V4_DEVICE_RECORD_DIGEST_DOMAIN: &str = "pubky2pubky/device-record-digest/v4";
const V4_DEVICE_PATH_DOMAIN: &str = "pubky2pubky/device-path/v4";
const V4_LOCATOR_DOMAIN: &str = "pubky2pubky/iroh-locator/v4";
const V4_LOCATOR_DIGEST_DOMAIN: &str = "pubky2pubky/iroh-locator-digest/v4";
const V4_HELLO_DOMAIN: &str = "pubky2pubky/hello/v4";
const V4_HELLO_DIGEST_DOMAIN: &str = "pubky2pubky/hello-digest/v4";
const V4_ACK_DOMAIN: &str = "pubky2pubky/ack/v4";
const V4_CURRENTNESS_DOMAIN: &str = "pubky2pubky/currentness/v4";
const V4_CURRENTNESS_PATH_DOMAIN: &str = "pubky2pubky/currentness-path/v4";
const MAX_DEVICE_ID_BYTES: usize = 64;
const MAX_APPLICATION_BYTES: usize = 128;
const MAX_RELAY_URL_BYTES: usize = 2_048;
const MIN_CHALLENGE_BYTES: usize = 16;
const MAX_CHALLENGE_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4GrantHeader {
    alg: String,
    typ: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4GrantClaimsWire {
    iss: PublicKey,
    client_id: ClientId,
    caps: Vec<Capability>,
    cnf: PublicKey,
    jti: GrantId,
    iat: u64,
    exp: u64,
}

impl V4GrantClaimsWire {
    fn into_claims(self) -> GrantClaims {
        GrantClaims {
            iss: self.iss,
            client_id: self.client_id,
            caps: self.caps,
            cnf: self.cnf,
            jti: self.jti,
            iat: self.iat,
            exp: self.exp,
        }
    }
}

fn decode_canonical_base64(value: &str, label: &'static str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProtocolError::InvalidEncoding(label))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(ProtocolError::InvalidEncoding(label));
    }
    Ok(bytes)
}

fn decode_v4_signature(encoded: &str) -> Result<Signature> {
    let bytes = decode_canonical_base64(encoded, "canonical v4 signature")?;
    Signature::from_slice(&bytes).map_err(|_| ProtocolError::InvalidEncoding("v4 signature"))
}

fn verify_signature(
    key: &PublicKey,
    domain: &str,
    claims: &impl Serialize,
    value: &str,
) -> Result<()> {
    let signature = decode_v4_signature(value)?;
    key.verify(&canonical_for_signing(domain, claims)?, &signature)
        .map_err(|_| ProtocolError::BadSignature)
}

fn validate_bounded_window(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    maximum: u64,
    label: &'static str,
) -> Result<()> {
    if expires_at <= issued_at {
        return Err(ProtocolError::InvalidTimeWindow);
    }
    if issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECONDS) {
        return Err(ProtocolError::NotYetValid);
    }
    // Expiry is intentionally strict in v4. In particular, a 30-second currentness proof must
    // not remain acceptable for an additional global clock-skew window.
    if expires_at <= now {
        return Err(ProtocolError::Expired);
    }
    if expires_at - issued_at > maximum {
        return Err(ProtocolError::InvalidEncoding(label));
    }
    Ok(())
}

fn validate_currentness_window(issued_at: u64, expires_at: u64, now: u64) -> Result<()> {
    validate_bounded_window(
        issued_at,
        expires_at,
        now,
        V4_MAX_CURRENTNESS_LIFETIME_SECONDS,
        "v4 currentness lifetime",
    )?;
    // Currentness is a live-authority check, not a general signed credential. Letting it inherit
    // the protocol-wide clock-skew allowance would make a future-dated 30-second proof usable for
    // roughly two and a half minutes. Issuers that need clock tolerance should backdate this
    // short-lived record; verifiers never accept a proof issued in their future or expiring more
    // than one proof window from their present.
    if issued_at > now {
        return Err(ProtocolError::NotYetValid);
    }
    if expires_at > now.saturating_add(V4_MAX_CURRENTNESS_LIFETIME_SECONDS) {
        return Err(ProtocolError::InvalidTimeWindow);
    }
    Ok(())
}

fn ensure_serialized_bound<T: Serialize>(
    value: &T,
    maximum: usize,
    label: &'static str,
) -> Result<()> {
    if serde_json::to_vec(value)?.len() > maximum {
        return Err(ProtocolError::InvalidEncoding(label));
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let bytes = canonical_for_signing(domain, value)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

fn validate_digest(value: &str, label: &'static str) -> Result<()> {
    let bytes = decode_canonical_base64(value, label)?;
    if bytes.len() != 32 {
        return Err(ProtocolError::InvalidEncoding(label));
    }
    Ok(())
}

fn validate_challenge(value: &str, label: &'static str) -> Result<()> {
    let bytes = decode_canonical_base64(value, label)?;
    if !(MIN_CHALLENGE_BYTES..=MAX_CHALLENGE_BYTES).contains(&bytes.len()) {
        return Err(ProtocolError::InvalidEncoding(label));
    }
    Ok(())
}

fn validate_device_id(device_id: &str) -> Result<()> {
    if device_id.is_empty()
        || device_id.len() > MAX_DEVICE_ID_BYTES
        || device_id.chars().any(char::is_control)
        || device_id.chars().all(char::is_whitespace)
    {
        return Err(ProtocolError::InvalidEncoding("v4 device id"));
    }
    Ok(())
}

fn validate_application(application: &str) -> Result<()> {
    if application.is_empty()
        || application.len() > MAX_APPLICATION_BYTES
        || !application
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(ProtocolError::InvalidEncoding("v4 application"));
    }
    Ok(())
}

fn local_relay_host(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

fn validate_relay_url(url: &Url, allow_loopback_dev: bool) -> Result<()> {
    let secure = url.scheme() == "https";
    let loopback_dev = allow_loopback_dev && url.scheme() == "http" && local_relay_host(url);
    if url.as_str().len() > MAX_RELAY_URL_BYTES
        || (!secure && !loopback_dev)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProtocolError::InvalidEncoding("v4 relay URL"));
    }
    Ok(())
}

fn validate_relays(relays: &[Url], allow_loopback_dev: bool) -> Result<()> {
    if relays.is_empty() || relays.len() > V4_MAX_RELAY_URLS {
        return Err(ProtocolError::InvalidEncoding("v4 relay URLs"));
    }
    let mut unique = BTreeSet::new();
    for relay in relays {
        validate_relay_url(relay, allow_loopback_dev)?;
        if !unique.insert(relay.as_str()) {
            return Err(ProtocolError::InvalidEncoding("duplicate v4 relay URL"));
        }
    }
    Ok(())
}

fn grant_covers_storage(claims: &GrantClaims) -> bool {
    let Ok(required) = StoragePath::new(V4_REQUIRED_STORAGE_SCOPE) else {
        return false;
    };
    claims.caps.iter().any(|capability| {
        capability.scope_covers_path(&required) && capability.actions().contains(&Action::Write)
    })
}

/// Generate a canonical 256-bit challenge for handshakes and currentness proofs.
#[must_use]
pub fn v4_random_challenge() -> String {
    let random = Keypair::random();
    let secret = Zeroizing::new(random.secret());
    URL_SAFE_NO_PAD.encode(&secret[..])
}

/// Root-signed Pubky 0.11 Grant authorization carried verbatim as a compact JWS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4GrantAuthorization {
    /// Exact canonical `pubky-grant` JWS issued by the Pubky identity.
    pub grant_jws: String,
}

impl V4GrantAuthorization {
    /// Construct and fully verify an authorization.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed, noncanonical, invalidly signed, stale, overlong,
    /// cross-identity, or insufficiently scoped Grant.
    pub fn from_jws(
        grant_jws: impl Into<String>,
        expected_identity: &str,
        now: u64,
    ) -> Result<Self> {
        let authorization = Self {
            grant_jws: grant_jws.into(),
        };
        authorization.verify(expected_identity, now)?;
        Ok(authorization)
    }

    /// Verify the exact compact JWS and return its typed Pubky claims.
    ///
    /// # Errors
    ///
    /// Returns an error when any format, signature, identity, time, count, or capability check
    /// fails.
    pub fn verify(&self, expected_identity: &str, now: u64) -> Result<GrantClaims> {
        if self.grant_jws.is_empty() || self.grant_jws.len() > V4_MAX_GRANT_JWS_BYTES {
            return Err(ProtocolError::InvalidEncoding("v4 Grant JWS size"));
        }

        let mut parts = self.grant_jws.split('.');
        let header_segment = parts
            .next()
            .ok_or(ProtocolError::InvalidEncoding("v4 Grant JWS"))?;
        let payload_segment = parts
            .next()
            .ok_or(ProtocolError::InvalidEncoding("v4 Grant JWS"))?;
        let signature_segment = parts
            .next()
            .ok_or(ProtocolError::InvalidEncoding("v4 Grant JWS"))?;
        if parts.next().is_some()
            || header_segment.is_empty()
            || payload_segment.is_empty()
            || signature_segment.is_empty()
        {
            return Err(ProtocolError::InvalidEncoding("v4 Grant JWS"));
        }

        let header_bytes = decode_canonical_base64(header_segment, "v4 Grant header")?;
        let header: V4GrantHeader = serde_json::from_slice(&header_bytes)?;
        if header.alg != "EdDSA"
            || header.typ != "pubky-grant"
            || header_bytes != V4_GRANT_HEADER_JSON
        {
            return Err(ProtocolError::InvalidEncoding("canonical v4 Grant header"));
        }

        let payload_bytes = decode_canonical_base64(payload_segment, "v4 Grant payload")?;
        let wire: V4GrantClaimsWire = serde_json::from_slice(&payload_bytes)?;
        if serde_json::to_vec(&wire)? != payload_bytes {
            return Err(ProtocolError::InvalidEncoding("canonical v4 Grant payload"));
        }
        let claims = wire.into_claims();

        let signature_bytes = decode_canonical_base64(signature_segment, "v4 Grant signature")?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| ProtocolError::InvalidEncoding("v4 Grant signature"))?;
        let signing_input = format!("{header_segment}.{payload_segment}");
        claims
            .iss
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| ProtocolError::BadSignature)?;

        let expected = parse_public_key(expected_identity)?;
        if claims.iss != expected {
            return Err(ProtocolError::IdentityMismatch);
        }
        if claims.cnf == claims.iss {
            return Err(ProtocolError::InvalidEncoding("independent v4 Grant cnf"));
        }
        validate_bounded_window(
            claims.iat,
            claims.exp,
            now,
            V4_MAX_GRANT_LIFETIME_SECONDS,
            "v4 Grant lifetime",
        )?;
        let client_id = claims.client_id.as_str();
        if client_id.is_empty()
            || client_id.len() > 253
            || client_id.chars().any(char::is_control)
            || client_id.chars().all(char::is_whitespace)
        {
            return Err(ProtocolError::InvalidEncoding("v4 Grant client id"));
        }
        if claims.caps.is_empty() || claims.caps.len() > V4_MAX_GRANT_CAPABILITIES {
            return Err(ProtocolError::InvalidEncoding("v4 Grant capabilities"));
        }
        let mut capabilities = BTreeSet::new();
        if claims
            .caps
            .iter()
            .any(|capability| !capabilities.insert(capability.to_string()))
        {
            return Err(ProtocolError::InvalidEncoding(
                "duplicate v4 Grant capability",
            ));
        }
        if !grant_covers_storage(&claims) {
            return Err(ProtocolError::MissingCapability(format!(
                "{V4_REQUIRED_STORAGE_SCOPE}:w"
            )));
        }
        Ok(claims)
    }

    /// Domain-separated digest of the exact canonical Grant JWS.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical serialization fails.
    pub fn digest(&self) -> Result<String> {
        canonical_digest(V4_GRANT_DIGEST_DOMAIN, self)
    }
}

/// Grant-`cnf`-signed device delegation claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4DeviceCertificateClaims {
    /// Protocol version.
    pub version: u16,
    /// Pubky root identity that issued the Grant.
    pub identity: String,
    /// Exact digest of the Grant authorization.
    pub grant_digest: String,
    /// Exact Grant revocation identifier.
    pub grant_jti: String,
    /// Exact Grant application identifier.
    pub client_id: String,
    /// Canonical Grant proof-of-possession public key.
    pub grant_cnf_key: String,
    /// Bounded display-oriented device identifier.
    pub device_id: String,
    /// Independent online Ed25519 control-signing public key.
    pub control_signing_key: String,
    /// Independent iroh endpoint Ed25519 public key.
    pub iroh_endpoint_id: String,
    /// Start of the device delegation validity window.
    pub issued_at: u64,
    /// End of the device delegation validity window.
    pub expires_at: u64,
}

/// Device delegation signed by the Pubky Grant's `cnf` key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4DeviceCertificate {
    /// Delegated public claims.
    pub claims: V4DeviceCertificateClaims,
    /// Grant-`cnf` signature, canonical base64url without padding.
    pub signature: String,
}

impl V4DeviceCertificate {
    fn control_public_key(&self) -> Result<PublicKey> {
        parse_public_key(&self.claims.control_signing_key)
    }

    /// Verify the Grant chain, exact bindings, lifetime, independent keys, and `cnf` signature.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, stale, overlong, cross-identity, mismatched, or tampered
    /// certificates.
    pub fn verify(
        &self,
        authorization: &V4GrantAuthorization,
        expected_identity: &str,
        now: u64,
    ) -> Result<()> {
        let grant = authorization.verify(expected_identity, now)?;
        if self.claims.version != V4_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.claims.version));
        }
        if self.claims.identity != expected_identity || self.claims.identity != grant.iss.z32() {
            return Err(ProtocolError::IdentityMismatch);
        }
        validate_device_id(&self.claims.device_id)?;
        validate_digest(&self.claims.grant_digest, "v4 Grant digest")?;
        if self.claims.grant_digest != authorization.digest()?
            || self.claims.grant_jti != grant.jti.as_str()
            || self.claims.client_id != grant.client_id.as_str()
            || self.claims.grant_cnf_key != grant.cnf.z32()
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_bounded_window(
            self.claims.issued_at,
            self.claims.expires_at,
            now,
            V4_MAX_DEVICE_CERTIFICATE_LIFETIME_SECONDS,
            "v4 certificate lifetime",
        )?;
        if self.claims.issued_at < grant.iat || self.claims.expires_at > grant.exp {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        let root = parse_public_key(&self.claims.identity)?;
        let cnf = parse_public_key(&self.claims.grant_cnf_key)?;
        let control = parse_public_key(&self.claims.control_signing_key)?;
        let iroh = parse_public_key(&self.claims.iroh_endpoint_id)?;
        if control == iroh
            || control == root
            || control == cnf
            || iroh == root
            || iroh == cnf
            || cnf != grant.cnf
        {
            return Err(ProtocolError::InvalidEncoding("independent v4 device keys"));
        }
        verify_signature(&cnf, V4_CERTIFICATE_DOMAIN, &self.claims, &self.signature)
    }

    /// Domain-separated digest bound by locators, records, and currentness proofs.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical serialization fails.
    pub fn digest(&self) -> Result<String> {
        canonical_digest(V4_CERTIFICATE_DIGEST_DOMAIN, self)
    }
}

/// In-progress device credential awaiting one purpose-specific Grant-`cnf` signature.
///
/// This type lets a nonextractable browser/WebCrypto `cnf` key sign the certificate without
/// exposing that private key to the protocol library.
#[derive(Clone, ZeroizeOnDrop)]
pub struct V4DeviceCredentialDraft {
    #[zeroize(skip)]
    authorization: V4GrantAuthorization,
    #[zeroize(skip)]
    certificate_claims: V4DeviceCertificateClaims,
    control_signing_secret: String,
    iroh_secret: String,
}

impl fmt::Debug for V4DeviceCredentialDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V4DeviceCredentialDraft")
            .field("authorization", &self.authorization)
            .field("certificate_claims", &self.certificate_claims)
            .field("control_signing_secret", &"[REDACTED]")
            .field("iroh_secret", &"[REDACTED]")
            .finish()
    }
}

impl V4DeviceCredentialDraft {
    /// Public claims the external Grant-`cnf` signer is authorizing.
    #[must_use]
    pub fn certificate_claims(&self) -> &V4DeviceCertificateClaims {
        &self.certificate_claims
    }

    /// Exact domain-separated bytes the Grant `cnf` key must sign once.
    ///
    /// This is purpose-specific and is not a generic signing oracle.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical serialization fails.
    pub fn certificate_signing_bytes(&self) -> Result<Vec<u8>> {
        canonical_for_signing(V4_CERTIFICATE_DOMAIN, &self.certificate_claims)
    }

    /// Consume the draft, attach a raw Ed25519 `cnf` signature, and verify the complete chain.
    ///
    /// # Errors
    ///
    /// Returns an error unless the signature is exactly 64 bytes and verifies under the Grant's
    /// `cnf` key over [`Self::certificate_signing_bytes`].
    pub fn finalize(self, signature: impl AsRef<[u8]>) -> Result<V4DeviceCredential> {
        let signature = Signature::from_slice(signature.as_ref())
            .map_err(|_| ProtocolError::InvalidEncoding("v4 certificate signature"))?;
        // This type zeroizes on drop, so clone the two secrets into their final owner and let the
        // draft wipe its originals at the end of this method.
        let credential = V4DeviceCredential {
            authorization: self.authorization.clone(),
            certificate: V4DeviceCertificate {
                claims: self.certificate_claims.clone(),
                signature: encode_signature(&signature),
            },
            control_signing_secret: self.control_signing_secret.clone(),
            iroh_secret: self.iroh_secret.clone(),
        };
        credential.verify(self.certificate_claims.issued_at)?;
        Ok(credential)
    }
}

/// Serializable v4 device state. Persist only in protected, owner-controlled storage.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct V4DeviceCredential {
    /// Root-signed Grant authorization.
    #[zeroize(skip)]
    pub authorization: V4GrantAuthorization,
    /// Grant-`cnf`-signed public device delegation.
    #[zeroize(skip)]
    pub certificate: V4DeviceCertificate,
    /// Device control secret, canonical base64url without padding.
    control_signing_secret: String,
    /// Independent iroh secret, canonical base64url without padding.
    iroh_secret: String,
}

impl fmt::Debug for V4DeviceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V4DeviceCredential")
            .field("authorization", &self.authorization)
            .field("certificate", &self.certificate)
            .field("control_signing_secret", &"[REDACTED]")
            .field("iroh_secret", &"[REDACTED]")
            .finish()
    }
}

impl V4DeviceCredential {
    /// Prepare fresh independent device keys and bounded certificate claims for external signing.
    ///
    /// The returned draft exposes only purpose-specific certificate signing bytes. This supports
    /// nonextractable Grant `cnf` keys held by `WebCrypto` or another hardware-backed signer.
    ///
    /// # Errors
    ///
    /// Returns an error if the Grant, identity, device id, or requested lifetime is invalid.
    pub fn prepare(
        authorization: V4GrantAuthorization,
        expected_identity: &str,
        device_id: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<V4DeviceCredentialDraft> {
        let grant = authorization.verify(expected_identity, issued_at)?;
        let device_id = device_id.into();
        validate_device_id(&device_id)?;
        validate_bounded_window(
            issued_at,
            expires_at,
            issued_at,
            V4_MAX_DEVICE_CERTIFICATE_LIFETIME_SECONDS,
            "v4 certificate lifetime",
        )?;
        if issued_at < grant.iat || expires_at > grant.exp {
            return Err(ProtocolError::InvalidTimeWindow);
        }

        let control = Keypair::random();
        let iroh = Keypair::random();
        let control_secret = Zeroizing::new(control.secret());
        let iroh_secret = Zeroizing::new(iroh.secret());
        Ok(V4DeviceCredentialDraft {
            certificate_claims: V4DeviceCertificateClaims {
                version: V4_PROTOCOL_VERSION,
                identity: grant.iss.z32(),
                grant_digest: authorization.digest()?,
                grant_jti: grant.jti.as_str().to_owned(),
                client_id: grant.client_id.as_str().to_owned(),
                grant_cnf_key: grant.cnf.z32(),
                device_id,
                control_signing_key: control.public_key().z32(),
                iroh_endpoint_id: iroh.public_key().z32(),
                issued_at,
                expires_at,
            },
            authorization,
            control_signing_secret: URL_SAFE_NO_PAD.encode(&control_secret[..]),
            iroh_secret: URL_SAFE_NO_PAD.encode(&iroh_secret[..]),
        })
    }

    /// Issue fresh independent control and iroh keys under an existing Pubky Grant.
    ///
    /// The caller supplies the Grant `cnf` keypair; the Pubky root secret is never required.
    ///
    /// # Errors
    ///
    /// Returns an error if the Grant, `cnf` binding, device id, or requested lifetime is invalid.
    #[allow(
        clippy::too_many_arguments,
        reason = "all Grant, identity, and device validity inputs are security-relevant"
    )]
    pub fn issue(
        authorization: V4GrantAuthorization,
        expected_identity: &str,
        grant_cnf: &Keypair,
        device_id: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        let draft = Self::prepare(
            authorization,
            expected_identity,
            device_id,
            issued_at,
            expires_at,
        )?;
        if draft.certificate_claims.grant_cnf_key != grant_cnf.public_key().z32() {
            return Err(ProtocolError::DeviceMismatch);
        }
        let signature = grant_cnf.sign(&draft.certificate_signing_bytes()?);
        draft.finalize(signature.to_bytes())
    }

    /// Verify this credential's complete public chain and private-key bindings.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid chain or mismatched stored secret.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.certificate
            .verify(&self.authorization, self.identity(), now)?;
        self.control_key()?;
        self.iroh_secret_key_bytes()?;
        Ok(())
    }

    /// Pubky identity that authorized this device.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.certificate.claims.identity
    }

    /// Bounded display-oriented device identifier.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.certificate.claims.device_id
    }

    /// Delegated online control-signing public key.
    #[must_use]
    pub fn control_signing_key(&self) -> &str {
        &self.certificate.claims.control_signing_key
    }

    /// Dedicated iroh endpoint id.
    #[must_use]
    pub fn iroh_endpoint_id(&self) -> &str {
        &self.certificate.claims.iroh_endpoint_id
    }

    fn decode_secret(encoded: &str, public: &str, label: &'static str) -> Result<Keypair> {
        let bytes = Zeroizing::new(decode_canonical_base64(encoded, label)?);
        let secret = Zeroizing::new(
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| ProtocolError::InvalidEncoding(label))?,
        );
        let key = Keypair::from_secret(&secret);
        if key.public_key().z32() != public {
            return Err(ProtocolError::InvalidEncoding(label));
        }
        Ok(key)
    }

    fn control_key(&self) -> Result<Keypair> {
        Self::decode_secret(
            &self.control_signing_secret,
            self.control_signing_key(),
            "v4 control-signing secret",
        )
    }

    /// Decode and verify the independent iroh secret key.
    ///
    /// Returned bytes are zeroized on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret is malformed, noncanonical, or mismatches the certificate.
    #[doc(hidden)]
    pub fn iroh_secret_key_bytes(&self) -> Result<Zeroizing<[u8; 32]>> {
        let key =
            Self::decode_secret(&self.iroh_secret, self.iroh_endpoint_id(), "v4 iroh secret")?;
        Ok(Zeroizing::new(key.secret()))
    }
}

/// Device-control-key-signed, relay-only iroh locator claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4LocatorClaims {
    /// Protocol version.
    pub version: u16,
    /// Pubky identity owning this record.
    pub identity: String,
    /// Exact Grant authorization digest.
    pub grant_digest: String,
    /// Exact device-certificate digest.
    pub device_certificate_digest: String,
    /// Certified control-signing key.
    pub control_signing_key: String,
    /// Certified iroh endpoint id.
    pub iroh_endpoint_id: String,
    /// Relay URLs used for initial contact; direct addresses are never published.
    pub relay_urls: Vec<Url>,
    /// Fixed v4 application-layer protocol identifier.
    pub alpn: String,
    /// Canonical random endpoint-instance challenge.
    pub instance_nonce: String,
    /// Positive monotonic publication sequence.
    pub sequence: u64,
    /// Start of locator validity.
    pub issued_at: u64,
    /// End of locator validity.
    pub expires_at: u64,
}

/// Control-key-signed v4 iroh locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4SignedLocator {
    /// Signed locator claims.
    pub claims: V4LocatorClaims,
    /// Device-control signature, canonical base64url without padding.
    pub signature: String,
}

impl V4SignedLocator {
    /// Sign a production relay-only locator.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed relays/challenges, stale credentials, invalid sequence or
    /// lifetime, or encoding failure.
    pub fn sign(
        credential: &V4DeviceCredential,
        relay_urls: Vec<Url>,
        instance_nonce: impl Into<String>,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            relay_urls,
            instance_nonce,
            sequence,
            (issued_at, expires_at),
            false,
        )
    }

    /// Sign a relay-only locator that explicitly permits an HTTP loopback development relay.
    ///
    /// # Errors
    ///
    /// Returns the same validation and signing errors as [`Self::sign`].
    pub fn sign_for_local_development(
        credential: &V4DeviceCredential,
        relay_urls: Vec<Url>,
        instance_nonce: impl Into<String>,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            relay_urls,
            instance_nonce,
            sequence,
            (issued_at, expires_at),
            true,
        )
    }

    fn sign_with_policy(
        credential: &V4DeviceCredential,
        relay_urls: Vec<Url>,
        instance_nonce: impl Into<String>,
        sequence: u64,
        validity: (u64, u64),
        allow_loopback_dev: bool,
    ) -> Result<Self> {
        let (issued_at, expires_at) = validity;
        credential.verify(issued_at)?;
        let claims = V4LocatorClaims {
            version: V4_PROTOCOL_VERSION,
            identity: credential.identity().to_owned(),
            grant_digest: credential.authorization.digest()?,
            device_certificate_digest: credential.certificate.digest()?,
            control_signing_key: credential.control_signing_key().to_owned(),
            iroh_endpoint_id: credential.iroh_endpoint_id().to_owned(),
            relay_urls,
            alpn: V4_IROH_ALPN_TEXT.to_owned(),
            instance_nonce: instance_nonce.into(),
            sequence,
            issued_at,
            expires_at,
        };
        Self::validate_claims(
            &claims,
            &credential.authorization,
            &credential.certificate,
            credential.identity(),
            issued_at,
            allow_loopback_dev,
            None,
        )?;
        let signature = credential
            .control_key()?
            .sign(&canonical_for_signing(V4_LOCATOR_DOMAIN, &claims)?);
        Ok(Self {
            claims,
            signature: encode_signature(&signature),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "verification keeps every authorization and rollback input explicit"
    )]
    fn validate_claims(
        claims: &V4LocatorClaims,
        authorization: &V4GrantAuthorization,
        certificate: &V4DeviceCertificate,
        expected_identity: &str,
        now: u64,
        allow_loopback_dev: bool,
        minimum_sequence: Option<u64>,
    ) -> Result<()> {
        if claims.version != V4_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(claims.version));
        }
        certificate.verify(authorization, expected_identity, now)?;
        if claims.identity != expected_identity || claims.identity != certificate.claims.identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        validate_digest(&claims.grant_digest, "v4 Grant digest")?;
        validate_digest(&claims.device_certificate_digest, "v4 certificate digest")?;
        if claims.grant_digest != authorization.digest()?
            || claims.device_certificate_digest != certificate.digest()?
            || claims.control_signing_key != certificate.claims.control_signing_key
            || claims.iroh_endpoint_id != certificate.claims.iroh_endpoint_id
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        if claims.alpn != V4_IROH_ALPN_TEXT {
            return Err(ProtocolError::InvalidEncoding("v4 ALPN"));
        }
        if claims.sequence == 0 || minimum_sequence.is_some_and(|minimum| claims.sequence < minimum)
        {
            return Err(ProtocolError::InvalidEncoding("v4 locator sequence"));
        }
        validate_challenge(&claims.instance_nonce, "v4 instance nonce")?;
        validate_relays(&claims.relay_urls, allow_loopback_dev)?;
        validate_bounded_window(
            claims.issued_at,
            claims.expires_at,
            now,
            V4_MAX_LOCATOR_LIFETIME_SECONDS,
            "v4 locator lifetime",
        )?;
        if claims.issued_at < certificate.claims.issued_at
            || claims.expires_at > certificate.claims.expires_at
        {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Verify authorization, certificate, exact bindings, relay policy, rollback floor, and
    /// control signature.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, stale, cross-device, rollback, or tampered locators.
    pub fn verify(
        &self,
        authorization: &V4GrantAuthorization,
        certificate: &V4DeviceCertificate,
        expected_identity: &str,
        now: u64,
        allow_loopback_dev: bool,
        minimum_sequence: Option<u64>,
    ) -> Result<()> {
        Self::validate_claims(
            &self.claims,
            authorization,
            certificate,
            expected_identity,
            now,
            allow_loopback_dev,
            minimum_sequence,
        )?;
        verify_signature(
            &certificate.control_public_key()?,
            V4_LOCATOR_DOMAIN,
            &self.claims,
            &self.signature,
        )
    }

    /// Domain-separated digest bound by records, handshakes, and currentness proofs.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical serialization fails.
    pub fn digest(&self) -> Result<String> {
        canonical_digest(V4_LOCATOR_DIGEST_DOMAIN, self)
    }
}

#[derive(Serialize)]
struct V4DevicePathInput<'a> {
    grant_cnf_key: &'a str,
    control_signing_key: &'a str,
}

/// Derive a fixed-alphabet device-record path from canonical Grant-`cnf` and control keys.
///
/// # Errors
///
/// Returns an error unless both keys are canonical Pubky/Ed25519 z-base-32 keys.
pub fn v4_device_record_path(grant_cnf_key: &str, control_signing_key: &str) -> Result<String> {
    parse_public_key(grant_cnf_key)?;
    parse_public_key(control_signing_key)?;
    let input = V4DevicePathInput {
        grant_cnf_key,
        control_signing_key,
    };
    let digest = canonical_digest(V4_DEVICE_PATH_DOMAIN, &input)?;
    Ok(format!("{V4_DEVICE_RECORD_PATH_PREFIX}{digest}.json"))
}

/// Self-contained homeserver publication for one v4 device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4DeviceRecord {
    /// Root-signed Pubky Grant authorization.
    pub authorization: V4GrantAuthorization,
    /// Grant-`cnf`-signed device certificate.
    pub certificate: V4DeviceCertificate,
    /// Device-control-key-signed relay-only locator.
    pub locator: V4SignedLocator,
}

impl V4DeviceRecord {
    /// Build and verify a self-contained record from one credential and locator.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched or invalid locator, chain, or encoded size.
    pub fn new(
        credential: &V4DeviceCredential,
        locator: V4SignedLocator,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<Self> {
        let record = Self {
            authorization: credential.authorization.clone(),
            certificate: credential.certificate.clone(),
            locator,
        };
        record.verify(credential.identity(), now, allow_loopback_dev, None)?;
        Ok(record)
    }

    /// Decode a bounded JSON record and verify its complete authorization chain.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized or malformed JSON and all errors from [`Self::verify`].
    pub fn decode_and_verify(
        input: &[u8],
        expected_identity: &str,
        now: u64,
        allow_loopback_dev: bool,
        minimum_sequence: Option<u64>,
    ) -> Result<Self> {
        if input.len() > V4_MAX_DEVICE_RECORD_BYTES {
            return Err(ProtocolError::InvalidEncoding("v4 device record size"));
        }
        let record: Self = serde_json::from_slice(input)?;
        record.verify(expected_identity, now, allow_loopback_dev, minimum_sequence)?;
        Ok(record)
    }

    /// Verify every component, exact cross-component bindings, size, and locator rollback floor.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid authorization chain, locator, mismatch, or encoded size.
    pub fn verify(
        &self,
        expected_identity: &str,
        now: u64,
        allow_loopback_dev: bool,
        minimum_sequence: Option<u64>,
    ) -> Result<()> {
        ensure_serialized_bound(self, V4_MAX_DEVICE_RECORD_BYTES, "v4 device record size")?;
        self.certificate
            .verify(&self.authorization, expected_identity, now)?;
        self.locator.verify(
            &self.authorization,
            &self.certificate,
            expected_identity,
            now,
            allow_loopback_dev,
            minimum_sequence,
        )
    }

    /// Canonical, domain-separated digest of the exact self-contained record.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical serialization fails.
    pub fn digest(&self) -> Result<String> {
        canonical_digest(V4_DEVICE_RECORD_DIGEST_DOMAIN, self)
    }

    /// Hash-derived public-storage path for this record.
    ///
    /// # Errors
    ///
    /// Returns an error if either path key is malformed.
    pub fn path(&self) -> Result<String> {
        v4_device_record_path(
            &self.certificate.claims.grant_cnf_key,
            &self.certificate.claims.control_signing_key,
        )
    }
}

/// Initiator-signed v4 connection Hello claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4HelloClaims {
    /// Protocol version.
    pub version: u16,
    /// Exact self-contained initiator publication for offline verification.
    pub from_device_record: V4DeviceRecord,
    /// Initiator Pubky identity.
    pub from_identity: String,
    /// Initiator device id.
    pub from_device_id: String,
    /// Initiator control-signing key.
    pub from_control_signing_key: String,
    /// Initiator iroh endpoint id.
    pub from_iroh_endpoint_id: String,
    /// Intended responder Pubky identity.
    pub to_identity: String,
    /// Intended responder device id.
    pub to_device_id: String,
    /// Intended responder control-signing key.
    pub to_control_signing_key: String,
    /// Intended responder iroh endpoint id.
    pub to_iroh_endpoint_id: String,
    /// Bounded application protocol selected inside the fixed QUIC ALPN.
    pub application: String,
    /// Fixed v4 ALPN.
    pub alpn: String,
    /// Canonical fresh initiator nonce.
    pub session_nonce: String,
    /// Digest of the exact target device record used to connect.
    pub target_device_record_digest: String,
    /// Start of Hello validity.
    pub issued_at: u64,
    /// End of Hello validity.
    pub expires_at: u64,
}

/// Device-control-key-signed v4 connection Hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4SignedHello {
    /// Signed Hello claims.
    pub claims: V4HelloClaims,
    /// Initiator control signature, canonical base64url without padding.
    pub signature: String,
}

impl V4SignedHello {
    /// Create a Hello carrying the exact sender record and binding the exact target record.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid publications, application, nonce, lifetime, or signing.
    pub fn sign(
        credential: &V4DeviceCredential,
        sender_record: &V4DeviceRecord,
        target_record: &V4DeviceRecord,
        application: impl Into<String>,
        session_nonce: impl Into<String>,
        validity: (u64, u64),
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            sender_record,
            target_record,
            application,
            session_nonce,
            validity,
            false,
        )
    }

    /// Create a Hello while explicitly accepting HTTP loopback development locators.
    ///
    /// # Errors
    ///
    /// Returns the same validation and signing errors as [`Self::sign`].
    pub fn sign_for_local_development(
        credential: &V4DeviceCredential,
        sender_record: &V4DeviceRecord,
        target_record: &V4DeviceRecord,
        application: impl Into<String>,
        session_nonce: impl Into<String>,
        validity: (u64, u64),
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            sender_record,
            target_record,
            application,
            session_nonce,
            validity,
            true,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "both exact publications and local-only relay policy are explicit"
    )]
    fn sign_with_policy(
        credential: &V4DeviceCredential,
        sender_record: &V4DeviceRecord,
        target_record: &V4DeviceRecord,
        application: impl Into<String>,
        session_nonce: impl Into<String>,
        validity: (u64, u64),
        allow_loopback_dev: bool,
    ) -> Result<Self> {
        let (issued_at, expires_at) = validity;
        if sender_record.authorization != credential.authorization
            || sender_record.certificate != credential.certificate
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        sender_record.verify(credential.identity(), issued_at, allow_loopback_dev, None)?;
        target_record.verify(
            &target_record.certificate.claims.identity,
            issued_at,
            allow_loopback_dev,
            None,
        )?;
        let sender = &credential.certificate.claims;
        let target = &target_record.certificate.claims;
        let claims = V4HelloClaims {
            version: V4_PROTOCOL_VERSION,
            from_device_record: sender_record.clone(),
            from_identity: sender.identity.clone(),
            from_device_id: sender.device_id.clone(),
            from_control_signing_key: sender.control_signing_key.clone(),
            from_iroh_endpoint_id: sender.iroh_endpoint_id.clone(),
            to_identity: target.identity.clone(),
            to_device_id: target.device_id.clone(),
            to_control_signing_key: target.control_signing_key.clone(),
            to_iroh_endpoint_id: target.iroh_endpoint_id.clone(),
            application: application.into(),
            alpn: V4_IROH_ALPN_TEXT.to_owned(),
            session_nonce: session_nonce.into(),
            target_device_record_digest: target_record.digest()?,
            issued_at,
            expires_at,
        };
        Self::validate_core(
            &claims,
            sender_record,
            target_record,
            &claims.application,
            issued_at,
            allow_loopback_dev,
        )?;
        let signature = credential
            .control_key()?
            .sign(&canonical_for_signing(V4_HELLO_DOMAIN, &claims)?);
        let hello = Self {
            claims,
            signature: encode_signature(&signature),
        };
        ensure_serialized_bound(&hello, V4_MAX_HELLO_BYTES, "v4 Hello size")?;
        Ok(hello)
    }

    fn validate_core(
        claims: &V4HelloClaims,
        sender_record: &V4DeviceRecord,
        target_record: &V4DeviceRecord,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        if claims.version != V4_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(claims.version));
        }
        ensure_serialized_bound(claims, V4_MAX_HELLO_BYTES, "v4 Hello size")?;
        if &claims.from_device_record != sender_record {
            return Err(ProtocolError::DeviceMismatch);
        }
        sender_record.verify(&claims.from_identity, now, allow_loopback_dev, None)?;
        target_record.verify(&claims.to_identity, now, allow_loopback_dev, None)?;
        let sender = &sender_record.certificate.claims;
        let target = &target_record.certificate.claims;
        if claims.from_identity != sender.identity || claims.to_identity != target.identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        if claims.from_device_id != sender.device_id
            || claims.from_control_signing_key != sender.control_signing_key
            || claims.from_iroh_endpoint_id != sender.iroh_endpoint_id
            || claims.to_device_id != target.device_id
            || claims.to_control_signing_key != target.control_signing_key
            || claims.to_iroh_endpoint_id != target.iroh_endpoint_id
            || claims.from_control_signing_key == claims.to_control_signing_key
            || claims.from_iroh_endpoint_id == claims.to_iroh_endpoint_id
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_application(&claims.application)?;
        if claims.application != expected_application {
            return Err(ProtocolError::InvalidEncoding("v4 application binding"));
        }
        if claims.alpn != V4_IROH_ALPN_TEXT {
            return Err(ProtocolError::InvalidEncoding("v4 ALPN"));
        }
        validate_challenge(&claims.session_nonce, "v4 session nonce")?;
        validate_digest(
            &claims.target_device_record_digest,
            "v4 target device digest",
        )?;
        if claims.target_device_record_digest != target_record.digest()? {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_bounded_window(
            claims.issued_at,
            claims.expires_at,
            now,
            V4_MAX_HANDSHAKE_LIFETIME_SECONDS,
            "v4 Hello lifetime",
        )?;
        if claims.issued_at < sender.issued_at
            || claims.issued_at < target.issued_at
            || claims.expires_at > sender.expires_at
            || claims.expires_at > target.expires_at
            || claims.expires_at > sender_record.locator.claims.expires_at
            || claims.expires_at > target_record.locator.claims.expires_at
        {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    fn verify_core(
        &self,
        sender_record: &V4DeviceRecord,
        target_record: &V4DeviceRecord,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        ensure_serialized_bound(self, V4_MAX_HELLO_BYTES, "v4 Hello size")?;
        Self::validate_core(
            &self.claims,
            sender_record,
            target_record,
            expected_application,
            now,
            allow_loopback_dev,
        )?;
        verify_signature(
            &sender_record.certificate.control_public_key()?,
            V4_HELLO_DOMAIN,
            &self.claims,
            &self.signature,
        )
    }

    /// Verify the exact sender and target records, all bindings, lifetime, and signature.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, expired, substituted, cross-device, or tampered Hello.
    pub fn verify(
        &self,
        sender_record: &V4DeviceRecord,
        target_record: &V4DeviceRecord,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        self.verify_core(
            sender_record,
            target_record,
            expected_application,
            now,
            allow_loopback_dev,
        )
    }

    /// Canonical, domain-separated digest bound by Acks and currentness proofs.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical serialization fails.
    pub fn digest(&self) -> Result<String> {
        canonical_digest(V4_HELLO_DIGEST_DOMAIN, self)
    }
}

/// Responder-signed v4 acknowledgement claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4AckClaims {
    /// Protocol version.
    pub version: u16,
    /// Responder Pubky identity.
    pub from_identity: String,
    /// Responder device id.
    pub from_device_id: String,
    /// Responder control-signing key.
    pub from_control_signing_key: String,
    /// Responder iroh endpoint id.
    pub from_iroh_endpoint_id: String,
    /// Initiator Pubky identity.
    pub to_identity: String,
    /// Initiator device id.
    pub to_device_id: String,
    /// Initiator control-signing key.
    pub to_control_signing_key: String,
    /// Initiator iroh endpoint id.
    pub to_iroh_endpoint_id: String,
    /// Application copied exactly from the Hello.
    pub application: String,
    /// Fixed v4 ALPN.
    pub alpn: String,
    /// Initiator nonce copied exactly from the Hello.
    pub session_nonce: String,
    /// Fresh canonical responder nonce.
    pub responder_nonce: String,
    /// Digest of the exact signed Hello.
    pub hello_digest: String,
    /// Digest of the exact responder device record.
    pub responder_device_record_digest: String,
    /// Start of Ack validity.
    pub issued_at: u64,
    /// End of Ack validity.
    pub expires_at: u64,
}

/// Device-control-key-signed acknowledgement of one exact v4 Hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4SignedAck {
    /// Signed acknowledgement claims.
    pub claims: V4AckClaims,
    /// Responder control signature, canonical base64url without padding.
    pub signature: String,
}

impl V4SignedAck {
    /// Sign an Ack after authenticating the exact Hello and both device records.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid Hello/device bindings, nonce, time, or signing.
    pub fn sign(
        credential: &V4DeviceCredential,
        hello: &V4SignedHello,
        initiator_record: &V4DeviceRecord,
        responder_record: &V4DeviceRecord,
        responder_nonce: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            hello,
            initiator_record,
            responder_record,
            responder_nonce,
            (issued_at, expires_at),
            false,
        )
    }

    /// Sign an Ack while explicitly accepting HTTP loopback development locators.
    ///
    /// # Errors
    ///
    /// Returns the same validation and signing errors as [`Self::sign`].
    pub fn sign_for_local_development(
        credential: &V4DeviceCredential,
        hello: &V4SignedHello,
        initiator_record: &V4DeviceRecord,
        responder_record: &V4DeviceRecord,
        responder_nonce: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            hello,
            initiator_record,
            responder_record,
            responder_nonce,
            (issued_at, expires_at),
            true,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "both exact publications and local-only relay policy are explicit"
    )]
    fn sign_with_policy(
        credential: &V4DeviceCredential,
        hello: &V4SignedHello,
        initiator_record: &V4DeviceRecord,
        responder_record: &V4DeviceRecord,
        responder_nonce: impl Into<String>,
        validity: (u64, u64),
        allow_loopback_dev: bool,
    ) -> Result<Self> {
        let (issued_at, expires_at) = validity;
        if responder_record.authorization != credential.authorization
            || responder_record.certificate != credential.certificate
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        hello.verify(
            initiator_record,
            responder_record,
            &hello.claims.application,
            issued_at,
            allow_loopback_dev,
        )?;
        let responder = &responder_record.certificate.claims;
        let initiator = &initiator_record.certificate.claims;
        let claims = V4AckClaims {
            version: V4_PROTOCOL_VERSION,
            from_identity: responder.identity.clone(),
            from_device_id: responder.device_id.clone(),
            from_control_signing_key: responder.control_signing_key.clone(),
            from_iroh_endpoint_id: responder.iroh_endpoint_id.clone(),
            to_identity: initiator.identity.clone(),
            to_device_id: initiator.device_id.clone(),
            to_control_signing_key: initiator.control_signing_key.clone(),
            to_iroh_endpoint_id: initiator.iroh_endpoint_id.clone(),
            application: hello.claims.application.clone(),
            alpn: V4_IROH_ALPN_TEXT.to_owned(),
            session_nonce: hello.claims.session_nonce.clone(),
            responder_nonce: responder_nonce.into(),
            hello_digest: hello.digest()?,
            responder_device_record_digest: responder_record.digest()?,
            issued_at,
            expires_at,
        };
        Self::validate_claims(
            &claims,
            &credential.certificate,
            initiator_record,
            responder_record,
            hello,
            &claims.application,
            issued_at,
            allow_loopback_dev,
        )?;
        let signature = credential
            .control_key()?
            .sign(&canonical_for_signing(V4_ACK_DOMAIN, &claims)?);
        let ack = Self {
            claims,
            signature: encode_signature(&signature),
        };
        ensure_serialized_bound(&ack, V4_MAX_ACK_BYTES, "v4 Ack size")?;
        Ok(ack)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "verification keeps both exact records and application policy explicit"
    )]
    fn validate_claims(
        claims: &V4AckClaims,
        responder_certificate: &V4DeviceCertificate,
        initiator_record: &V4DeviceRecord,
        responder_record: &V4DeviceRecord,
        hello: &V4SignedHello,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        if claims.version != V4_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(claims.version));
        }
        hello.verify_core(
            initiator_record,
            responder_record,
            expected_application,
            now,
            allow_loopback_dev,
        )?;
        if responder_certificate != &responder_record.certificate {
            return Err(ProtocolError::DeviceMismatch);
        }
        let responder = &responder_record.certificate.claims;
        let initiator = &initiator_record.certificate.claims;
        if claims.from_identity != responder.identity || claims.to_identity != initiator.identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        if claims.from_device_id != responder.device_id
            || claims.from_control_signing_key != responder.control_signing_key
            || claims.from_iroh_endpoint_id != responder.iroh_endpoint_id
            || claims.to_device_id != initiator.device_id
            || claims.to_control_signing_key != initiator.control_signing_key
            || claims.to_iroh_endpoint_id != initiator.iroh_endpoint_id
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_application(&claims.application)?;
        if claims.application != expected_application
            || claims.application != hello.claims.application
        {
            return Err(ProtocolError::InvalidEncoding("v4 application binding"));
        }
        if claims.alpn != V4_IROH_ALPN_TEXT || claims.alpn != hello.claims.alpn {
            return Err(ProtocolError::InvalidEncoding("v4 ALPN"));
        }
        validate_challenge(&claims.session_nonce, "v4 session nonce")?;
        validate_challenge(&claims.responder_nonce, "v4 responder nonce")?;
        if claims.session_nonce != hello.claims.session_nonce
            || claims.responder_nonce == claims.session_nonce
        {
            return Err(ProtocolError::InvalidEncoding("v4 nonce binding"));
        }
        validate_digest(&claims.hello_digest, "v4 Hello digest")?;
        validate_digest(
            &claims.responder_device_record_digest,
            "v4 responder device digest",
        )?;
        if claims.hello_digest != hello.digest()?
            || claims.responder_device_record_digest != responder_record.digest()?
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_bounded_window(
            claims.issued_at,
            claims.expires_at,
            now,
            V4_MAX_HANDSHAKE_LIFETIME_SECONDS,
            "v4 Ack lifetime",
        )?;
        if claims.issued_at < hello.claims.issued_at
            || claims.expires_at > hello.claims.expires_at
            || claims.issued_at < responder.issued_at
            || claims.issued_at < initiator.issued_at
            || claims.expires_at > responder.expires_at
            || claims.expires_at > initiator.expires_at
        {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Verify an Ack against both exact records and the exact signed Hello.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, stale, substituted, cross-device, or tampered Acks.
    pub fn verify(
        &self,
        responder_record: &V4DeviceRecord,
        initiator_record: &V4DeviceRecord,
        hello: &V4SignedHello,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        ensure_serialized_bound(self, V4_MAX_ACK_BYTES, "v4 Ack size")?;
        Self::validate_claims(
            &self.claims,
            &responder_record.certificate,
            initiator_record,
            responder_record,
            hello,
            expected_application,
            now,
            allow_loopback_dev,
        )?;
        verify_signature(
            &responder_record.certificate.control_public_key()?,
            V4_ACK_DOMAIN,
            &self.claims,
            &self.signature,
        )
    }
}

/// A participant's role in one currentness-proof exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V4CurrentnessRole {
    /// Peer that signed the Hello.
    Initiator,
    /// Peer that signed the Ack.
    Responder,
}

/// Short-lived currentness claims. No peer Pubky identifier is stored in this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4CurrentnessClaims {
    /// Protocol version.
    pub version: u16,
    /// Signer's handshake role.
    pub role: V4CurrentnessRole,
    /// Fresh shared 128-bit-or-larger challenge.
    pub challenge: String,
    /// Digest of the exact signed Hello.
    pub hello_digest: String,
    /// Digest of the signer's exact device record.
    pub device_record_digest: String,
    /// Digest of the signer's exact root-signed Grant JWS.
    pub grant_digest: String,
    /// Digest of the signer's exact locator.
    pub locator_digest: String,
    /// Start of proof validity.
    pub issued_at: u64,
    /// End of proof validity, at most 30 seconds later.
    pub expires_at: u64,
}

/// Device-control-key-signed currentness proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4SignedCurrentnessProof {
    /// Signed currentness claims.
    pub claims: V4CurrentnessClaims,
    /// Device-control signature, canonical base64url without padding.
    pub signature: String,
}

#[derive(Serialize)]
struct V4CurrentnessPathInput<'a> {
    role: V4CurrentnessRole,
    challenge: &'a str,
    hello_digest: &'a str,
    device_record_digest: &'a str,
    grant_digest: &'a str,
    locator_digest: &'a str,
}

/// Derive the currentness-proof path from values known before fetching the proof.
///
/// This lets a peer compute the remote path from the shared challenge, exact Hello, and exact
/// remote publication. Neither the path nor its hash preimage contains the other peer's Pubky.
///
/// # Errors
///
/// Returns an error if the challenge or any digest is malformed.
pub fn v4_currentness_path(
    role: V4CurrentnessRole,
    challenge: &str,
    hello_digest: &str,
    device_record_digest: &str,
    grant_digest: &str,
    locator_digest: &str,
) -> Result<String> {
    validate_challenge(challenge, "v4 currentness challenge")?;
    validate_digest(hello_digest, "v4 Hello digest")?;
    validate_digest(device_record_digest, "v4 device record digest")?;
    validate_digest(grant_digest, "v4 Grant digest")?;
    validate_digest(locator_digest, "v4 locator digest")?;
    let input = V4CurrentnessPathInput {
        role,
        challenge,
        hello_digest,
        device_record_digest,
        grant_digest,
        locator_digest,
    };
    let digest = canonical_digest(V4_CURRENTNESS_PATH_DOMAIN, &input)?;
    Ok(format!("{V4_CURRENTNESS_PATH_PREFIX}{digest}.json"))
}

fn records_for_role<'a>(
    role: V4CurrentnessRole,
    own_record: &'a V4DeviceRecord,
    peer_record: &'a V4DeviceRecord,
) -> (&'a V4DeviceRecord, &'a V4DeviceRecord) {
    match role {
        V4CurrentnessRole::Initiator => (own_record, peer_record),
        V4CurrentnessRole::Responder => (peer_record, own_record),
    }
}

impl V4SignedCurrentnessProof {
    /// Sign a fresh proof for the exact Hello and the signer's exact current publication.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid records, Hello, challenge, lifetime, role, or signing.
    #[allow(
        clippy::too_many_arguments,
        reason = "mutual-proof role, exact records, challenge, and validity are explicit"
    )]
    pub fn sign(
        credential: &V4DeviceCredential,
        own_record: &V4DeviceRecord,
        peer_record: &V4DeviceRecord,
        hello: &V4SignedHello,
        role: V4CurrentnessRole,
        challenge: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        allow_loopback_dev: bool,
    ) -> Result<Self> {
        if own_record.authorization != credential.authorization
            || own_record.certificate != credential.certificate
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        let (initiator_record, responder_record) = records_for_role(role, own_record, peer_record);
        hello.verify(
            initiator_record,
            responder_record,
            &hello.claims.application,
            issued_at,
            allow_loopback_dev,
        )?;
        let claims = V4CurrentnessClaims {
            version: V4_PROTOCOL_VERSION,
            role,
            challenge: challenge.into(),
            hello_digest: hello.digest()?,
            device_record_digest: own_record.digest()?,
            grant_digest: own_record.authorization.digest()?,
            locator_digest: own_record.locator.digest()?,
            issued_at,
            expires_at,
        };
        Self::validate_claims(
            &claims,
            own_record,
            peer_record,
            hello,
            role,
            &claims.challenge,
            issued_at,
            allow_loopback_dev,
        )?;
        let signature = credential
            .control_key()?
            .sign(&canonical_for_signing(V4_CURRENTNESS_DOMAIN, &claims)?);
        let proof = Self {
            claims,
            signature: encode_signature(&signature),
        };
        ensure_serialized_bound(
            &proof,
            V4_MAX_CURRENTNESS_PROOF_BYTES,
            "v4 currentness proof size",
        )?;
        Ok(proof)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "mutual-proof role, exact records, and expected challenge are explicit"
    )]
    fn validate_claims(
        claims: &V4CurrentnessClaims,
        own_record: &V4DeviceRecord,
        peer_record: &V4DeviceRecord,
        hello: &V4SignedHello,
        expected_role: V4CurrentnessRole,
        expected_challenge: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        if claims.version != V4_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(claims.version));
        }
        if claims.role != expected_role {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_challenge(&claims.challenge, "v4 currentness challenge")?;
        if claims.challenge != expected_challenge || claims.challenge == hello.claims.session_nonce
        {
            return Err(ProtocolError::InvalidEncoding(
                "v4 currentness challenge binding",
            ));
        }
        let (initiator_record, responder_record) =
            records_for_role(expected_role, own_record, peer_record);
        hello.verify(
            initiator_record,
            responder_record,
            &hello.claims.application,
            now,
            allow_loopback_dev,
        )?;
        validate_digest(&claims.hello_digest, "v4 Hello digest")?;
        validate_digest(&claims.device_record_digest, "v4 device record digest")?;
        validate_digest(&claims.grant_digest, "v4 Grant digest")?;
        validate_digest(&claims.locator_digest, "v4 locator digest")?;
        if claims.hello_digest != hello.digest()?
            || claims.device_record_digest != own_record.digest()?
            || claims.grant_digest != own_record.authorization.digest()?
            || claims.locator_digest != own_record.locator.digest()?
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_currentness_window(claims.issued_at, claims.expires_at, now)?;
        if claims.issued_at < hello.claims.issued_at
            || claims.expires_at > hello.claims.expires_at
            || claims.expires_at > own_record.locator.claims.expires_at
        {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Verify one side of a mutual currentness exchange.
    ///
    /// Both peers must verify one proof with the same fresh challenge and opposite roles before
    /// treating homeserver publications as current.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid role, challenge, digest, record, lifetime, or signature.
    #[allow(
        clippy::too_many_arguments,
        reason = "mutual-proof role, exact records, and expected challenge are explicit"
    )]
    pub fn verify(
        &self,
        own_record: &V4DeviceRecord,
        peer_record: &V4DeviceRecord,
        hello: &V4SignedHello,
        expected_role: V4CurrentnessRole,
        expected_challenge: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        ensure_serialized_bound(
            self,
            V4_MAX_CURRENTNESS_PROOF_BYTES,
            "v4 currentness proof size",
        )?;
        Self::validate_claims(
            &self.claims,
            own_record,
            peer_record,
            hello,
            expected_role,
            expected_challenge,
            now,
            allow_loopback_dev,
        )?;
        verify_signature(
            &own_record.certificate.control_public_key()?,
            V4_CURRENTNESS_DOMAIN,
            &self.claims,
            &self.signature,
        )
    }

    /// Hash-derived public-storage path binding every currentness-proof digest and challenge.
    ///
    /// The path contains no peer Pubky identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the challenge or any digest is malformed.
    pub fn path(&self) -> Result<String> {
        v4_currentness_path(
            self.claims.role,
            &self.claims.challenge,
            &self.claims.hello_digest,
            &self.claims.device_record_digest,
            &self.claims.grant_digest,
            &self.claims.locator_digest,
        )
    }
}
