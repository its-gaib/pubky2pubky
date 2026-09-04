//! Pubky-authenticated iroh discovery and handshake protocol, version 3.
//!
//! Version 3 intentionally has no custom rendezvous or HPKE signaling layer. A Pubky root key
//! delegates independent control-signing and iroh endpoint keys to a device. Public Pubky storage
//! contains a bounded root-signed device directory and one short-lived, device-signed locator per
//! control key. Locators disclose relay URLs, never direct network addresses.

use std::{collections::BTreeSet, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;
use pubky_common::crypto::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    MAX_CERTIFICATE_LIFETIME_SECONDS, ProtocolError, Result,
    identity::{canonical_for_signing, encode_signature, parse_public_key, validate_window},
};

/// Pubky-to-iroh protocol version implemented by this module.
pub const V3_PROTOCOL_VERSION: u16 = 3;

/// Fixed public-storage path for the root-signed device directory.
pub const V3_DIRECTORY_PATH: &str = "/pub/pubky2pubky/v3/directory.json";

/// Fixed public-storage directory for per-device locators.
pub const V3_LOCATOR_PATH_PREFIX: &str = "/pub/pubky2pubky/v3/locators/";

/// Text representation of the fixed v3 QUIC ALPN.
pub const V3_IROH_ALPN_TEXT: &str = "pubky2pubky/iroh/v3";

/// Fixed v3 QUIC ALPN bytes passed to iroh.
pub const V3_IROH_ALPN: &[u8] = b"pubky2pubky/iroh/v3";

/// Exact operations delegated to every v3 device control key.
pub const V3_DEVICE_CAPABILITIES: [&str; 2] = ["publish-locator", "sign-handshake"];

/// Maximum devices advertised by one identity.
pub const V3_MAX_CERTIFICATES: usize = 8;

/// Maximum iroh relay URLs in one locator.
pub const V3_MAX_RELAY_URLS: usize = 4;

/// Maximum root-signed directory lifetime.
///
/// This matches the bounded device-certificate horizon so an offline root does not need to be
/// brought online merely to refresh an unchanged directory.
pub const V3_MAX_DIRECTORY_LIFETIME_SECONDS: u64 = MAX_CERTIFICATE_LIFETIME_SECONDS;

/// Maximum device-signed locator lifetime.
pub const V3_MAX_LOCATOR_LIFETIME_SECONDS: u64 = 15 * 60;

/// Maximum Hello or Ack lifetime.
pub const V3_MAX_HANDSHAKE_LIFETIME_SECONDS: u64 = 2 * 60;

const V3_CERTIFICATE_DOMAIN: &str = "pubky2pubky/device-certificate/v3";
const V3_DIRECTORY_DOMAIN: &str = "pubky2pubky/device-directory/v3";
const V3_LOCATOR_DOMAIN: &str = "pubky2pubky/iroh-locator/v3";
const V3_LOCATOR_DIGEST_DOMAIN: &str = "pubky2pubky/iroh-locator-digest/v3";
const V3_HELLO_DOMAIN: &str = "pubky2pubky/hello/v3";
const V3_HELLO_DIGEST_DOMAIN: &str = "pubky2pubky/hello-digest/v3";
const V3_ACK_DOMAIN: &str = "pubky2pubky/ack/v3";
const MAX_DEVICE_ID_BYTES: usize = 64;
const MAX_APPLICATION_BYTES: usize = 128;
const MIN_NONCE_BYTES: usize = 16;
const MAX_NONCE_BYTES: usize = 32;

fn decode_v3_signature(encoded: &str) -> Result<Signature> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidEncoding("v3 signature"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(ProtocolError::InvalidEncoding("canonical v3 signature"));
    }
    Signature::from_slice(&bytes).map_err(|_| ProtocolError::InvalidEncoding("v3 signature"))
}

fn validate_bounded_window(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    maximum: u64,
    label: &'static str,
) -> Result<()> {
    validate_window(issued_at, expires_at, now)?;
    if expires_at - issued_at > maximum {
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
        return Err(ProtocolError::InvalidEncoding("v3 device id"));
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
        return Err(ProtocolError::InvalidEncoding("v3 application"));
    }
    Ok(())
}

fn validate_nonce(encoded: &str, label: &'static str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidEncoding(label))?;
    if !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&bytes.len())
        || URL_SAFE_NO_PAD.encode(&bytes) != encoded
    {
        return Err(ProtocolError::InvalidEncoding(label));
    }
    Ok(())
}

fn validate_digest(encoded: &str, label: &'static str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidEncoding(label))?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(ProtocolError::InvalidEncoding(label));
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let bytes = canonical_for_signing(domain, value)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

fn exact_capabilities(capabilities: &[String]) -> bool {
    capabilities.len() == V3_DEVICE_CAPABILITIES.len()
        && capabilities
            .iter()
            .map(String::as_str)
            .eq(V3_DEVICE_CAPABILITIES)
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
    if (!secure && !loopback_dev)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProtocolError::InvalidEncoding("v3 relay URL"));
    }
    Ok(())
}

fn validate_relays(relays: &[Url], allow_loopback_dev: bool) -> Result<()> {
    if relays.is_empty() || relays.len() > V3_MAX_RELAY_URLS {
        return Err(ProtocolError::InvalidEncoding("v3 relay URLs"));
    }
    let mut unique = BTreeSet::new();
    for relay in relays {
        validate_relay_url(relay, allow_loopback_dev)?;
        if !unique.insert(relay.as_str()) {
            return Err(ProtocolError::InvalidEncoding("duplicate v3 relay URL"));
        }
    }
    Ok(())
}

fn verify_signature(
    key: &PublicKey,
    domain: &str,
    claims: &impl Serialize,
    value: &str,
) -> Result<()> {
    let signature = decode_v3_signature(value)?;
    key.verify(&canonical_for_signing(domain, claims)?, &signature)
        .map_err(|_| ProtocolError::BadSignature)
}

/// Generate a canonical 256-bit base64url nonce suitable for locators and handshakes.
#[must_use]
pub fn v3_random_nonce() -> String {
    let random = Keypair::random();
    let secret = Zeroizing::new(random.secret());
    URL_SAFE_NO_PAD.encode(&secret[..])
}

/// Derive a fixed-alphabet public-storage path from a canonical control-signing key.
///
/// Device ids are deliberately never used in locator paths.
///
/// # Errors
///
/// Returns an error unless `control_signing_key` is a canonical Pubky/Ed25519 z-base-32 key.
pub fn v3_locator_path(control_signing_key: &str) -> Result<String> {
    parse_public_key(control_signing_key)?;
    Ok(format!(
        "{V3_LOCATOR_PATH_PREFIX}{control_signing_key}.json"
    ))
}

/// Root-signed stable delegation claims for one v3 device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3DeviceCertificateClaims {
    /// Protocol version.
    pub version: u16,
    /// Canonical Pubky root identity.
    pub identity: String,
    /// Bounded display-oriented device identifier; never used as a storage path component.
    pub device_id: String,
    /// Independent online Ed25519 control-signing public key.
    pub control_signing_key: String,
    /// Independent iroh endpoint id.
    pub iroh_endpoint_id: String,
    /// Start of the delegation validity window.
    pub issued_at: u64,
    /// End of the delegation validity window.
    pub expires_at: u64,
    /// Exact operations delegated to the control key.
    pub capabilities: Vec<String>,
}

/// Pubky-root-signed v3 device delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3DeviceCertificate {
    /// Delegated public claims.
    pub claims: V3DeviceCertificateClaims,
    /// Pubky root signature, canonical base64url without padding.
    pub signature: String,
}

impl V3DeviceCertificate {
    /// Verify version, exact capabilities, bindings, lifetime, and Pubky root signature.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, expired, cross-identity, overlong, or tampered claims.
    pub fn verify(&self, expected_identity: &str, now: u64) -> Result<()> {
        let expected_root = parse_public_key(expected_identity)?;
        if self.claims.version != V3_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.claims.version));
        }
        if self.claims.identity != expected_identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        validate_bounded_window(
            self.claims.issued_at,
            self.claims.expires_at,
            now,
            MAX_CERTIFICATE_LIFETIME_SECONDS,
            "v3 certificate lifetime",
        )?;
        validate_device_id(&self.claims.device_id)?;
        if !exact_capabilities(&self.claims.capabilities) {
            return Err(ProtocolError::InvalidEncoding("v3 device capabilities"));
        }
        let control = parse_public_key(&self.claims.control_signing_key)?;
        let iroh = parse_public_key(&self.claims.iroh_endpoint_id)?;
        if control == iroh || control == expected_root || iroh == expected_root {
            return Err(ProtocolError::InvalidEncoding("independent v3 device keys"));
        }
        verify_signature(
            &expected_root,
            V3_CERTIFICATE_DOMAIN,
            &self.claims,
            &self.signature,
        )
    }

    fn control_public_key(&self) -> Result<PublicKey> {
        parse_public_key(&self.claims.control_signing_key)
    }
}

/// Serializable v3 device secrets. Persist only with owner-only file permissions.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct V3DeviceCredential {
    /// Root-signed public device delegation.
    #[zeroize(skip)]
    pub certificate: V3DeviceCertificate,
    /// Ed25519 control-signing secret, canonical base64url without padding.
    control_signing_secret: String,
    /// Independent iroh Ed25519 secret, canonical base64url without padding.
    iroh_secret: String,
}

impl fmt::Debug for V3DeviceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V3DeviceCredential")
            .field("certificate", &self.certificate)
            .field("control_signing_secret", &"[REDACTED]")
            .field("iroh_secret", &"[REDACTED]")
            .finish()
    }
}

impl V3DeviceCredential {
    /// Issue fresh, independent control and iroh keys under a Pubky root identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid device id or validity interval.
    pub fn issue(
        root: &Keypair,
        device_id: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        validate_bounded_window(
            issued_at,
            expires_at,
            issued_at,
            MAX_CERTIFICATE_LIFETIME_SECONDS,
            "v3 certificate lifetime",
        )?;
        let device_id = device_id.into();
        validate_device_id(&device_id)?;

        let control = Keypair::random();
        let iroh = Keypair::random();
        let control_secret = Zeroizing::new(control.secret());
        let iroh_secret = Zeroizing::new(iroh.secret());
        let claims = V3DeviceCertificateClaims {
            version: V3_PROTOCOL_VERSION,
            identity: root.public_key().z32(),
            device_id,
            control_signing_key: control.public_key().z32(),
            iroh_endpoint_id: iroh.public_key().z32(),
            issued_at,
            expires_at,
            capabilities: V3_DEVICE_CAPABILITIES.map(str::to_owned).to_vec(),
        };
        let signature = root.sign(&canonical_for_signing(V3_CERTIFICATE_DOMAIN, &claims)?);
        Ok(Self {
            certificate: V3DeviceCertificate {
                claims,
                signature: encode_signature(&signature),
            },
            control_signing_secret: URL_SAFE_NO_PAD.encode(&control_secret[..]),
            iroh_secret: URL_SAFE_NO_PAD.encode(&iroh_secret[..]),
        })
    }

    /// Pubky identity that delegated this credential.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.certificate.claims.identity
    }

    /// Stable display-oriented device id.
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
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| ProtocolError::InvalidEncoding(label))?,
        );
        if URL_SAFE_NO_PAD.encode(&bytes[..]) != encoded {
            return Err(ProtocolError::InvalidEncoding(label));
        }
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
            "v3 control-signing secret",
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
            Self::decode_secret(&self.iroh_secret, self.iroh_endpoint_id(), "v3 iroh secret")?;
        Ok(Zeroizing::new(key.secret()))
    }
}

/// Root-signed v3 device-directory claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3DeviceDirectoryClaims {
    /// Protocol version.
    pub version: u16,
    /// Canonical Pubky identity that owns every listed device.
    pub identity: String,
    /// Positive monotonic publication generation.
    pub generation: u64,
    /// Root-signed certificates sorted by control-signing key.
    pub devices: Vec<V3DeviceCertificate>,
    /// Start of directory validity.
    pub issued_at: u64,
    /// End of directory validity.
    pub expires_at: u64,
}

/// Root-signed, bounded directory of active v3 devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3DeviceDirectory {
    /// Directory claims.
    pub claims: V3DeviceDirectoryClaims,
    /// Pubky root signature, canonical base64url without padding.
    pub signature: String,
}

impl V3DeviceDirectory {
    /// Sign a bounded device directory, sorting certificates by control key.
    ///
    /// An empty directory is valid and revokes all discoverable devices.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid generation, lifetime, certificates, duplicates, or encoding.
    pub fn sign(
        root: &Keypair,
        generation: u64,
        mut devices: Vec<V3DeviceCertificate>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        devices.sort_by(|left, right| {
            left.claims
                .control_signing_key
                .cmp(&right.claims.control_signing_key)
        });
        let claims = V3DeviceDirectoryClaims {
            version: V3_PROTOCOL_VERSION,
            identity: root.public_key().z32(),
            generation,
            devices,
            issued_at,
            expires_at,
        };
        Self::validate_claims(&claims, &claims.identity, issued_at, None)?;
        let signature = root.sign(&canonical_for_signing(V3_DIRECTORY_DOMAIN, &claims)?);
        Ok(Self {
            claims,
            signature: encode_signature(&signature),
        })
    }

    fn validate_claims(
        claims: &V3DeviceDirectoryClaims,
        expected_identity: &str,
        now: u64,
        minimum_generation: Option<u64>,
    ) -> Result<()> {
        if claims.version != V3_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(claims.version));
        }
        parse_public_key(expected_identity)?;
        if claims.identity != expected_identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        if claims.generation == 0
            || minimum_generation.is_some_and(|minimum| claims.generation < minimum)
        {
            return Err(ProtocolError::InvalidEncoding("v3 directory generation"));
        }
        validate_bounded_window(
            claims.issued_at,
            claims.expires_at,
            now,
            V3_MAX_DIRECTORY_LIFETIME_SECONDS,
            "v3 directory lifetime",
        )?;
        if claims.devices.len() > V3_MAX_CERTIFICATES {
            return Err(ProtocolError::InvalidEncoding("v3 device directory size"));
        }

        let mut device_ids = BTreeSet::new();
        let mut control_keys = BTreeSet::new();
        let mut endpoint_ids = BTreeSet::new();
        let mut previous_control: Option<&str> = None;
        for certificate in &claims.devices {
            certificate.verify(expected_identity, now)?;
            if certificate.claims.issued_at > claims.issued_at
                || certificate.claims.expires_at < claims.expires_at
            {
                return Err(ProtocolError::InvalidTimeWindow);
            }
            let control = certificate.claims.control_signing_key.as_str();
            if previous_control.is_some_and(|previous| previous >= control) {
                return Err(ProtocolError::InvalidEncoding("v3 directory ordering"));
            }
            previous_control = Some(control);
            if !device_ids.insert(certificate.claims.device_id.as_str())
                || !control_keys.insert(control)
                || !endpoint_ids.insert(certificate.claims.iroh_endpoint_id.as_str())
            {
                return Err(ProtocolError::InvalidEncoding("duplicate v3 device"));
            }
        }
        Ok(())
    }

    /// Verify the root signature, all contained certificates, bounds, ordering, and generation.
    ///
    /// `minimum_generation` is a rollback floor: re-reading an equal generation is allowed.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed, expired, stale, cross-identity, or tampered value.
    pub fn verify(
        &self,
        expected_identity: &str,
        now: u64,
        minimum_generation: Option<u64>,
    ) -> Result<()> {
        Self::validate_claims(&self.claims, expected_identity, now, minimum_generation)?;
        let root = parse_public_key(expected_identity)?;
        verify_signature(&root, V3_DIRECTORY_DOMAIN, &self.claims, &self.signature)
    }

    /// Find one listed certificate by its canonical control-signing key.
    #[must_use]
    pub fn device_by_control_key(&self, control_signing_key: &str) -> Option<&V3DeviceCertificate> {
        self.claims
            .devices
            .iter()
            .find(|certificate| certificate.claims.control_signing_key == control_signing_key)
    }
}

/// Device-signed, short-lived iroh locator claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3LocatorClaims {
    /// Protocol version.
    pub version: u16,
    /// Pubky identity owning the device.
    pub identity: String,
    /// Certified device id.
    pub device_id: String,
    /// Certified control-signing key.
    pub control_signing_key: String,
    /// Certified iroh endpoint id.
    pub iroh_endpoint_id: String,
    /// Initial-contact iroh relay URLs; direct addresses are never published.
    pub relay_urls: Vec<Url>,
    /// Fixed v3 application-layer protocol identifier.
    pub alpn: String,
    /// Canonical random 128-bit-or-larger endpoint-instance nonce.
    pub instance_nonce: String,
    /// Positive monotonic locator publication sequence.
    pub sequence: u64,
    /// Start of locator validity.
    pub issued_at: u64,
    /// End of locator validity.
    pub expires_at: u64,
}

/// Control-key-signed v3 iroh locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3SignedLocator {
    /// Signed locator claims.
    pub claims: V3LocatorClaims,
    /// Device control signature, canonical base64url without padding.
    pub signature: String,
}

impl V3SignedLocator {
    /// Sign a relay-only locator with the delegated device control key.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed relays/nonces, invalid sequence/lifetime, certificate
    /// mismatch, or encoding failure.
    pub fn sign(
        credential: &V3DeviceCredential,
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

    /// Sign a relay-only locator while explicitly allowing an HTTP loopback relay.
    ///
    /// Use only for local development. The resulting locator is rejected by production
    /// verification (`allow_loopback_dev = false`).
    ///
    /// # Errors
    ///
    /// Returns the same validation and signing errors as [`Self::sign`].
    pub fn sign_for_local_development(
        credential: &V3DeviceCredential,
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
        credential: &V3DeviceCredential,
        relay_urls: Vec<Url>,
        instance_nonce: impl Into<String>,
        sequence: u64,
        validity: (u64, u64),
        allow_loopback_dev: bool,
    ) -> Result<Self> {
        let (issued_at, expires_at) = validity;
        credential
            .certificate
            .verify(credential.identity(), issued_at)?;
        let claims = V3LocatorClaims {
            version: V3_PROTOCOL_VERSION,
            identity: credential.identity().to_owned(),
            device_id: credential.device_id().to_owned(),
            control_signing_key: credential.control_signing_key().to_owned(),
            iroh_endpoint_id: credential.iroh_endpoint_id().to_owned(),
            relay_urls,
            alpn: V3_IROH_ALPN_TEXT.to_owned(),
            instance_nonce: instance_nonce.into(),
            sequence,
            issued_at,
            expires_at,
        };
        Self::validate_claims(
            &claims,
            &credential.certificate,
            credential.identity(),
            issued_at,
            allow_loopback_dev,
            None,
        )?;
        let signature = credential
            .control_key()?
            .sign(&canonical_for_signing(V3_LOCATOR_DOMAIN, &claims)?);
        Ok(Self {
            claims,
            signature: encode_signature(&signature),
        })
    }

    fn validate_claims(
        claims: &V3LocatorClaims,
        certificate: &V3DeviceCertificate,
        expected_identity: &str,
        now: u64,
        allow_loopback_dev: bool,
        minimum_sequence: Option<u64>,
    ) -> Result<()> {
        if claims.version != V3_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(claims.version));
        }
        certificate.verify(expected_identity, now)?;
        if claims.identity != expected_identity || claims.identity != certificate.claims.identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        if claims.device_id != certificate.claims.device_id
            || claims.control_signing_key != certificate.claims.control_signing_key
            || claims.iroh_endpoint_id != certificate.claims.iroh_endpoint_id
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        if claims.alpn != V3_IROH_ALPN_TEXT {
            return Err(ProtocolError::InvalidEncoding("v3 ALPN"));
        }
        if claims.sequence == 0 || minimum_sequence.is_some_and(|minimum| claims.sequence < minimum)
        {
            return Err(ProtocolError::InvalidEncoding("v3 locator sequence"));
        }
        validate_nonce(&claims.instance_nonce, "v3 instance nonce")?;
        validate_relays(&claims.relay_urls, allow_loopback_dev)?;
        validate_bounded_window(
            claims.issued_at,
            claims.expires_at,
            now,
            V3_MAX_LOCATOR_LIFETIME_SECONDS,
            "v3 locator lifetime",
        )?;
        if claims.issued_at < certificate.claims.issued_at
            || claims.expires_at > certificate.claims.expires_at
        {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Verify the certificate, exact bindings, relay policy, rollback floor, and signature.
    ///
    /// `minimum_sequence` accepts an equal sequence when re-reading the same publication.
    /// Set `allow_loopback_dev` only for an explicitly local development environment.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, expired, stale, cross-device, or tampered locators.
    pub fn verify(
        &self,
        certificate: &V3DeviceCertificate,
        expected_identity: &str,
        now: u64,
        allow_loopback_dev: bool,
        minimum_sequence: Option<u64>,
    ) -> Result<()> {
        Self::validate_claims(
            &self.claims,
            certificate,
            expected_identity,
            now,
            allow_loopback_dev,
            minimum_sequence,
        )?;
        verify_signature(
            &certificate.control_public_key()?,
            V3_LOCATOR_DOMAIN,
            &self.claims,
            &self.signature,
        )
    }

    /// Canonical, domain-separated SHA-256 digest used by v3 Hello messages.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical serialization fails.
    pub fn digest(&self) -> Result<String> {
        canonical_digest(V3_LOCATOR_DIGEST_DOMAIN, self)
    }

    /// Public-storage path derived only from the certified control-signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not canonical.
    pub fn path(&self) -> Result<String> {
        v3_locator_path(&self.claims.control_signing_key)
    }
}

/// Initiator-signed v3 connection Hello claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3HelloClaims {
    /// Protocol version.
    pub version: u16,
    /// Exact Pubky-root-signed initiator device certificate presented for offline verification.
    pub from_certificate: V3DeviceCertificate,
    /// Exact device-signed initiator locator that must still be current when consent is granted.
    pub from_locator: V3SignedLocator,
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
    /// Fixed v3 ALPN.
    pub alpn: String,
    /// Canonical random initiator nonce.
    pub session_nonce: String,
    /// Canonical digest of the exact target locator used to connect.
    pub target_locator_digest: String,
    /// Start of Hello validity.
    pub issued_at: u64,
    /// End of Hello validity.
    pub expires_at: u64,
}

/// Device-control-key-signed connection Hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3SignedHello {
    /// Signed Hello claims.
    pub claims: V3HelloClaims,
    /// Initiator control signature, canonical base64url without padding.
    pub signature: String,
}

impl V3SignedHello {
    /// Create a Hello carrying and binding the exact sender certificate and locator, the target
    /// certificate, and the exact target locator.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid certificates, locator, application, nonce, time, or signing.
    pub fn sign(
        credential: &V3DeviceCredential,
        sender_locator: &V3SignedLocator,
        target_certificate: &V3DeviceCertificate,
        target_locator: &V3SignedLocator,
        application: impl Into<String>,
        session_nonce: impl Into<String>,
        validity: (u64, u64),
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            sender_locator,
            target_certificate,
            target_locator,
            application,
            session_nonce,
            validity,
            false,
        )
    }

    /// Create a Hello while explicitly accepting HTTP loopback sender and target locators.
    ///
    /// Use only for a local-development transport configuration.
    ///
    /// # Errors
    ///
    /// Returns the same validation and signing errors as [`Self::sign`].
    pub fn sign_for_local_development(
        credential: &V3DeviceCredential,
        sender_locator: &V3SignedLocator,
        target_certificate: &V3DeviceCertificate,
        target_locator: &V3SignedLocator,
        application: impl Into<String>,
        session_nonce: impl Into<String>,
        validity: (u64, u64),
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            sender_locator,
            target_certificate,
            target_locator,
            application,
            session_nonce,
            validity,
            true,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "keeps both signed device publications and local-only relay policy explicit"
    )]
    fn sign_with_policy(
        credential: &V3DeviceCredential,
        sender_locator: &V3SignedLocator,
        target_certificate: &V3DeviceCertificate,
        target_locator: &V3SignedLocator,
        application: impl Into<String>,
        session_nonce: impl Into<String>,
        validity: (u64, u64),
        allow_loopback_dev: bool,
    ) -> Result<Self> {
        let (issued_at, expires_at) = validity;
        credential
            .certificate
            .verify(credential.identity(), issued_at)?;
        sender_locator.verify(
            &credential.certificate,
            credential.identity(),
            issued_at,
            allow_loopback_dev,
            None,
        )?;
        target_certificate.verify(&target_certificate.claims.identity, issued_at)?;
        target_locator.verify(
            target_certificate,
            &target_certificate.claims.identity,
            issued_at,
            allow_loopback_dev,
            None,
        )?;
        let claims = V3HelloClaims {
            version: V3_PROTOCOL_VERSION,
            from_certificate: credential.certificate.clone(),
            from_locator: sender_locator.clone(),
            from_identity: credential.identity().to_owned(),
            from_device_id: credential.device_id().to_owned(),
            from_control_signing_key: credential.control_signing_key().to_owned(),
            from_iroh_endpoint_id: credential.iroh_endpoint_id().to_owned(),
            to_identity: target_certificate.claims.identity.clone(),
            to_device_id: target_certificate.claims.device_id.clone(),
            to_control_signing_key: target_certificate.claims.control_signing_key.clone(),
            to_iroh_endpoint_id: target_certificate.claims.iroh_endpoint_id.clone(),
            application: application.into(),
            alpn: V3_IROH_ALPN_TEXT.to_owned(),
            session_nonce: session_nonce.into(),
            target_locator_digest: target_locator.digest()?,
            issued_at,
            expires_at,
        };
        Self::validate_core(
            &claims,
            &credential.certificate,
            target_certificate,
            &claims.application,
            issued_at,
            allow_loopback_dev,
        )?;
        if claims.target_locator_digest != target_locator.digest()?
            || claims.expires_at > sender_locator.claims.expires_at
            || claims.expires_at > target_locator.claims.expires_at
        {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        let signature = credential
            .control_key()?
            .sign(&canonical_for_signing(V3_HELLO_DOMAIN, &claims)?);
        Ok(Self {
            claims,
            signature: encode_signature(&signature),
        })
    }

    fn validate_core(
        claims: &V3HelloClaims,
        sender_certificate: &V3DeviceCertificate,
        target_certificate: &V3DeviceCertificate,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        if claims.version != V3_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(claims.version));
        }
        sender_certificate.verify(&claims.from_identity, now)?;
        if &claims.from_certificate != sender_certificate {
            return Err(ProtocolError::DeviceMismatch);
        }
        claims.from_locator.verify(
            sender_certificate,
            &claims.from_identity,
            now,
            allow_loopback_dev,
            None,
        )?;
        target_certificate.verify(&claims.to_identity, now)?;
        let sender = &sender_certificate.claims;
        let target = &target_certificate.claims;
        if claims.from_identity != sender.identity || claims.to_identity != target.identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        if claims.from_device_id != sender.device_id
            || claims.from_control_signing_key != sender.control_signing_key
            || claims.from_iroh_endpoint_id != sender.iroh_endpoint_id
            || claims.from_locator.claims.control_signing_key != sender.control_signing_key
            || claims.from_locator.claims.iroh_endpoint_id != sender.iroh_endpoint_id
            || claims.to_device_id != target.device_id
            || claims.to_control_signing_key != target.control_signing_key
            || claims.to_iroh_endpoint_id != target.iroh_endpoint_id
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        if claims.from_control_signing_key == claims.to_control_signing_key
            || claims.from_iroh_endpoint_id == claims.to_iroh_endpoint_id
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_application(&claims.application)?;
        if claims.application != expected_application {
            return Err(ProtocolError::InvalidEncoding("v3 application binding"));
        }
        if claims.alpn != V3_IROH_ALPN_TEXT {
            return Err(ProtocolError::InvalidEncoding("v3 ALPN"));
        }
        validate_nonce(&claims.session_nonce, "v3 session nonce")?;
        validate_digest(&claims.target_locator_digest, "v3 locator digest")?;
        validate_bounded_window(
            claims.issued_at,
            claims.expires_at,
            now,
            V3_MAX_HANDSHAKE_LIFETIME_SECONDS,
            "v3 Hello lifetime",
        )?;
        if claims.issued_at < sender.issued_at
            || claims.issued_at < target.issued_at
            || claims.expires_at > sender.expires_at
            || claims.expires_at > claims.from_locator.claims.expires_at
            || claims.expires_at > target.expires_at
        {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    fn verify_core(
        &self,
        sender_certificate: &V3DeviceCertificate,
        target_certificate: &V3DeviceCertificate,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        Self::validate_core(
            &self.claims,
            sender_certificate,
            target_certificate,
            expected_application,
            now,
            allow_loopback_dev,
        )?;
        verify_signature(
            &sender_certificate.control_public_key()?,
            V3_HELLO_DOMAIN,
            &self.claims,
            &self.signature,
        )
    }

    /// Verify a Hello against its exact embedded sender certificate and locator, the supplied
    /// target certificate, and the exact target locator.
    ///
    /// # Errors
    ///
    /// Returns an error for any invalid binding, lifetime, locator digest, or signature.
    pub fn verify(
        &self,
        sender_certificate: &V3DeviceCertificate,
        target_certificate: &V3DeviceCertificate,
        target_locator: &V3SignedLocator,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        self.verify_core(
            sender_certificate,
            target_certificate,
            expected_application,
            now,
            allow_loopback_dev,
        )?;
        target_locator.verify(
            target_certificate,
            &self.claims.to_identity,
            now,
            allow_loopback_dev,
            None,
        )?;
        if self.claims.target_locator_digest != target_locator.digest()? {
            return Err(ProtocolError::DeviceMismatch);
        }
        if self.claims.expires_at > target_locator.claims.expires_at {
            return Err(ProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Canonical, domain-separated SHA-256 digest bound by an Ack.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical serialization fails.
    pub fn digest(&self) -> Result<String> {
        canonical_digest(V3_HELLO_DIGEST_DOMAIN, self)
    }
}

/// Responder-signed v3 acknowledgement claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3AckClaims {
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
    /// Fixed v3 ALPN.
    pub alpn: String,
    /// Initiator nonce copied exactly from the Hello.
    pub session_nonce: String,
    /// Fresh canonical responder nonce.
    pub responder_nonce: String,
    /// Canonical digest of the exact signed Hello.
    pub hello_digest: String,
    /// Start of Ack validity.
    pub issued_at: u64,
    /// End of Ack validity.
    pub expires_at: u64,
}

/// Device-control-key-signed acknowledgement of one exact Hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3SignedAck {
    /// Signed acknowledgement claims.
    pub claims: V3AckClaims,
    /// Responder control signature, canonical base64url without padding.
    pub signature: String,
}

impl V3SignedAck {
    /// Sign an Ack only after authenticating the Hello and this responder's exact locator.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid Hello/device/locator bindings, nonce, time, or signing.
    pub fn sign(
        credential: &V3DeviceCredential,
        hello: &V3SignedHello,
        initiator_certificate: &V3DeviceCertificate,
        responder_locator: &V3SignedLocator,
        responder_nonce: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            hello,
            initiator_certificate,
            responder_locator,
            responder_nonce,
            (issued_at, expires_at),
            false,
        )
    }

    /// Sign an Ack while explicitly accepting an HTTP loopback responder locator.
    ///
    /// Use only for a local-development transport configuration.
    ///
    /// # Errors
    ///
    /// Returns the same validation and signing errors as [`Self::sign`].
    pub fn sign_for_local_development(
        credential: &V3DeviceCredential,
        hello: &V3SignedHello,
        initiator_certificate: &V3DeviceCertificate,
        responder_locator: &V3SignedLocator,
        responder_nonce: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        Self::sign_with_policy(
            credential,
            hello,
            initiator_certificate,
            responder_locator,
            responder_nonce,
            (issued_at, expires_at),
            true,
        )
    }

    fn sign_with_policy(
        credential: &V3DeviceCredential,
        hello: &V3SignedHello,
        initiator_certificate: &V3DeviceCertificate,
        responder_locator: &V3SignedLocator,
        responder_nonce: impl Into<String>,
        validity: (u64, u64),
        allow_loopback_dev: bool,
    ) -> Result<Self> {
        let (issued_at, expires_at) = validity;
        hello.verify(
            initiator_certificate,
            &credential.certificate,
            responder_locator,
            &hello.claims.application,
            issued_at,
            allow_loopback_dev,
        )?;
        let claims = V3AckClaims {
            version: V3_PROTOCOL_VERSION,
            from_identity: credential.identity().to_owned(),
            from_device_id: credential.device_id().to_owned(),
            from_control_signing_key: credential.control_signing_key().to_owned(),
            from_iroh_endpoint_id: credential.iroh_endpoint_id().to_owned(),
            to_identity: hello.claims.from_identity.clone(),
            to_device_id: hello.claims.from_device_id.clone(),
            to_control_signing_key: hello.claims.from_control_signing_key.clone(),
            to_iroh_endpoint_id: hello.claims.from_iroh_endpoint_id.clone(),
            application: hello.claims.application.clone(),
            alpn: V3_IROH_ALPN_TEXT.to_owned(),
            session_nonce: hello.claims.session_nonce.clone(),
            responder_nonce: responder_nonce.into(),
            hello_digest: hello.digest()?,
            issued_at,
            expires_at,
        };
        Self::validate_claims(
            &claims,
            &credential.certificate,
            initiator_certificate,
            hello,
            &claims.application,
            issued_at,
            allow_loopback_dev,
        )?;
        let signature = credential
            .control_key()?
            .sign(&canonical_for_signing(V3_ACK_DOMAIN, &claims)?);
        Ok(Self {
            claims,
            signature: encode_signature(&signature),
        })
    }

    fn validate_claims(
        claims: &V3AckClaims,
        responder_certificate: &V3DeviceCertificate,
        initiator_certificate: &V3DeviceCertificate,
        hello: &V3SignedHello,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        if claims.version != V3_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(claims.version));
        }
        hello.verify_core(
            initiator_certificate,
            responder_certificate,
            expected_application,
            now,
            allow_loopback_dev,
        )?;
        let responder = &responder_certificate.claims;
        let initiator = &initiator_certificate.claims;
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
            return Err(ProtocolError::InvalidEncoding("v3 application binding"));
        }
        if claims.alpn != V3_IROH_ALPN_TEXT || claims.alpn != hello.claims.alpn {
            return Err(ProtocolError::InvalidEncoding("v3 ALPN"));
        }
        validate_nonce(&claims.session_nonce, "v3 session nonce")?;
        validate_nonce(&claims.responder_nonce, "v3 responder nonce")?;
        if claims.session_nonce != hello.claims.session_nonce
            || claims.responder_nonce == claims.session_nonce
        {
            return Err(ProtocolError::InvalidEncoding("v3 nonce binding"));
        }
        validate_digest(&claims.hello_digest, "v3 Hello digest")?;
        if claims.hello_digest != hello.digest()? {
            return Err(ProtocolError::DeviceMismatch);
        }
        validate_bounded_window(
            claims.issued_at,
            claims.expires_at,
            now,
            V3_MAX_HANDSHAKE_LIFETIME_SECONDS,
            "v3 Ack lifetime",
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

    /// Verify an Ack against the responder certificate and the exact signed Hello.
    ///
    /// Set `allow_loopback_dev` only when both peers use explicitly local-development locators.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, expired, cross-device, replay-substituted, or tampered Ack.
    pub fn verify(
        &self,
        responder_certificate: &V3DeviceCertificate,
        initiator_certificate: &V3DeviceCertificate,
        hello: &V3SignedHello,
        expected_application: &str,
        now: u64,
        allow_loopback_dev: bool,
    ) -> Result<()> {
        Self::validate_claims(
            &self.claims,
            responder_certificate,
            initiator_certificate,
            hello,
            expected_application,
            now,
            allow_loopback_dev,
        )?;
        verify_signature(
            &responder_certificate.control_public_key()?,
            V3_ACK_DOMAIN,
            &self.claims,
            &self.signature,
        )
    }
}
