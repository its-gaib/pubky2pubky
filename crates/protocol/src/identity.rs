use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;
use hpke::{Deserializable, Kem as _, Serializable, kem::X25519HkdfSha256};
use pubky_common::crypto::{Keypair, PublicKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use web_time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    MAX_CERTIFICATE_LIFETIME_SECONDS, MAX_CLOCK_SKEW_SECONDS, PROTOCOL_VERSION, ProtocolError,
    Result,
};

const CERTIFICATE_DOMAIN: &str = "hole-punchky/device-certificate/v2";

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

pub(crate) fn decode_signature(encoded: &str) -> Result<Signature> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidEncoding("signature"))?;
    Signature::from_slice(&bytes).map_err(|_| ProtocolError::InvalidEncoding("signature"))
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<PublicKey> {
    let key = PublicKey::try_from_z32(encoded)
        .map_err(|_| ProtocolError::InvalidEncoding("public key"))?;
    if key.z32() != encoded {
        return Err(ProtocolError::InvalidEncoding("canonical public key"));
    }
    Ok(key)
}

pub(crate) fn validate_window(issued_at: u64, expires_at: u64, now: u64) -> Result<()> {
    if expires_at <= issued_at {
        return Err(ProtocolError::InvalidTimeWindow);
    }
    if issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECONDS) {
        return Err(ProtocolError::NotYetValid);
    }
    if expires_at.saturating_add(MAX_CLOCK_SKEW_SECONDS) < now {
        return Err(ProtocolError::Expired);
    }
    Ok(())
}

/// Root-signed claims that delegate a device for Hole Punchky.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificateClaims {
    /// Protocol version.
    pub version: u16,
    /// Pubky root public key in raw z-base-32 form.
    pub identity: String,
    /// Opaque, user-chosen stable identifier for this device.
    pub device_id: String,
    /// Device Ed25519 public key in z-base-32 form.
    pub signing_key: String,
    /// Device X25519 HPKE public key, base64url without padding.
    pub encryption_key: String,
    /// Dedicated iroh endpoint id in canonical z-base-32 form.
    pub iroh_endpoint_id: String,
    /// Beginning of the certificate validity interval.
    pub issued_at: u64,
    /// End of the certificate validity interval.
    pub expires_at: u64,
    /// Operations delegated by the root key.
    pub capabilities: Vec<String>,
}

/// A root-signed device delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    /// Delegated claims.
    pub claims: DeviceCertificateClaims,
    /// Root Ed25519 signature, base64url without padding.
    pub signature: String,
}

impl DeviceCertificate {
    /// Verify the root signature, lifetime, and an optional required capability.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, time window, lifetime, key encoding,
    /// capability, or root signature.
    pub fn verify(&self, now: u64, capability: Option<&str>) -> Result<()> {
        if self.claims.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.claims.version));
        }
        validate_window(self.claims.issued_at, self.claims.expires_at, now)?;
        if self.claims.expires_at - self.claims.issued_at > MAX_CERTIFICATE_LIFETIME_SECONDS {
            return Err(ProtocolError::CertificateLifetime);
        }
        if self.claims.device_id.is_empty() || self.claims.device_id.len() > 128 {
            return Err(ProtocolError::InvalidEncoding("device id"));
        }
        let encryption_key = URL_SAFE_NO_PAD
            .decode(&self.claims.encryption_key)
            .map_err(|_| ProtocolError::InvalidEncoding("HPKE public key"))?;
        <<X25519HkdfSha256 as hpke::Kem>::PublicKey as Deserializable>::from_bytes(&encryption_key)
            .map_err(|_| ProtocolError::InvalidEncoding("HPKE public key"))?;
        parse_public_key(&self.claims.signing_key)?;
        parse_public_key(&self.claims.iroh_endpoint_id)?;

        if let Some(required) = capability
            && !self
                .claims
                .capabilities
                .iter()
                .any(|value| value == required)
        {
            return Err(ProtocolError::MissingCapability(required.to_owned()));
        }

        let identity = parse_public_key(&self.claims.identity)?;
        let signature = decode_signature(&self.signature)?;
        let bytes = canonical_for_signing(CERTIFICATE_DOMAIN, &self.claims)?;
        identity
            .verify(&bytes, &signature)
            .map_err(|_| ProtocolError::BadSignature)
    }

    pub(crate) fn device_public_key(&self) -> Result<PublicKey> {
        parse_public_key(&self.claims.signing_key)
    }

    /// Return the certified iroh endpoint id in the lowercase hexadecimal form used by
    /// iroh relay authorization callouts.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint id is not a canonical Ed25519 public key.
    pub fn iroh_endpoint_id_hex(&self) -> Result<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let key = parse_public_key(&self.claims.iroh_endpoint_id)?;
        let mut encoded = String::with_capacity(64);
        for byte in key.as_inner().as_bytes() {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(encoded)
    }

    pub(crate) fn encryption_public_key(
        &self,
    ) -> Result<<X25519HkdfSha256 as hpke::Kem>::PublicKey> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.claims.encryption_key)
            .map_err(|_| ProtocolError::InvalidEncoding("HPKE public key"))?;
        <<X25519HkdfSha256 as hpke::Kem>::PublicKey as Deserializable>::from_bytes(&bytes)
            .map_err(|_| ProtocolError::InvalidEncoding("HPKE public key"))
    }
}

/// Serializable device secrets. Keep this structure in a mode-0600 file.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeviceCredential {
    /// Root-signed public delegation. This field is not secret.
    #[zeroize(skip)]
    pub certificate: DeviceCertificate,
    /// Ed25519 signing secret, base64url without padding.
    signing_secret: String,
    /// X25519 HPKE secret, base64url without padding.
    encryption_secret: String,
    /// Dedicated iroh Ed25519 secret, base64url without padding.
    iroh_secret: String,
}

impl std::fmt::Debug for DeviceCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCredential")
            .field("certificate", &self.certificate)
            .field("signing_secret", &"[REDACTED]")
            .field("encryption_secret", &"[REDACTED]")
            .field("iroh_secret", &"[REDACTED]")
            .finish()
    }
}

impl DeviceCredential {
    /// Create a fresh device credential signed by a Pubky root key.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested validity window is invalid or too long, or when
    /// canonical JSON encoding fails.
    pub fn issue(
        root: &Keypair,
        device_id: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        validate_window(issued_at, expires_at, issued_at)?;
        if expires_at - issued_at > MAX_CERTIFICATE_LIFETIME_SECONDS {
            return Err(ProtocolError::CertificateLifetime);
        }

        let signing = Keypair::random();
        let iroh = Keypair::random();
        let (encryption_private, encryption_public) = X25519HkdfSha256::gen_keypair();
        let signing_secret = Zeroizing::new(signing.secret());
        let mut encryption_secret_bytes = encryption_private.to_bytes();
        let encoded_encryption_secret = URL_SAFE_NO_PAD.encode(&encryption_secret_bytes[..]);
        let encryption_secret_slice: &mut [u8] = encryption_secret_bytes.as_mut();
        encryption_secret_slice.zeroize();
        let claims = DeviceCertificateClaims {
            version: PROTOCOL_VERSION,
            identity: root.public_key().z32(),
            device_id: device_id.into(),
            signing_key: signing.public_key().z32(),
            encryption_key: URL_SAFE_NO_PAD.encode(encryption_public.to_bytes()),
            iroh_endpoint_id: iroh.public_key().z32(),
            issued_at,
            expires_at,
            capabilities: vec![
                "rendezvous".to_owned(),
                "signal".to_owned(),
                "iroh".to_owned(),
            ],
        };
        let signature = root.sign(&canonical_for_signing(CERTIFICATE_DOMAIN, &claims)?);
        let certificate = DeviceCertificate {
            claims,
            signature: encode_signature(&signature),
        };

        Ok(Self {
            certificate,
            signing_secret: URL_SAFE_NO_PAD.encode(&signing_secret[..]),
            encryption_secret: encoded_encryption_secret,
            iroh_secret: URL_SAFE_NO_PAD.encode(iroh.secret()),
        })
    }

    /// Pubky identity delegated by this credential.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.certificate.claims.identity
    }

    /// Device identifier delegated by this credential.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.certificate.claims.device_id
    }

    /// Dedicated iroh endpoint id certified for this device.
    #[must_use]
    pub fn iroh_endpoint_id(&self) -> &str {
        &self.certificate.claims.iroh_endpoint_id
    }

    /// Decode and verify the dedicated iroh secret key.
    ///
    /// The returned bytes are zeroized on drop. Applications normally do not need this;
    /// it exists so the native transport crate can construct the certified endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored secret is malformed or does not match the certificate.
    #[doc(hidden)]
    pub fn iroh_secret_key_bytes(&self) -> Result<Zeroizing<[u8; 32]>> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&self.iroh_secret)
                .map_err(|_| ProtocolError::InvalidEncoding("iroh secret key"))?,
        );
        let secret = Zeroizing::new(
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| ProtocolError::InvalidEncoding("iroh secret key"))?,
        );
        let key = Keypair::from_secret(&secret);
        if key.public_key().z32() != self.certificate.claims.iroh_endpoint_id {
            return Err(ProtocolError::InvalidEncoding("iroh secret key"));
        }
        Ok(secret)
    }

    pub(crate) fn signing_key(&self) -> Result<Keypair> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&self.signing_secret)
                .map_err(|_| ProtocolError::InvalidEncoding("signing secret"))?,
        );
        let secret = Zeroizing::new(
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| ProtocolError::InvalidEncoding("signing secret"))?,
        );
        let key = Keypair::from_secret(&secret);
        if key.public_key().z32() != self.certificate.claims.signing_key {
            return Err(ProtocolError::InvalidEncoding("signing secret"));
        }
        Ok(key)
    }

    pub(crate) fn encryption_private_key(
        &self,
    ) -> Result<<X25519HkdfSha256 as hpke::Kem>::PrivateKey> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&self.encryption_secret)
                .map_err(|_| ProtocolError::InvalidEncoding("HPKE secret key"))?,
        );
        let private =
            <<X25519HkdfSha256 as hpke::Kem>::PrivateKey as Deserializable>::from_bytes(&bytes)
                .map_err(|_| ProtocolError::InvalidEncoding("HPKE secret key"))?;
        let public = X25519HkdfSha256::sk_to_pk(&private);
        if URL_SAFE_NO_PAD.encode(public.to_bytes()) != self.certificate.claims.encryption_key {
            return Err(ProtocolError::InvalidEncoding("HPKE secret key"));
        }
        Ok(private)
    }
}

/// A value signed by a delegated device key and accompanied by its root certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authenticated<T> {
    /// Signed value.
    pub payload: T,
    /// Root-signed device delegation used for the signature.
    pub certificate: DeviceCertificate,
    /// Device signature, base64url without padding.
    pub signature: String,
}

/// Metadata required for a short-lived authenticated protocol message.
pub trait SignedPayload: Serialize + DeserializeOwned {
    /// Domain-separation label used when signing this kind of payload.
    const DOMAIN: &'static str;

    /// Protocol version in the payload.
    fn version(&self) -> u16;
    /// Pubky root identity claimed by the sender.
    fn identity(&self) -> &str;
    /// Delegated device identifier claimed by the sender.
    fn device_id(&self) -> &str;
    /// Beginning of this message's validity interval.
    fn issued_at(&self) -> u64;
    /// End of this message's validity interval.
    fn expires_at(&self) -> u64;
}

impl<T: SignedPayload> Authenticated<T> {
    /// Sign a payload with the delegated device key.
    ///
    /// # Errors
    ///
    /// Returns an error when payload identity/device claims differ from the credential or the
    /// credential/signable representation is malformed.
    pub fn sign(payload: T, credential: &DeviceCredential) -> Result<Self> {
        if payload.identity() != credential.identity() {
            return Err(ProtocolError::IdentityMismatch);
        }
        if payload.device_id() != credential.device_id() {
            return Err(ProtocolError::DeviceMismatch);
        }
        let signature = credential
            .signing_key()?
            .sign(&canonical_for_signing(T::DOMAIN, &payload)?);
        Ok(Self {
            payload,
            certificate: credential.certificate.clone(),
            signature: encode_signature(&signature),
        })
    }

    /// Verify the root delegation and the device signature.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version/time window, delegation, identity/device
    /// binding, encoding, or signature.
    pub fn verify(&self, now: u64) -> Result<()> {
        if self.payload.version() != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.payload.version()));
        }
        validate_window(self.payload.issued_at(), self.payload.expires_at(), now)?;
        self.certificate.verify(now, Some("rendezvous"))?;
        if self.payload.identity() != self.certificate.claims.identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        if self.payload.device_id() != self.certificate.claims.device_id {
            return Err(ProtocolError::DeviceMismatch);
        }
        let signature = decode_signature(&self.signature)?;
        let bytes = canonical_for_signing(T::DOMAIN, &self.payload)?;
        self.certificate
            .device_public_key()?
            .verify(&bytes, &signature)
            .map_err(|_| ProtocolError::BadSignature)
    }
}
