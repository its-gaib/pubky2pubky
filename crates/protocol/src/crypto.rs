use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open, single_shot_seal,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    PROTOCOL_VERSION, ProtocolError, Result,
    identity::{
        DeviceCertificate, DeviceCredential, canonical_for_signing, decode_signature,
        encode_signature, validate_window,
    },
};

const SIGNAL_SIGNATURE_DOMAIN: &str = "hole-punchky/encrypted-signal/v2";
const HPKE_INFO: &[u8] = b"hole-punchky/hpke-signal/v2";

/// Maximum number of relay URLs accepted in one encrypted endpoint address.
pub const MAX_IROH_RELAY_URLS: usize = 8;

/// Maximum number of direct socket addresses accepted in one encrypted endpoint address.
pub const MAX_IROH_DIRECT_ADDRESSES: usize = 32;

/// Portable, dependency-neutral representation of an iroh endpoint address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrohEndpointAddress {
    /// Certified iroh endpoint id in canonical z-base-32 form.
    pub endpoint_id: String,
    /// Relay URLs at which this endpoint is registered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_urls: Vec<Url>,
    /// Direct addresses discovered by the endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_addresses: Vec<SocketAddr>,
}

impl IrohEndpointAddress {
    /// Validate field encodings and conservative resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed id, unusable address, unsupported relay URL, or an
    /// address list exceeding protocol limits.
    pub fn validate(&self) -> Result<()> {
        crate::identity::parse_public_key(&self.endpoint_id)?;
        if self.relay_urls.len() > MAX_IROH_RELAY_URLS
            || self.direct_addresses.len() > MAX_IROH_DIRECT_ADDRESSES
            || (self.relay_urls.is_empty() && self.direct_addresses.is_empty())
        {
            return Err(ProtocolError::InvalidEncoding("iroh endpoint address"));
        }
        for url in &self.relay_urls {
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(ProtocolError::InvalidEncoding("iroh relay URL"));
            }
        }
        if self.direct_addresses.iter().any(|address| {
            address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast()
        }) {
            return Err(ProtocolError::InvalidEncoding("iroh direct address"));
        }
        Ok(())
    }
}

/// Kind of opaque payload being forwarded by the rendezvous service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// Responder's iroh endpoint address, released only after consent.
    IrohEndpoint,
    /// Abort negotiation.
    Abort,
}

/// Plaintext negotiation signal protected with recipient-specific HPKE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalPayload {
    /// Network coordinates for the responder's certified iroh endpoint.
    IrohEndpoint {
        /// Address to dial over direct UDP or the named relay.
        endpoint: IrohEndpointAddress,
    },
    /// Stop negotiation.
    Abort {
        /// Safe reason to show the peer.
        reason: String,
    },
}

impl SignalPayload {
    fn kind(&self) -> Result<SignalKind> {
        match self {
            Self::IrohEndpoint { endpoint } => {
                endpoint.validate()?;
                Ok(SignalKind::IrohEndpoint)
            }
            Self::Abort { .. } => Ok(SignalKind::Abort),
        }
    }
}

/// Public routing metadata authenticated as HPKE associated data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalHeader {
    /// Protocol version.
    pub version: u16,
    /// Bound rendezvous session.
    pub session_id: Uuid,
    /// Sender Pubky identity.
    pub from_identity: String,
    /// Sender device id.
    pub from_device_id: String,
    /// Recipient Pubky identity.
    pub to_identity: String,
    /// Recipient device id.
    pub to_device_id: String,
    /// Strictly increasing per-sender sequence number, beginning at zero.
    pub sequence: u64,
    /// Plaintext type, exposed only so the server can enforce ordering and size policy.
    pub kind: SignalKind,
    /// Beginning of message validity.
    pub issued_at: u64,
    /// End of message validity.
    pub expires_at: u64,
}

#[derive(Serialize)]
struct SignalSignatureInput<'a> {
    header: &'a SignalHeader,
    encapsulated_key: &'a str,
    ciphertext: &'a str,
}

/// End-to-end encrypted and sender-authenticated signaling envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSignal {
    /// Public routing metadata and HPKE associated data.
    pub header: SignalHeader,
    /// Root-signed certificate for the sender device.
    pub certificate: DeviceCertificate,
    /// HPKE encapsulated X25519 key, base64url without padding.
    pub encapsulated_key: String,
    /// AEAD ciphertext, base64url without padding.
    pub ciphertext: String,
    /// Device signature over the complete opaque envelope.
    pub signature: String,
}

impl EncryptedSignal {
    /// Encrypt a signal to the recipient device and sign the opaque envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the recipient delegation/time window is invalid, JSON
    /// canonicalization fails, a key cannot be decoded, or HPKE cannot seal the payload.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        sender: &DeviceCredential,
        recipient: &DeviceCertificate,
        session_id: Uuid,
        sequence: u64,
        payload: &SignalPayload,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        recipient.verify(issued_at, Some("signal"))?;
        if let SignalPayload::IrohEndpoint { endpoint } = payload
            && endpoint.endpoint_id != sender.iroh_endpoint_id()
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        let header = SignalHeader {
            version: PROTOCOL_VERSION,
            session_id,
            from_identity: sender.identity().to_owned(),
            from_device_id: sender.device_id().to_owned(),
            to_identity: recipient.claims.identity.clone(),
            to_device_id: recipient.claims.device_id.clone(),
            sequence,
            kind: payload.kind()?,
            issued_at,
            expires_at,
        };
        validate_window(issued_at, expires_at, issued_at)?;
        let aad = serde_jcs::to_vec(&header)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(payload)?);
        let (encapsulated_key, ciphertext) =
            single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                &recipient.encryption_public_key()?,
                HPKE_INFO,
                &plaintext,
                &aad,
            )
            .map_err(|_| ProtocolError::Hpke)?;
        let encapsulated_key = URL_SAFE_NO_PAD.encode(encapsulated_key.to_bytes());
        let ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        let signature_input = SignalSignatureInput {
            header: &header,
            encapsulated_key: &encapsulated_key,
            ciphertext: &ciphertext,
        };
        let signature = sender.signing_key()?.sign(&canonical_for_signing(
            SIGNAL_SIGNATURE_DOMAIN,
            &signature_input,
        )?);

        Ok(Self {
            header,
            certificate: sender.certificate.clone(),
            encapsulated_key,
            ciphertext,
            signature: encode_signature(&signature),
        })
    }

    /// Verify the sender, routing metadata, time window, and envelope signature.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, time window, delegation, identity binding,
    /// encoding, or device signature.
    pub fn verify(&self, now: u64) -> Result<()> {
        if self.header.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.header.version));
        }
        validate_window(self.header.issued_at, self.header.expires_at, now)?;
        self.certificate.verify(now, Some("signal"))?;
        if self.header.from_identity != self.certificate.claims.identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        if self.header.from_device_id != self.certificate.claims.device_id {
            return Err(ProtocolError::DeviceMismatch);
        }
        let input = SignalSignatureInput {
            header: &self.header,
            encapsulated_key: &self.encapsulated_key,
            ciphertext: &self.ciphertext,
        };
        self.certificate
            .device_public_key()?
            .verify(
                &canonical_for_signing(SIGNAL_SIGNATURE_DOMAIN, &input)?,
                &decode_signature(&self.signature)?,
            )
            .map_err(|_| ProtocolError::BadSignature)
    }

    /// Verify and decrypt a signal using the recipient device credential.
    ///
    /// # Errors
    ///
    /// Returns an error when verification fails, the credential is not the named recipient,
    /// HPKE authentication fails, or the plaintext does not match the declared signal kind.
    pub fn open(&self, recipient: &DeviceCredential, now: u64) -> Result<SignalPayload> {
        self.verify(now)?;
        if self.header.to_identity != recipient.identity() {
            return Err(ProtocolError::IdentityMismatch);
        }
        if self.header.to_device_id != recipient.device_id() {
            return Err(ProtocolError::DeviceMismatch);
        }
        let encapped_bytes = URL_SAFE_NO_PAD
            .decode(&self.encapsulated_key)
            .map_err(|_| ProtocolError::InvalidEncoding("HPKE encapsulated key"))?;
        let encapped =
            <<X25519HkdfSha256 as hpke::Kem>::EncappedKey as Deserializable>::from_bytes(
                &encapped_bytes,
            )
            .map_err(|_| ProtocolError::InvalidEncoding("HPKE encapsulated key"))?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|_| ProtocolError::InvalidEncoding("ciphertext"))?;
        let plaintext = Zeroizing::new(
            single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &recipient.encryption_private_key()?,
                &encapped,
                HPKE_INFO,
                &ciphertext,
                &serde_jcs::to_vec(&self.header)?,
            )
            .map_err(|_| ProtocolError::Hpke)?,
        );
        let payload: SignalPayload = serde_json::from_slice(&plaintext)?;
        if payload.kind()? != self.header.kind {
            return Err(ProtocolError::InvalidEncoding("signal kind"));
        }
        if let SignalPayload::IrohEndpoint { endpoint } = &payload
            && endpoint.endpoint_id != self.certificate.claims.iroh_endpoint_id
        {
            return Err(ProtocolError::DeviceMismatch);
        }
        Ok(payload)
    }
}
