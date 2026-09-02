use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open, single_shot_seal,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    PROTOCOL_VERSION, ProtocolError, Result,
    identity::{
        DeviceCertificate, DeviceCredential, canonical_for_signing, decode_signature,
        encode_signature, validate_window,
    },
};

const SIGNAL_SIGNATURE_DOMAIN: &str = "hole-punchky/encrypted-signal/v1";
const HPKE_INFO: &[u8] = b"hole-punchky/hpke-signal/v1";

/// Kind of opaque payload being forwarded by the rendezvous service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// WebRTC SDP offer.
    Offer,
    /// WebRTC SDP answer.
    Answer,
    /// Trickle ICE candidate.
    Candidate,
    /// Trickle ICE gathering completed.
    EndOfCandidates,
    /// Abort negotiation.
    Abort,
}

/// Plaintext WebRTC signal protected with recipient-specific HPKE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalPayload {
    /// A session description.
    SessionDescription {
        /// SDP type (`offer` or `answer`).
        sdp_type: String,
        /// SDP body.
        sdp: String,
    },
    /// One ICE candidate.
    IceCandidate {
        /// Candidate attribute.
        candidate: String,
        /// Optional SDP media id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp_mid: Option<String>,
        /// Optional SDP media-line index.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp_mline_index: Option<u16>,
        /// Optional username fragment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username_fragment: Option<String>,
    },
    /// ICE gathering has no more candidates.
    EndOfCandidates,
    /// Stop negotiation.
    Abort {
        /// Safe reason to show the peer.
        reason: String,
    },
}

impl SignalPayload {
    fn kind(&self) -> Result<SignalKind> {
        match self {
            Self::SessionDescription { sdp_type, .. } if sdp_type == "offer" => {
                Ok(SignalKind::Offer)
            }
            Self::SessionDescription { sdp_type, .. } if sdp_type == "answer" => {
                Ok(SignalKind::Answer)
            }
            Self::SessionDescription { .. } => Err(ProtocolError::InvalidEncoding("SDP type")),
            Self::IceCandidate { .. } => Ok(SignalKind::Candidate),
            Self::EndOfCandidates => Ok(SignalKind::EndOfCandidates),
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
        Ok(payload)
    }
}
