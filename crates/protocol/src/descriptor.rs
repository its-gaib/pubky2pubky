use ed25519_dalek::Signature;
use pubky_common::crypto::Keypair;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    IROH_TRANSPORT, PROTOCOL_VERSION, ProtocolError, Result,
    identity::{canonical_for_signing, decode_signature, encode_signature, parse_public_key},
};

const DESCRIPTOR_DOMAIN: &str = "hole-punchky/rendezvous-descriptor/v2";

/// Well-known public-storage path beneath a Pubky identity.
pub const DESCRIPTOR_PATH: &str = "/pub/hole-punchky/v2/descriptor.json";

/// One public rendezvous service usable for an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousEndpoint {
    /// Secure WebSocket endpoint, or `ws://` for explicitly local development.
    pub signaling_url: Url,
    /// Smaller values are preferred.
    #[serde(default)]
    pub priority: u16,
    /// Optional deployment region label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// Root-signed discovery claims stored in Pubky public storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousDescriptorClaims {
    /// Protocol version.
    pub version: u16,
    /// Pubky root public key in z-base-32 form.
    pub identity: String,
    /// Redundant rendezvous endpoints in preference order.
    pub endpoints: Vec<RendezvousEndpoint>,
    /// Data-plane transports supported by this descriptor.
    pub transports: Vec<String>,
    /// Unix time after which clients must re-resolve this record.
    pub expires_at: u64,
}

/// Signed Pubky discovery record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousDescriptor {
    /// Signed claims.
    pub claims: RendezvousDescriptorClaims,
    /// Root Ed25519 signature, base64url without padding.
    pub signature: String,
}

impl RendezvousDescriptor {
    /// Create a descriptor signed by the Pubky root key.
    ///
    /// # Errors
    ///
    /// Returns an error when no endpoint is supplied or canonical JSON encoding fails.
    pub fn sign(
        root: &Keypair,
        endpoints: Vec<RendezvousEndpoint>,
        expires_at: u64,
    ) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(ProtocolError::InvalidEncoding("rendezvous endpoint"));
        }
        let claims = RendezvousDescriptorClaims {
            version: PROTOCOL_VERSION,
            identity: root.public_key().z32(),
            endpoints,
            transports: vec![IROH_TRANSPORT.to_owned()],
            expires_at,
        };
        let signature = root.sign(&canonical_for_signing(DESCRIPTOR_DOMAIN, &claims)?);
        Ok(Self {
            claims,
            signature: encode_signature(&signature),
        })
    }

    /// Verify the descriptor's root signature, identity, endpoint policy, and expiry.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong identity/version, expiry, invalid endpoint URL, malformed
    /// key/signature, or failed root signature verification.
    pub fn verify(
        &self,
        expected_identity: &str,
        now: u64,
        allow_insecure_local: bool,
    ) -> Result<()> {
        if self.claims.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.claims.version));
        }
        if self.claims.identity != expected_identity {
            return Err(ProtocolError::IdentityMismatch);
        }
        if self.claims.expires_at < now {
            return Err(ProtocolError::Expired);
        }
        if self.claims.endpoints.is_empty() || self.claims.endpoints.len() > 8 {
            return Err(ProtocolError::InvalidEncoding("rendezvous endpoint"));
        }
        if self.claims.transports.len() > 8
            || !self
                .claims
                .transports
                .iter()
                .any(|transport| transport == IROH_TRANSPORT)
        {
            return Err(ProtocolError::InvalidEncoding("iroh transport capability"));
        }
        for endpoint in &self.claims.endpoints {
            let secure = endpoint.signaling_url.scheme() == "wss";
            let local = allow_insecure_local
                && endpoint.signaling_url.scheme() == "ws"
                && endpoint.signaling_url.host_str().is_some_and(|host| {
                    host == "localhost"
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback())
                });
            if !secure && !local {
                return Err(ProtocolError::InvalidEncoding("secure rendezvous URL"));
            }
        }
        let key = parse_public_key(expected_identity)?;
        let signature: Signature = decode_signature(&self.signature)?;
        key.verify(
            &canonical_for_signing(DESCRIPTOR_DOMAIN, &self.claims)?,
            &signature,
        )
        .map_err(|_| ProtocolError::BadSignature)
    }

    /// Endpoints ordered by increasing priority.
    #[must_use]
    pub fn ordered_endpoints(&self) -> Vec<&RendezvousEndpoint> {
        let mut endpoints: Vec<_> = self.claims.endpoints.iter().collect();
        endpoints.sort_by_key(|endpoint| endpoint.priority);
        endpoints
    }
}
