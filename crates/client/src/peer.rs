use std::time::Duration;

use futures_util::StreamExt as _;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use n0_future::time;
use tokio::{io::AsyncWriteExt as _, sync::Mutex};
use url::Url;
use uuid::Uuid;

use crate::{ClientError, Result};

/// Explicit acknowledgement of the metadata exposed while establishing an iroh connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicContactDisclosure {
    /// Direct-capable peers accept address and network-metadata exposure before app consent.
    AcknowledgePreConsentNetworkExposure,
    /// Relay-only peers accept relay-visible endpoint, timing, and traffic metadata.
    AcknowledgePreConsentRelayMetadataExposure,
}

/// Path policy applied to the iroh endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathPolicy {
    /// Attempt direct QUIC and keep the configured iroh relay as fallback.
    #[default]
    DirectWithRelayFallback,
    /// Disable IP transports and carry QUIC only through an iroh relay.
    RelayOnly,
}

/// Configuration for one locally trusted iroh relay.
#[derive(Clone)]
pub struct IrohRelayConfig {
    /// Exact HTTP(S) endpoint of the relay.
    pub url: Url,
    /// Optional bearer token configured locally for a private relay.
    pub auth_token: Option<String>,
}

impl std::fmt::Debug for IrohRelayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IrohRelayConfig")
            .field("url", &self.url)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl IrohRelayConfig {
    /// Configure a relay without application-level authentication.
    #[must_use]
    pub fn new(url: Url) -> Self {
        Self {
            url,
            auth_token: None,
        }
    }

    /// Attach a bearer token used when registering with this relay.
    #[must_use]
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }
}

/// Actual network path selected by iroh QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPath {
    /// An IP path is selected.
    Direct,
    /// An iroh relay path is selected.
    Relayed,
    /// No selected path has been reported yet.
    Unknown,
}

/// An authenticated iroh QUIC stream connected to a verified Pubky identity.
pub struct Peer {
    connection: Connection,
    send: Mutex<Option<SendStream>>,
    recv: Mutex<RecvStream>,
    session_id: Uuid,
    remote_identity: String,
    remote_device_id: String,
    max_message_bytes: usize,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Peer")
            .field("session_id", &self.session_id)
            .field("peer_identity", &self.remote_identity)
            .field("peer_device_id", &self.remote_device_id)
            .field("path", &self.path())
            .finish_non_exhaustive()
    }
}

impl Peer {
    pub(crate) fn new(
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
        session_id: Uuid,
        remote_identity: String,
        remote_device_id: String,
        max_message_bytes: usize,
    ) -> Self {
        Self {
            connection,
            send: Mutex::new(Some(send)),
            recv: Mutex::new(recv),
            session_id,
            remote_identity,
            remote_device_id,
            max_message_bytes,
        }
    }

    /// Bound handshake session id.
    #[must_use]
    pub const fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Authenticated peer Pubky identity.
    #[must_use]
    pub fn peer_identity(&self) -> &str {
        &self.remote_identity
    }

    /// Authenticated delegated device id.
    #[must_use]
    pub fn peer_device_id(&self) -> &str {
        &self.remote_device_id
    }

    /// Send one length-delimited binary message.
    ///
    /// # Errors
    ///
    /// Returns an error when the message exceeds the configured bound or QUIC is closed.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if data.len() > self.max_message_bytes {
            return Err(ClientError::Iroh(format!(
                "message exceeds the {} byte limit",
                self.max_message_bytes
            )));
        }
        let mut guard = self.send.lock().await;
        let stream = guard.as_mut().ok_or(ClientError::ChannelClosed)?;
        write_bytes(stream, data).await
    }

    /// Send one UTF-8 message.
    ///
    /// # Errors
    ///
    /// Returns an error when the message exceeds the configured bound or QUIC is closed.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        self.send(text.as_bytes()).await
    }

    /// Receive one complete binary message.
    ///
    /// # Errors
    ///
    /// Returns an error when QUIC is closed or a frame exceeds the configured bound.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut stream = self.recv.lock().await;
        read_bytes(&mut stream, self.max_message_bytes).await
    }

    /// Inspect the selected iroh path.
    #[must_use]
    pub fn path(&self) -> ConnectionPath {
        selected_path(&self.connection)
    }

    /// Wait for a preferred path, returning the last observed path on timeout.
    pub async fn wait_for_path(
        &self,
        preferred: ConnectionPath,
        timeout: Duration,
    ) -> ConnectionPath {
        let connection = self.connection.clone();
        let wait = async move {
            let mut paths = connection.paths_stream();
            while let Some(snapshot) = paths.next().await {
                let current = snapshot
                    .iter()
                    .find(iroh::endpoint::Path::is_selected)
                    .map_or(ConnectionPath::Unknown, |path| {
                        if path.is_ip() {
                            ConnectionPath::Direct
                        } else if path.is_relay() {
                            ConnectionPath::Relayed
                        } else {
                            ConnectionPath::Unknown
                        }
                    });
                if current == preferred {
                    return current;
                }
            }
            ConnectionPath::Unknown
        };
        time::timeout(timeout, wait)
            .await
            .unwrap_or_else(|_| self.path())
    }

    /// Flush pending stream bytes to the QUIC transport.
    ///
    /// # Errors
    ///
    /// Returns an error when QUIC fails or the supplied timeout elapses.
    pub async fn flush(&self, timeout: Duration) -> Result<()> {
        let mut guard = self.send.lock().await;
        let stream = guard.as_mut().ok_or(ClientError::ChannelClosed)?;
        time::timeout(timeout, stream.flush())
            .await
            .map_err(|_| ClientError::Timeout("flushing peer QUIC stream"))?
            .map_err(|error| ClientError::Iroh(error.to_string()))
    }

    /// Finish the send direction and wait until all stream bytes are acknowledged.
    ///
    /// # Errors
    ///
    /// Returns an error when the stream closes, QUIC fails, or the timeout elapses.
    pub async fn finish(&self, timeout: Duration) -> Result<()> {
        let mut stream = self
            .send
            .lock()
            .await
            .take()
            .ok_or(ClientError::ChannelClosed)?;
        stream
            .finish()
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        match time::timeout(timeout, stream.stopped()).await {
            Err(_) => Err(ClientError::Timeout("draining peer QUIC stream")),
            Ok(Err(error)) => Err(ClientError::Iroh(error.to_string())),
            Ok(Ok(Some(code))) => Err(ClientError::Iroh(format!(
                "peer stopped QUIC stream with code {code}"
            ))),
            Ok(Ok(None)) => Ok(()),
        }
    }

    /// Wait until the peer finishes its send direction without trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for trailing bytes, QUIC failure, or timeout.
    pub async fn wait_for_peer_finish(&self, timeout: Duration) -> Result<()> {
        let mut stream = self.recv.lock().await;
        let mut trailing = [0u8; 1];
        match time::timeout(timeout, stream.read(&mut trailing)).await {
            Err(_) => Err(ClientError::Timeout("waiting for peer QUIC stream finish")),
            Ok(Err(error)) => Err(ClientError::Iroh(error.to_string())),
            Ok(Ok(None | Some(0))) => Ok(()),
            Ok(Ok(Some(_))) => Err(ClientError::Iroh(
                "peer sent trailing bytes after the close handshake".to_owned(),
            )),
        }
    }

    /// Close this QUIC connection, making a best effort to finish the send direction first.
    ///
    /// # Errors
    ///
    /// This implementation currently returns success after starting the best-effort close.
    pub async fn close(&self) -> Result<()> {
        if let Some(mut stream) = self.send.lock().await.take() {
            let _ = stream.finish();
        }
        self.connection.close(0u32.into(), b"application closed");
        Ok(())
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"peer dropped");
    }
}

fn selected_path(connection: &Connection) -> ConnectionPath {
    connection
        .paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map_or(ConnectionPath::Unknown, |path| {
            if path.is_ip() {
                ConnectionPath::Direct
            } else if path.is_relay() {
                ConnectionPath::Relayed
            } else {
                ConnectionPath::Unknown
            }
        })
}

async fn write_bytes(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| ClientError::Iroh("QUIC message is too large".to_owned()))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))
}

async fn read_bytes(stream: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut encoded_length = [0u8; 4];
    stream
        .read_exact(&mut encoded_length)
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    let length = u32::from_be_bytes(encoded_length) as usize;
    if length > max {
        return Err(ClientError::Iroh(format!(
            "peer message exceeds the {max} byte limit"
        )));
    }
    let mut bytes = vec![0u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    Ok(bytes)
}
