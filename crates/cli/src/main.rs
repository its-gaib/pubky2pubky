//! Operational CLI for identities, descriptors, rendezvous, and test connections.

use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead as _, Read as _, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand};
use hole_punchky_client::{
    ConnectionPath, DialOptions, FileSequenceStore, IrohRelayConfig, PathPolicy, Peer,
    PubkyResolver, PubkyV3Resolver, PublicContactDisclosure, RendezvousClient,
    RendezvousClientConfig, V3Client, V3ClientConfig, V3DeviceResolver, V3DiscoveryConfig,
    publish_descriptor, publish_v3_directory, publish_v3_locator, resolve_rendezvous_url,
};
use hole_punchky_protocol::{
    DESCRIPTOR_PATH, DeviceCredential, RendezvousDescriptor, RendezvousEndpoint,
    V3DeviceCertificate, V3DeviceCredential, V3DeviceDirectory, V3SignedLocator, now_seconds,
};
use hole_punchky_rendezvous::{ServerConfig, serve};
use pubky::{ClientId, Keypair, Pubky, PublicKey};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing_subscriber::EnvFilter;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CLOSE_MARKER: &[u8] = b"__hole_punchky_close__";
const CLOSE_ACK: &[u8] = b"__hole_punchky_close_ack__";
const V3_CLOSE_MARKER: &[u8] = b"__pubky2pubky_v3_close__";
const V3_CLOSE_ACK: &[u8] = b"__pubky2pubky_v3_close_ack__";
const V3_CLI_MESSAGE_MAX_BYTES: usize = 64 * 1024;
const V3_RELAY_TOKEN_MAX_BYTES: usize = 4 * 1024;
const V3_RELAY_TOKEN_ENV: &str = "PUBKY2PUBKY_IROH_RELAY_TOKEN";

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a v3 Pubky root identity and its first delegated native device.
    V3Init(V3InitArgs),
    /// Issue another v3 native device credential from an offline root identity.
    V3IssueDevice(V3IssueDeviceArgs),
    /// Export the public certificate from a v3 device credential.
    V3ExportCertificate(V3ExportCertificateArgs),
    /// Root-sign a v3 device directory from public certificate files.
    V3Directory(V3DirectoryArgs),
    /// Publish a root-signed v3 directory with a short-lived file-backed session.
    V3PublishDirectory(V3PublishDirectoryArgs),
    /// Publish a device-signed v3 locator with a short-lived file-backed session.
    V3PublishLocator(V3PublishLocatorArgs),
    /// Resolve and verify every currently published v3 device for a Pubky ID.
    V3Resolve(V3ResolveArgs),
    /// Start a native v3 listener and write its device-signed locator.
    V3Listen(V3ListenArgs),
    /// Resolve a Pubky ID over v3, then read and send one bounded UTF-8 stdin line.
    V3Dial(V3DialArgs),
    /// Create a Pubky root identity and its first delegated device.
    Init(InitArgs),
    /// Issue another device credential from an existing root identity.
    IssueDevice(IssueDeviceArgs),
    /// Sign a rendezvous descriptor for Pubky public storage.
    Descriptor(DescriptorArgs),
    /// Sign in and publish a descriptor to the user's homeserver.
    Publish(PublishArgs),
    /// Resolve and verify a user's descriptor through Pubky/PKARR.
    Resolve(ResolveArgs),
    /// Sign a new identity up on a homeserver.
    Signup(SignupArgs),
    /// Run the public rendezvous service.
    Serve(ServeArgs),
    /// Listen for knocks and optionally echo accepted QUIC messages.
    Listen(ListenArgs),
    /// Dial a peer and send one test message.
    Dial(DialArgs),
}

#[derive(Debug, Args)]
struct V3InitArgs {
    /// Destination for the Pubky root secret. Keep this offline.
    #[arg(long, default_value = "pubky2pubky-v3.root.key.json")]
    root_out: PathBuf,
    /// Destination for the delegated online device credential.
    #[arg(long, default_value = "pubky2pubky-v3.device.key.json")]
    device_out: PathBuf,
    /// Private durable state initialized for this device's locator sequence.
    #[arg(long, default_value = "pubky2pubky-v3.publisher-state")]
    publisher_state_dir: PathBuf,
    /// Stable local device label.
    #[arg(long)]
    device_id: String,
    /// Device authorization lifetime in days (maximum 90).
    #[arg(long, default_value_t = 30)]
    days: u64,
}

#[derive(Debug, Args)]
struct V3IssueDeviceArgs {
    /// Offline root secret created by `v3-init`.
    #[arg(long)]
    root: PathBuf,
    /// Destination for the delegated online device credential.
    #[arg(long)]
    out: PathBuf,
    /// Private durable state initialized for this device's locator sequence.
    #[arg(long)]
    publisher_state_dir: PathBuf,
    /// Stable local device label.
    #[arg(long)]
    device_id: String,
    /// Device authorization lifetime in days (maximum 90).
    #[arg(long, default_value_t = 30)]
    days: u64,
}

#[derive(Debug, Args)]
struct V3ExportCertificateArgs {
    /// V3 device credential whose secrets remain in this process only.
    #[arg(long)]
    device: PathBuf,
    /// Destination for the public device certificate.
    #[arg(long)]
    out: PathBuf,
    /// Replace an existing destination.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct V3DirectoryArgs {
    /// Offline Pubky root secret.
    #[arg(long)]
    root: PathBuf,
    /// Public certificate file; repeat once for every authorized device.
    #[arg(
        long = "certificate",
        required_unless_present = "revoke_all",
        conflicts_with = "revoke_all"
    )]
    certificates: Vec<PathBuf>,
    /// Publish an explicitly empty directory, retiring every v3 device.
    #[arg(long)]
    revoke_all: bool,
    /// Strictly increasing offline generation. Losing it requires a new Pubky identity.
    #[arg(long)]
    generation: u64,
    /// Directory lifetime in days (maximum 90 and bounded by every certificate).
    #[arg(long, default_value_t = 30)]
    days: u64,
    /// Signed public directory output.
    #[arg(long, default_value = "pubky2pubky-v3.directory.json")]
    out: PathBuf,
    /// Replace an existing destination.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct V3PublishDirectoryArgs {
    /// Root secret used only to establish the development Pubky session.
    #[arg(long)]
    root: PathBuf,
    /// Root-signed v3 directory JSON.
    #[arg(long)]
    directory: PathBuf,
    /// Use the SDK's local testnet configuration.
    #[arg(long)]
    testnet: bool,
}

#[derive(Debug, Args)]
struct V3PublishLocatorArgs {
    /// Root secret used only to establish the development Pubky session.
    #[arg(long)]
    root: PathBuf,
    /// Public v3 device certificate corresponding to the locator.
    #[arg(long)]
    certificate: PathBuf,
    /// Device-signed v3 locator JSON.
    #[arg(long)]
    locator: PathBuf,
    /// Use the SDK's local testnet configuration.
    #[arg(long)]
    testnet: bool,
    /// Permit an HTTP loopback relay in a local-development locator.
    #[arg(long)]
    allow_insecure_local: bool,
}

#[derive(Debug, Args)]
struct V3ResolveArgs {
    /// Bare canonical z-base-32 Pubky identity.
    #[arg(long)]
    identity: String,
    /// Private directory holding durable anti-rollback state.
    #[arg(long)]
    state_dir: PathBuf,
    /// Use the SDK's local testnet configuration.
    #[arg(long)]
    testnet: bool,
    /// Permit HTTP loopback relay records for an explicitly local test.
    #[arg(long)]
    allow_insecure_local: bool,
}

#[derive(Debug, Args)]
struct V3TransportArgs {
    /// Locally trusted iroh relay origin; repeat for up to four relays.
    ///
    /// An optional visible-ASCII token (maximum 4096 bytes) is read only from
    /// `PUBKY2PUBKY_IROH_RELAY_TOKEN`.
    #[arg(
        long = "iroh-relay",
        env = "PUBKY2PUBKY_IROH_RELAY_URLS",
        value_delimiter = ',',
        required = true
    )]
    iroh_relays: Vec<Url>,
    /// PEM file containing an additional CA trusted for local relay TLS.
    #[arg(
        long = "iroh-relay-ca",
        env = "PUBKY2PUBKY_IROH_RELAY_CA_FILES",
        value_delimiter = ','
    )]
    relay_ca_files: Vec<PathBuf>,
    /// Permit an exact HTTP loopback relay for local development.
    #[arg(long)]
    allow_insecure_relay: bool,
}

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent CLI consent, lifecycle, network, and output switches"
)]
struct V3ListenArgs {
    /// Delegated v3 device credential. The Pubky root is never loaded.
    #[arg(long)]
    device: PathBuf,
    /// Private directory holding durable discovery anti-rollback state.
    #[arg(long)]
    state_dir: PathBuf,
    /// Destination for this live endpoint's device-signed locator.
    #[arg(long)]
    locator_out: PathBuf,
    /// Existing private state initialized when this exact device was issued.
    #[arg(long)]
    publisher_state_dir: PathBuf,
    /// Locator lifetime in minutes (maximum 15).
    #[arg(long, default_value_t = 10)]
    locator_minutes: u64,
    /// Application identifier accepted from authenticated peers.
    #[arg(long, default_value = "pubky2pubky/echo/3")]
    application: String,
    /// Echo the one bounded test message, then complete the close handshake.
    #[arg(long)]
    echo: bool,
    /// Accept every authenticated v3 Hello without prompting (scripted tests only).
    #[arg(long)]
    auto_accept: bool,
    /// Exit after handling one authenticated peer.
    #[arg(long)]
    once: bool,
    /// Replace an existing locator output file.
    #[arg(long)]
    force: bool,
    /// Acknowledge that public v3 contact may expose liveness and network addresses pre-consent.
    #[arg(long)]
    acknowledge_pre_consent_network_exposure: bool,
    /// Use the SDK's local testnet configuration for inbound identity verification.
    #[arg(long)]
    testnet: bool,
    #[command(flatten)]
    transport: V3TransportArgs,
}

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent CLI consent, response, network, and output switches"
)]
struct V3DialArgs {
    /// Delegated v3 device credential.
    #[arg(long)]
    device: PathBuf,
    /// Target bare canonical z-base-32 Pubky identity.
    #[arg(long)]
    peer: String,
    /// Select one published target device ID instead of deterministic failover.
    #[arg(long)]
    peer_device: Option<String>,
    /// Private directory holding durable discovery anti-rollback state.
    #[arg(long)]
    state_dir: PathBuf,
    /// Existing private state initialized when this exact device was issued.
    #[arg(long)]
    publisher_state_dir: PathBuf,
    /// Destination for this dialer's fresh, device-signed locator.
    #[arg(long)]
    locator_out: PathBuf,
    /// Locator lifetime in minutes (maximum 15).
    #[arg(long, default_value_t = 10)]
    locator_minutes: u64,
    /// Replace an existing locator output file.
    #[arg(long)]
    force: bool,
    /// Application identifier bound into the signed v3 handshake.
    #[arg(long, default_value = "pubky2pubky/echo/3")]
    application: String,
    /// Do not wait for an echo/response.
    #[arg(long)]
    no_response: bool,
    /// Acknowledge that public v3 contact may expose liveness and network addresses pre-consent.
    #[arg(long)]
    acknowledge_pre_consent_network_exposure: bool,
    /// Use the SDK's local testnet configuration for discovery.
    #[arg(long)]
    testnet: bool,
    #[command(flatten)]
    transport: V3TransportArgs,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Destination for the root secret.
    #[arg(long, default_value = "root.key.json")]
    root_out: PathBuf,
    /// Destination for the delegated device credential.
    #[arg(long, default_value = "device.key.json")]
    device_out: PathBuf,
    /// Stable local device label.
    #[arg(long)]
    device_id: String,
    /// Device certificate lifetime in days (maximum 90).
    #[arg(long, default_value_t = 30)]
    days: u64,
    /// Replace existing files.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct IssueDeviceArgs {
    /// Root secret created by `init`.
    #[arg(long)]
    root: PathBuf,
    /// Destination for the delegated device credential.
    #[arg(long)]
    out: PathBuf,
    /// Stable local device label.
    #[arg(long)]
    device_id: String,
    /// Device certificate lifetime in days (maximum 90).
    #[arg(long, default_value_t = 30)]
    days: u64,
    /// Replace an existing destination.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct DescriptorArgs {
    /// Pubky root secret.
    #[arg(long)]
    root: PathBuf,
    /// One or more wss:// endpoints; ws:// loopback is accepted for development.
    #[arg(long, required = true)]
    rendezvous: Vec<Url>,
    /// Descriptor lifetime in hours.
    #[arg(long, default_value_t = 24)]
    hours: u64,
    /// JSON output file, or stdout when omitted.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Replace an existing destination.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct PublishArgs {
    /// Pubky root secret for homeserver sign-in.
    #[arg(long)]
    root: PathBuf,
    /// Signed descriptor JSON.
    #[arg(long)]
    descriptor: PathBuf,
    /// Use the SDK's local testnet configuration.
    #[arg(long)]
    testnet: bool,
}

#[derive(Debug, Args)]
struct ResolveArgs {
    /// Bare z-base-32 Pubky identity.
    #[arg(long)]
    identity: String,
    /// Use the SDK's local testnet configuration.
    #[arg(long)]
    testnet: bool,
    /// Allow a loopback ws:// endpoint in a development descriptor.
    #[arg(long)]
    allow_insecure_local: bool,
}

#[derive(Debug, Args)]
struct SignupArgs {
    /// Pubky root secret.
    #[arg(long)]
    root: PathBuf,
    /// Homeserver's bare z-base-32 public key.
    #[arg(long)]
    homeserver: String,
    /// Optional homeserver signup token.
    #[arg(long)]
    token: Option<String>,
    /// Use the SDK's local testnet configuration.
    #[arg(long)]
    testnet: bool,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// HTTP/WebSocket listen address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    /// Secret authenticating calls from the co-located iroh relay.
    #[arg(long, env = "HPK_RELAY_AUTH_SECRET", hide_env_values = true)]
    relay_auth_secret: Option<String>,
}

#[derive(Debug, Args)]
struct TransportArgs {
    /// Self-hosted iroh relay URL; repeat for redundancy.
    #[arg(
        long = "iroh-relay",
        env = "HPK_IROH_RELAY_URLS",
        value_delimiter = ','
    )]
    iroh_relays: Vec<Url>,
    /// Optional bearer token accepted by every configured relay.
    #[arg(long, env = "HPK_IROH_RELAY_TOKEN", hide_env_values = true)]
    relay_token: Option<String>,
    /// PEM file containing an additional CA trusted for relay address discovery; repeat as needed.
    #[arg(
        long = "iroh-relay-ca",
        env = "HPK_IROH_RELAY_CA_FILES",
        value_delimiter = ','
    )]
    relay_ca_files: Vec<PathBuf>,
    /// Permit `<http://localhost>` iroh relays for local development.
    #[arg(long)]
    allow_insecure_relay: bool,
    /// Disable direct UDP paths and force iroh relay transport.
    #[arg(long)]
    relay_only: bool,
}

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches are clearest as booleans"
)]
struct ListenArgs {
    /// Delegated device credential.
    #[arg(long)]
    device: PathBuf,
    /// WebSocket rendezvous URL.
    #[arg(long)]
    rendezvous: Url,
    /// Explicitly consent to every received knock (intended for demos/tests).
    #[arg(long)]
    accept: bool,
    /// Echo each binary message until the caller sends the close marker.
    #[arg(long)]
    echo: bool,
    /// Exit after handling one knock.
    #[arg(long)]
    once: bool,
    #[command(flatten)]
    transport: TransportArgs,
}

#[derive(Debug, Args)]
struct DialArgs {
    /// Delegated device credential.
    #[arg(long)]
    device: PathBuf,
    /// Target bare z-base-32 Pubky identity.
    #[arg(long)]
    peer: String,
    /// Explicit rendezvous URL. When omitted, resolve the peer through Pubky.
    #[arg(long)]
    rendezvous: Option<Url>,
    /// UTF-8 test message.
    #[arg(long)]
    message: String,
    /// Application protocol placed in the pre-consent knock.
    #[arg(long, default_value = "hole-punchky/echo/1")]
    application: String,
    /// Use the SDK's local testnet for discovery.
    #[arg(long)]
    testnet: bool,
    #[command(flatten)]
    transport: TransportArgs,
    /// Do not wait for an echo/response.
    #[arg(long)]
    no_response: bool,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct RootKeyFile {
    version: u16,
    identity: String,
    secret: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();
    match Cli::parse().command {
        Command::V3Init(args) => v3_init(args).await,
        Command::V3IssueDevice(args) => v3_issue_device(args).await,
        Command::V3ExportCertificate(args) => v3_export_certificate(&args),
        Command::V3Directory(args) => v3_directory(&args),
        Command::V3PublishDirectory(args) => v3_publish_directory(args).await,
        Command::V3PublishLocator(args) => v3_publish_locator(args).await,
        Command::V3Resolve(args) => v3_resolve(args).await,
        Command::V3Listen(args) => v3_listen(args).await,
        Command::V3Dial(args) => v3_dial(args).await,
        Command::Init(args) => init(args),
        Command::IssueDevice(args) => issue_device(args),
        Command::Descriptor(args) => descriptor(args),
        Command::Publish(args) => publish(args).await,
        Command::Resolve(args) => resolve(args).await,
        Command::Signup(args) => signup(args).await,
        Command::Serve(args) => run_server(args).await,
        Command::Listen(args) => listen(args).await,
        Command::Dial(args) => dial(args).await,
    }
}

async fn v3_init(args: V3InitArgs) -> Result<()> {
    validate_days(args.days)?;
    if args.root_out == args.device_out {
        bail!("v3 root and device outputs must be different files");
    }
    ensure_new_output(&args.root_out)?;
    ensure_new_output(&args.device_out)?;
    let root = Keypair::random();
    let root_file = RootKeyFile {
        version: 1,
        identity: root.public_key().z32(),
        secret: URL_SAFE_NO_PAD.encode(root.secret()),
    };
    let device = issue_v3_credential(&root, args.device_id, args.days)?;
    write_json(&args.root_out, &root_file, false, true)?;
    if let Err(error) = write_json(&args.device_out, &device, false, true) {
        let _ = fs::remove_file(&args.root_out);
        return Err(error);
    }
    let state_result = match FileSequenceStore::new(&args.publisher_state_dir) {
        Ok(publisher_state) => {
            publisher_state
                .initialize_locator_publisher(device.identity(), device.control_signing_key())
                .await
        }
        Err(error) => Err(error),
    };
    if let Err(error) = state_result {
        let _ = fs::remove_file(&args.device_out);
        let _ = fs::remove_file(&args.root_out);
        return Err(error.into());
    }
    println!("identity={}", root.public_key().z32());
    println!("root={}", args.root_out.display());
    println!("device={}", args.device_out.display());
    println!("publisher_state={}", args.publisher_state_dir.display());
    Ok(())
}

async fn v3_issue_device(args: V3IssueDeviceArgs) -> Result<()> {
    validate_days(args.days)?;
    ensure_new_output(&args.out)?;
    let root = load_root(&args.root)?;
    let device = issue_v3_credential(&root, args.device_id, args.days)?;
    write_json(&args.out, &device, false, true)?;
    let state_result = match FileSequenceStore::new(&args.publisher_state_dir) {
        Ok(publisher_state) => {
            publisher_state
                .initialize_locator_publisher(device.identity(), device.control_signing_key())
                .await
        }
        Err(error) => Err(error),
    };
    if let Err(error) = state_result {
        let _ = fs::remove_file(&args.out);
        return Err(error.into());
    }
    println!("identity={}", device.identity());
    println!("device_id={}", device.device_id());
    println!("publisher_state={}", args.publisher_state_dir.display());
    Ok(())
}

fn v3_export_certificate(args: &V3ExportCertificateArgs) -> Result<()> {
    let device: V3DeviceCredential = read_secret_json(&args.device)?;
    device
        .certificate
        .verify(device.identity(), now_seconds())?;
    write_json(&args.out, &device.certificate, args.force, false)?;
    println!("certificate={}", args.out.display());
    Ok(())
}

fn v3_directory(args: &V3DirectoryArgs) -> Result<()> {
    validate_days(args.days)?;
    if args.generation == 0 {
        bail!("directory generation must be greater than zero");
    }
    let root = load_root(&args.root)?;
    let certificates = if args.revoke_all {
        Vec::new()
    } else {
        args.certificates
            .iter()
            .map(|path| read_json::<V3DeviceCertificate>(path))
            .collect::<Result<Vec<_>>>()?
    };
    let now = now_seconds();
    let requested_expiry = now + args.days * 24 * 60 * 60;
    let expires_at = certificates
        .iter()
        .map(|certificate| certificate.claims.expires_at)
        .min()
        .map_or(requested_expiry, |certificate_expiry| {
            requested_expiry.min(certificate_expiry)
        });
    if expires_at <= now {
        bail!("every directory certificate is expired");
    }
    let directory = V3DeviceDirectory::sign(&root, args.generation, certificates, now, expires_at)?;
    write_json(&args.out, &directory, args.force, false)?;
    println!("directory={}", args.out.display());
    eprintln!(
        "IMPORTANT: persist directory generation {} offline before publication; every later directory must use a strictly greater value",
        args.generation,
    );
    Ok(())
}

async fn v3_publish_directory(args: V3PublishDirectoryArgs) -> Result<()> {
    let root = load_root(&args.root)?;
    let directory: V3DeviceDirectory = read_json(&args.directory)?;
    if directory.claims.identity != root.public_key().z32() {
        bail!("directory and session root identity differ");
    }
    let session = pubky_client(args.testnet)?
        .signer(root)
        .signin_blocking(ClientId::new("pubky2pubky-v3")?)
        .await
        .context("signing into homeserver")?;
    publish_v3_directory(&session, &directory).await?;
    println!(
        "published=pubky://{}{}",
        directory.claims.identity,
        hole_punchky_protocol::V3_DIRECTORY_PATH
    );
    Ok(())
}

async fn v3_publish_locator(args: V3PublishLocatorArgs) -> Result<()> {
    let root = load_root(&args.root)?;
    let certificate: V3DeviceCertificate = read_json(&args.certificate)?;
    let locator: V3SignedLocator = read_json(&args.locator)?;
    if certificate.claims.identity != root.public_key().z32() {
        bail!("certificate and session root identity differ");
    }
    let session = pubky_client(args.testnet)?
        .signer(root)
        .signin_blocking(ClientId::new("pubky2pubky-v3")?)
        .await
        .context("signing into homeserver")?;
    publish_v3_locator(&session, &certificate, &locator, args.allow_insecure_local).await?;
    println!(
        "published=pubky://{}{}",
        certificate.claims.identity,
        locator.path()?
    );
    Ok(())
}

async fn v3_resolve(args: V3ResolveArgs) -> Result<()> {
    let resolver = v3_resolver(args.testnet, &args.state_dir, args.allow_insecure_local)?;
    let devices = resolver.resolve_devices(&args.identity).await?;
    println!("resolved_devices={}", devices.len());
    for device in devices {
        println!(
            "device={} endpoint={} sequence={} expires_at={} relays={}",
            device.certificate.claims.device_id,
            device.certificate.claims.iroh_endpoint_id,
            device.locator.claims.sequence,
            device.locator.claims.expires_at,
            device
                .locator
                .claims
                .relay_urls
                .iter()
                .map(Url::as_str)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    Ok(())
}

async fn v3_listen(args: V3ListenArgs) -> Result<()> {
    if !(1..=15).contains(&args.locator_minutes) {
        bail!("locator minutes must be between 1 and 15");
    }
    let credential: V3DeviceCredential = read_secret_json(&args.device)?;
    let resolver = v3_resolver(
        args.testnet,
        &args.state_dir,
        args.transport.allow_insecure_relay,
    )?;
    let config = v3_transport_config(
        &args.transport,
        vec![args.application.clone()],
        args.acknowledge_pre_consent_network_exposure,
    )?;
    let client = V3Client::bind(credential, resolver, config).await?;
    let publisher_state = FileSequenceStore::new(&args.publisher_state_dir)?;
    let locator = client
        .next_locator(
            &publisher_state,
            Duration::from_secs(args.locator_minutes * 60),
        )
        .await?;
    write_json(&args.locator_out, &locator, args.force, false)?;
    println!("listening identity={}", client.identity());
    println!("device_id={}", client.device_id());
    println!("locator={}", args.locator_out.display());
    println!("locator_path={}", locator.path()?);

    loop {
        let remaining = locator.claims.expires_at.saturating_sub(now_seconds());
        if remaining == 0 {
            bail!("v3 locator expired; generate and publish a refreshed locator");
        }
        let incoming = tokio::time::timeout(Duration::from_secs(remaining), client.next_incoming())
            .await
            .context(
                "v3 locator expired while waiting; generate and publish a refreshed locator",
            )??;
        println!(
            "request peer={} device={} application={}",
            incoming.identity(),
            incoming.device_id(),
            incoming.application()
        );
        if !args.auto_accept && !prompt_for_v3_consent()? {
            incoming.reject();
            println!("request=rejected");
            if args.once {
                break;
            }
            continue;
        }
        let peer = incoming.accept().await?;
        println!(
            "connected peer={} device={} path={:?}",
            peer.peer_identity(),
            peer.peer_device_id(),
            reported_path(&peer, false).await
        );
        let bytes = tokio::time::timeout(Duration::from_secs(15), peer.recv())
            .await
            .context("timed out waiting for v3 test message")??;
        if bytes == V3_CLOSE_MARKER {
            bail!("peer closed before sending a v3 test message");
        }
        println!("message={}", escape_terminal_bytes(&bytes));
        if args.echo {
            peer.send(&bytes).await?;
            let close = tokio::time::timeout(Duration::from_secs(5), peer.recv())
                .await
                .context("timed out waiting for v3 close marker")??;
            if close != V3_CLOSE_MARKER {
                bail!("peer returned an invalid v3 close marker");
            }
            peer.send(V3_CLOSE_ACK).await?;
            peer.finish(Duration::from_secs(5)).await?;
            peer.wait_for_peer_finish(Duration::from_secs(5)).await?;
        }
        peer.close().await?;
        if args.once {
            break;
        }
    }
    client.close().await;
    Ok(())
}

async fn v3_dial(args: V3DialArgs) -> Result<()> {
    if !(1..=15).contains(&args.locator_minutes) {
        bail!("locator minutes must be between 1 and 15");
    }
    let credential: V3DeviceCredential = read_secret_json(&args.device)?;
    let resolver = v3_resolver(
        args.testnet,
        &args.state_dir,
        args.transport.allow_insecure_relay,
    )?;
    let config = v3_transport_config(
        &args.transport,
        vec![args.application.clone()],
        args.acknowledge_pre_consent_network_exposure,
    )?;
    let client = V3Client::bind(credential, resolver, config).await?;
    let publisher_state = FileSequenceStore::new(&args.publisher_state_dir)?;
    let locator = client
        .next_locator(
            &publisher_state,
            Duration::from_secs(args.locator_minutes * 60),
        )
        .await?;
    write_json(&args.locator_out, &locator, args.force, false)?;
    println!("local_locator={}", args.locator_out.display());
    println!("local_locator_path={}", locator.path()?);
    wait_for_locator_publication()?;
    let message = read_v3_message_from_stdin()?;
    let peer = client
        .dial(&args.peer, args.peer_device.as_deref(), &args.application)
        .await?;
    println!(
        "connected peer={} device={} path={:?}",
        peer.peer_identity(),
        peer.peer_device_id(),
        reported_path(&peer, false).await
    );
    peer.send(&message).await?;
    drop(message);
    if !args.no_response {
        let response = tokio::time::timeout(Duration::from_secs(15), peer.recv())
            .await
            .context("timed out waiting for v3 response")??;
        println!("response={}", escape_terminal_bytes(&response));
        peer.send(V3_CLOSE_MARKER).await?;
        let acknowledgement = tokio::time::timeout(Duration::from_secs(5), peer.recv())
            .await
            .context("timed out waiting for v3 close acknowledgement")??;
        if acknowledgement != V3_CLOSE_ACK {
            bail!("peer returned an invalid v3 close acknowledgement");
        }
        peer.finish(Duration::from_secs(5)).await?;
        peer.wait_for_peer_finish(Duration::from_secs(5)).await?;
    }
    peer.close().await?;
    client.close().await;
    Ok(())
}

fn init(args: InitArgs) -> Result<()> {
    validate_days(args.days)?;
    let root = Keypair::random();
    let root_file = RootKeyFile {
        version: 1,
        identity: root.public_key().z32(),
        secret: URL_SAFE_NO_PAD.encode(root.secret()),
    };
    let device = issue_credential(&root, args.device_id, args.days)?;
    write_json(&args.root_out, &root_file, args.force, true)?;
    if let Err(error) = write_json(&args.device_out, &device, args.force, true) {
        let _ = fs::remove_file(&args.root_out);
        return Err(error);
    }
    println!("identity={}", root.public_key().z32());
    println!("root={}", args.root_out.display());
    println!("device={}", args.device_out.display());
    Ok(())
}

fn issue_device(args: IssueDeviceArgs) -> Result<()> {
    validate_days(args.days)?;
    let root = load_root(&args.root)?;
    let device = issue_credential(&root, args.device_id, args.days)?;
    write_json(&args.out, &device, args.force, true)?;
    println!("identity={}", device.identity());
    println!("device_id={}", device.device_id());
    Ok(())
}

fn descriptor(args: DescriptorArgs) -> Result<()> {
    let root = load_root(&args.root)?;
    if args.hours == 0 || args.hours > 24 * 30 {
        bail!("descriptor hours must be between 1 and 720");
    }
    let endpoints = args
        .rendezvous
        .into_iter()
        .enumerate()
        .map(|(index, signaling_url)| RendezvousEndpoint {
            signaling_url,
            priority: u16::try_from(index).unwrap_or(u16::MAX),
            region: None,
        })
        .collect();
    let signed =
        RendezvousDescriptor::sign(&root, endpoints, now_seconds() + args.hours * 60 * 60)?;
    if let Some(path) = args.out {
        write_json(&path, &signed, args.force, false)?;
        println!("descriptor={}", path.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&signed)?);
    }
    Ok(())
}

async fn publish(args: PublishArgs) -> Result<()> {
    let root = load_root(&args.root)?;
    let descriptor: RendezvousDescriptor = read_json(&args.descriptor)?;
    if descriptor.claims.identity != root.public_key().z32() {
        bail!("descriptor and root identity differ");
    }
    let pubky = pubky_client(args.testnet)?;
    let client_id = ClientId::new("hole-punchky")?;
    let session = pubky
        .signer(root)
        .signin_blocking(client_id)
        .await
        .context("signing into homeserver")?;
    publish_descriptor(&session, &descriptor).await?;
    println!(
        "published=pubky://{}{}",
        descriptor.claims.identity, DESCRIPTOR_PATH
    );
    Ok(())
}

async fn resolve(args: ResolveArgs) -> Result<()> {
    let resolver = PubkyResolver::new(pubky_client(args.testnet)?)
        .allow_insecure_local(args.allow_insecure_local);
    let url = resolve_rendezvous_url(&resolver, &args.identity).await?;
    println!("{url}");
    Ok(())
}

async fn signup(args: SignupArgs) -> Result<()> {
    let root = load_root(&args.root)?;
    let homeserver = PublicKey::try_from_z32(&args.homeserver)
        .map_err(|error| anyhow::anyhow!("invalid homeserver key: {error}"))?;
    pubky_client(args.testnet)?
        .signer(root)
        .signup(&homeserver, args.token.as_deref())
        .await
        .context("homeserver signup failed")?;
    println!("signup=ok");
    Ok(())
}

async fn run_server(args: ServeArgs) -> Result<()> {
    if args.relay_auth_secret.as_deref().is_some_and(str::is_empty) {
        bail!("--relay-auth-secret must not be empty");
    }
    serve(ServerConfig {
        bind: args.bind,
        relay_auth_secret: args.relay_auth_secret,
        ..ServerConfig::default()
    })
    .await
}

async fn listen(args: ListenArgs) -> Result<()> {
    let credential: DeviceCredential = read_secret_json(&args.device)?;
    let client_config = transport_config(&args.transport)?;
    let client = RendezvousClient::connect(args.rendezvous, credential, client_config).await?;
    println!("listening identity={}", client.identity());
    loop {
        let knock = client.next_knock().await?;
        println!(
            "knock from={} device={} application={}",
            knock.knock().identity,
            knock.knock().device_id,
            knock.knock().application
        );
        if args.accept {
            let peer = client.accept(knock).await?;
            println!(
                "connected path={:?}",
                reported_path(&peer, args.transport.relay_only).await
            );
            if args.echo {
                loop {
                    let bytes = peer.recv().await?;
                    if bytes == CLOSE_MARKER {
                        peer.send(CLOSE_ACK).await?;
                        peer.finish(Duration::from_secs(5)).await?;
                        peer.wait_for_peer_finish(Duration::from_secs(5)).await?;
                        break;
                    }
                    peer.send(&bytes).await?;
                }
            } else {
                let bytes = peer.recv().await?;
                println!("message={}", String::from_utf8_lossy(&bytes));
            }
            peer.close().await?;
        } else {
            client.reject(&knock, "listener requires --accept").await?;
        }
        if args.once {
            break;
        }
    }
    client.close().await;
    Ok(())
}

async fn dial(args: DialArgs) -> Result<()> {
    let credential: DeviceCredential = read_secret_json(&args.device)?;
    let client_config = transport_config(&args.transport)?;
    let client = if let Some(url) = args.rendezvous {
        RendezvousClient::connect(url, credential, client_config.clone()).await?
    } else {
        let resolver =
            PubkyResolver::new(pubky_client(args.testnet)?).allow_insecure_local(args.testnet);
        RendezvousClient::connect_resolved(&resolver, &args.peer, credential, client_config).await?
    };
    let peer = client
        .dial(
            &args.peer,
            DialOptions {
                application: args.application,
                ..DialOptions::default()
            },
        )
        .await?;
    println!(
        "connected path={:?}",
        reported_path(&peer, args.transport.relay_only).await
    );
    peer.send_text(&args.message).await?;
    if !args.no_response {
        let response = tokio::time::timeout(Duration::from_secs(15), peer.recv())
            .await
            .context("timed out waiting for response")??;
        println!("response={}", String::from_utf8_lossy(&response));
        peer.send(CLOSE_MARKER).await?;
        let acknowledgement = tokio::time::timeout(Duration::from_secs(5), peer.recv())
            .await
            .context("timed out waiting for close acknowledgement")??;
        if acknowledgement != CLOSE_ACK {
            bail!("peer returned an invalid close acknowledgement");
        }
        peer.finish(Duration::from_secs(5)).await?;
        peer.wait_for_peer_finish(Duration::from_secs(5)).await?;
    }
    peer.close().await?;
    client.close().await;
    Ok(())
}

fn issue_credential(root: &Keypair, device_id: String, days: u64) -> Result<DeviceCredential> {
    let now = now_seconds();
    DeviceCredential::issue(
        root,
        device_id,
        now.saturating_sub(1),
        now + days * 24 * 60 * 60,
    )
    .map_err(Into::into)
}

fn issue_v3_credential(root: &Keypair, device_id: String, days: u64) -> Result<V3DeviceCredential> {
    let now = now_seconds();
    V3DeviceCredential::issue(
        root,
        device_id,
        now.saturating_sub(1),
        now + days * 24 * 60 * 60,
    )
    .map_err(Into::into)
}

fn validate_days(days: u64) -> Result<()> {
    if !(1..=90).contains(&days) {
        bail!("device certificate days must be between 1 and 90");
    }
    Ok(())
}

fn prompt_for_v3_consent() -> Result<bool> {
    let answer = read_bounded_stdin_line(
        "Accept authenticated v3 request? [y/N] ",
        16,
        "consent response",
    )?;
    let answer = std::str::from_utf8(&answer).context("consent response is not UTF-8")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

fn wait_for_locator_publication() -> Result<()> {
    let _answer = read_bounded_stdin_line(
        "Publish this locator with v3-publish-locator in another terminal, then press Enter to dial: ",
        16,
        "locator publication response",
    )?;
    Ok(())
}

fn read_v3_message_from_stdin() -> Result<Zeroizing<Vec<u8>>> {
    let message = read_bounded_stdin_line(
        "Test message (one UTF-8 line, maximum 65536 bytes): ",
        V3_CLI_MESSAGE_MAX_BYTES,
        "v3 test message",
    )?;
    if message.is_empty() {
        bail!("v3 test message must not be empty");
    }
    std::str::from_utf8(&message).context("v3 test message is not UTF-8")?;
    Ok(message)
}

fn read_bounded_stdin_line(
    prompt: &str,
    max_bytes: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .with_context(|| format!("writing {label} prompt"))?;
    let stdin = io::stdin();
    let mut locked = stdin.lock();
    read_bounded_line(&mut locked, max_bytes, label)
}

fn read_bounded_line<R: io::BufRead>(
    reader: &mut R,
    max_bytes: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let limit = u64::try_from(max_bytes)
        .context("stdin size limit does not fit u64")?
        .saturating_add(2);
    let mut bytes = Zeroizing::new(Vec::with_capacity(max_bytes.min(4096)));
    let mut limited = reader.take(limit);
    let count = limited
        .read_until(b'\n', &mut bytes)
        .with_context(|| format!("reading {label}"))?;
    if count == 0 {
        bail!("stdin closed before {label} was provided");
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > max_bytes {
        bail!("{label} exceeds the {max_bytes}-byte limit");
    }
    Ok(bytes)
}

fn escape_terminal_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .flat_map(char::escape_default)
        .collect()
}

fn load_root(path: &Path) -> Result<Keypair> {
    let file: RootKeyFile = read_secret_json(path)?;
    if file.version != 1 {
        bail!("unsupported root key file version {}", file.version);
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&file.secret)
            .context("invalid base64url root secret")?,
    );
    let secret = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("root secret must contain 32 bytes"))?,
    );
    let root = Keypair::from_secret(&secret);
    if root.public_key().z32() != file.identity {
        bail!("root key file identity does not match its secret");
    }
    Ok(root)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("decoding {}", path.display()))
}

fn read_secret_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        Zeroizing::new(fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    serde_json::from_slice(&bytes).with_context(|| format!("decoding {}", path.display()))
}

fn ensure_new_output(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to replace existing output {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("checking output {}", path.display())),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T, force: bool, secret: bool) -> Result<()> {
    let encoded = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if force {
        options.truncate(false);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(if secret { 0o600 } else { 0o644 })
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {}", path.display()))?;
    if !metadata.is_file() {
        bail!("output {} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            bail!("output {} must have exactly one hard link", path.display());
        }
    }
    if secret {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    if force {
        file.set_len(0)
            .with_context(|| format!("truncating {}", path.display()))?;
    }
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

fn pubky_client(testnet: bool) -> Result<Pubky> {
    if testnet {
        Pubky::testnet().context("creating Pubky testnet client")
    } else {
        Pubky::new().context("creating Pubky client")
    }
}

fn v3_resolver(
    testnet: bool,
    state_dir: &Path,
    allow_insecure_loopback_relay: bool,
) -> Result<Arc<dyn V3DeviceResolver>> {
    let sequences = Arc::new(FileSequenceStore::new(state_dir)?);
    Ok(Arc::new(
        PubkyV3Resolver::new(pubky_client(testnet)?, sequences).with_config(V3DiscoveryConfig {
            allow_insecure_loopback_relay,
            ..V3DiscoveryConfig::default()
        }),
    ))
}

fn v3_transport_config(
    args: &V3TransportArgs,
    accepted_applications: Vec<String>,
    disclosure_acknowledged: bool,
) -> Result<V3ClientConfig> {
    if !disclosure_acknowledged {
        bail!(
            "v3 direct contact requires --acknowledge-pre-consent-network-exposure; see docs/v3.md"
        );
    }
    if args.iroh_relays.is_empty() || args.iroh_relays.len() > 4 {
        bail!("v3 requires between one and four --iroh-relay values");
    }
    if args.relay_ca_files.len() > 16 {
        bail!("v3 accepts at most 16 --iroh-relay-ca files");
    }
    let relay_token = v3_relay_token_from_env()?;
    let trusted_relays = args
        .iroh_relays
        .iter()
        .cloned()
        .map(|url| {
            let relay = IrohRelayConfig::new(url);
            relay_token
                .as_ref()
                .map_or(relay.clone(), |token| relay.with_auth_token(token.as_str()))
        })
        .collect();
    let mut config = V3ClientConfig::direct(
        PublicContactDisclosure::AcknowledgePreConsentNetworkExposure,
        accepted_applications,
    );
    config.trusted_relays = trusted_relays;
    config.relay_ca_certificates = read_relay_ca_certificates(&args.relay_ca_files)?;
    config.allow_insecure_loopback_relay = args.allow_insecure_relay;
    Ok(config)
}

fn v3_relay_token_from_env() -> Result<Option<Zeroizing<String>>> {
    let token = match std::env::var(V3_RELAY_TOKEN_ENV) {
        Ok(token) => token,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{V3_RELAY_TOKEN_ENV} must contain UTF-8")
        }
    };
    validate_v3_relay_token(token).map(Some)
}

fn validate_v3_relay_token(token: String) -> Result<Zeroizing<String>> {
    let token = Zeroizing::new(token);
    if token.is_empty() {
        bail!("{V3_RELAY_TOKEN_ENV} must not be empty");
    }
    if token.len() > V3_RELAY_TOKEN_MAX_BYTES {
        bail!("{V3_RELAY_TOKEN_ENV} exceeds the {V3_RELAY_TOKEN_MAX_BYTES}-byte limit");
    }
    if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!("{V3_RELAY_TOKEN_ENV} must contain only visible ASCII without whitespace");
    }
    Ok(token)
}

fn transport_config(args: &TransportArgs) -> Result<RendezvousClientConfig> {
    if args.relay_token.as_deref().is_some_and(str::is_empty) {
        bail!("--relay-token must not be empty");
    }
    if args.relay_token.is_some() && args.iroh_relays.is_empty() {
        bail!("--relay-token requires at least one --iroh-relay");
    }
    if !args.relay_ca_files.is_empty() && args.iroh_relays.is_empty() {
        bail!("--iroh-relay-ca requires at least one --iroh-relay");
    }
    let relay_servers = args
        .iroh_relays
        .iter()
        .cloned()
        .map(|url| {
            let relay = IrohRelayConfig::new(url);
            args.relay_token
                .as_ref()
                .map_or(relay.clone(), |token| relay.with_auth_token(token.as_str()))
        })
        .collect();
    Ok(RendezvousClientConfig {
        relay_servers,
        relay_ca_certificates: read_relay_ca_certificates(&args.relay_ca_files)?,
        allow_insecure_relay: args.allow_insecure_relay,
        path_policy: if args.relay_only {
            PathPolicy::RelayOnly
        } else {
            PathPolicy::DirectWithRelayFallback
        },
        ..RendezvousClientConfig::default()
    })
}

fn read_relay_ca_certificates(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    for path in paths {
        let original_len = certificates.len();
        let pem_blocks = CertificateDer::pem_file_iter(path)
            .with_context(|| format!("opening relay CA file {}", path.display()))?;
        for certificate in pem_blocks {
            let certificate =
                certificate.with_context(|| format!("reading relay CA file {}", path.display()))?;
            certificates.push(certificate.as_ref().to_vec());
        }
        if certificates.len() == original_len {
            bail!(
                "relay CA file {} contains no CERTIFICATE PEM block",
                path.display()
            );
        }
    }
    Ok(certificates)
}

async fn reported_path(peer: &Peer, relay_only: bool) -> ConnectionPath {
    let preferred = if relay_only {
        ConnectionPath::Relayed
    } else {
        ConnectionPath::Direct
    };
    peer.wait_for_path(preferred, Duration::from_secs(5)).await
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn clap_v3_contract_has_no_conflicts() {
        Cli::command().debug_assert();
    }

    #[test]
    fn v3_directory_requires_certificates_or_explicit_revocation() {
        assert!(
            Cli::try_parse_from([
                "pubky2pubky",
                "v3-directory",
                "--root",
                "root.json",
                "--generation",
                "2",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "pubky2pubky",
            "v3-directory",
            "--root",
            "root.json",
            "--generation",
            "2",
            "--revoke-all",
        ])
        .unwrap_or_else(|error| panic!("parsing explicit v3 revocation: {error}"));
        assert!(matches!(cli.command, Command::V3Directory(_)));
    }

    #[test]
    fn v3_transport_rejects_missing_disclosure_acknowledgement() {
        let relay = Url::parse("https://relay.example/")
            .unwrap_or_else(|error| panic!("test URL: {error}"));
        let args = V3TransportArgs {
            iroh_relays: vec![relay],
            relay_ca_files: Vec::new(),
            allow_insecure_relay: false,
        };
        let error = v3_transport_config(&args, vec!["pubky2pubky/echo/3".to_owned()], false)
            .err()
            .unwrap_or_else(|| panic!("missing v3 disclosure acknowledgement was accepted"));
        assert!(error.to_string().contains("acknowledge-pre-consent"));
    }

    #[test]
    fn untrusted_peer_bytes_cannot_emit_terminal_controls() {
        let escaped = escape_terminal_bytes(b"hello\n\x1b]52;c;clipboard\x07");
        assert!(!escaped.chars().any(char::is_control));
        assert!(escaped.contains("\\n"));
        assert!(escaped.contains("\\u{1b}"));
        assert!(escaped.contains("\\u{7}"));
    }

    #[test]
    fn v3_rejects_message_and_relay_token_plaintext_arguments() {
        let base = [
            "pubky2pubky",
            "v3-dial",
            "--device",
            "device.json",
            "--peer",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--state-dir",
            "observed",
            "--publisher-state-dir",
            "publisher",
            "--locator-out",
            "locator.json",
            "--iroh-relay",
            "https://relay.example/",
            "--acknowledge-pre-consent-network-exposure",
        ];
        assert!(Cli::try_parse_from(base).is_ok());
        let mut with_message = base.to_vec();
        with_message.extend(["--message", "secret message"]);
        assert!(Cli::try_parse_from(with_message).is_err());

        let mut with_token = base.to_vec();
        with_token.extend(["--relay-token", "secret-token"]);
        assert!(Cli::try_parse_from(with_token).is_err());
    }

    #[test]
    fn v3_relay_token_validation_is_bounded_and_header_safe() {
        assert!(validate_v3_relay_token("token-123".to_owned()).is_ok());
        assert!(validate_v3_relay_token(String::new()).is_err());
        assert!(validate_v3_relay_token("token\nheader".to_owned()).is_err());
        assert!(validate_v3_relay_token("x".repeat(V3_RELAY_TOKEN_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn v3_stdin_line_reader_enforces_bound_and_strips_line_ending() {
        let mut valid = io::Cursor::new(b"hello\r\nnext\n");
        assert_eq!(
            read_bounded_line(&mut valid, 5, "test")
                .unwrap_or_else(|error| panic!("reading bounded line: {error}"))
                .as_slice(),
            b"hello"
        );
        let mut oversized = io::Cursor::new(vec![b'x'; V3_CLI_MESSAGE_MAX_BYTES + 1]);
        assert!(read_bounded_line(&mut oversized, V3_CLI_MESSAGE_MAX_BYTES, "test").is_err());
    }
}
