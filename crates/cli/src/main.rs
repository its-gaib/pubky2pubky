//! Operational CLI for identities, descriptors, rendezvous, and test connections.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand};
use hole_punchky_client::{
    ConnectionPath, DialOptions, IrohRelayConfig, PathPolicy, Peer, PubkyResolver,
    RendezvousClient, RendezvousClientConfig, publish_descriptor, resolve_rendezvous_url,
};
use hole_punchky_protocol::{
    DESCRIPTOR_PATH, DeviceCredential, RendezvousDescriptor, RendezvousEndpoint, now_seconds,
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

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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

fn validate_days(days: u64) -> Result<()> {
    if !(1..=90).contains(&days) {
        bail!("device certificate days must be between 1 and 90");
    }
    Ok(())
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

fn write_json<T: Serialize>(path: &Path, value: &T, force: bool, secret: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if force {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    if secret {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    let encoded = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn pubky_client(testnet: bool) -> Result<Pubky> {
    if testnet {
        Pubky::testnet().context("creating Pubky testnet client")
    } else {
        Pubky::new().context("creating Pubky client")
    }
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
