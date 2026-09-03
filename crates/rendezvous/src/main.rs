//! Standalone Hole Punchky rendezvous server.

use std::{net::SocketAddr, time::Duration};

use anyhow::Context as _;
use clap::Parser;
use hole_punchky_rendezvous::{ServerConfig, serve};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Arguments {
    /// HTTP/WebSocket listen address.
    #[arg(long, env = "HPK_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    /// Secret authenticating calls from the co-located iroh relay.
    #[arg(long, env = "HPK_RELAY_AUTH_SECRET", hide_env_values = true)]
    relay_auth_secret: Option<String>,
    /// Rendezvous session lifetime in seconds.
    #[arg(long, env = "HPK_SESSION_TTL_SECONDS", default_value_t = 120)]
    session_ttl_seconds: u64,
    /// Maximum WebSocket JSON message size.
    #[arg(long, env = "HPK_MAX_MESSAGE_BYTES", default_value_t = 65_536)]
    max_message_bytes: usize,
    /// Maximum knocks per identity per rolling minute.
    #[arg(long, env = "HPK_KNOCKS_PER_MINUTE", default_value_t = 30)]
    knocks_per_minute: usize,
    /// Maximum active and replay-tracked session identifiers retained in memory.
    #[arg(long, env = "HPK_MAX_SESSIONS", default_value_t = 10_000)]
    max_sessions: usize,
    /// Maximum connected sockets for one Pubky identity.
    #[arg(long, env = "HPK_MAX_CONNECTIONS_PER_IDENTITY", default_value_t = 16)]
    max_connections_per_identity: usize,
    /// Maximum connected sockets across all identities.
    #[arg(long, env = "HPK_MAX_CONNECTIONS", default_value_t = 10_000)]
    max_connections: usize,
    /// Maximum registration nonces retained for replay detection.
    #[arg(long, env = "HPK_MAX_REGISTRATION_NONCES", default_value_t = 50_000)]
    max_registration_nonces: usize,
    /// Comma-separated accepted browser origins; empty accepts all.
    #[arg(long, env = "HPK_ALLOWED_ORIGINS", value_delimiter = ',')]
    allowed_origins: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Arguments::parse();
    if args.session_ttl_seconds == 0 {
        anyhow::bail!("session lifetime must be non-zero");
    }
    if args.relay_auth_secret.as_deref().is_some_and(str::is_empty) {
        anyhow::bail!("HPK_RELAY_AUTH_SECRET must not be empty");
    }
    if args.max_message_bytes < 1_024 {
        anyhow::bail!("HPK_MAX_MESSAGE_BYTES must be at least 1024");
    }
    let config = ServerConfig {
        bind: args.bind,
        relay_auth_secret: args.relay_auth_secret,
        session_ttl: Duration::from_secs(args.session_ttl_seconds),
        max_message_bytes: args.max_message_bytes,
        knocks_per_minute: args.knocks_per_minute,
        max_sessions: args.max_sessions,
        max_connections_per_identity: args.max_connections_per_identity,
        max_connections: args.max_connections,
        max_registration_nonces: args.max_registration_nonces,
        allowed_origins: args.allowed_origins,
        ..ServerConfig::default()
    };
    serve(config).await.context("rendezvous server failed")
}
