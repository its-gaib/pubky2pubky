# syntax=docker/dockerfile:1.7
FROM rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates ./crates
RUN CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_STRIP=symbols \
    cargo build --locked --release -p hole-punchky-rendezvous \
    && install -Dm755 \
        target/release/hole-punchky-rendezvous \
        /out/hole-punchky-rendezvous \
    && cargo clean \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/hole-punchky-rendezvous /usr/local/bin/hole-punchky-rendezvous
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["hole-punchky-rendezvous"]
