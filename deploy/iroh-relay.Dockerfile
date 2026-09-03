# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS downloader

ARG TARGETARCH=amd64
ARG IROH_VERSION=1.1.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /download
RUN case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu; checksum=4cc2053654985d023ee7a5e510c2f8e074daf900d466ed415dbb34b83b0a9271 ;; \
      arm64) target=aarch64-unknown-linux-gnu; checksum=5a676fd0f540f09a08f80ef1c70bdb22bbfbf56078bc32e98f532edea439c489 ;; \
      *) printf 'unsupported architecture: %s\n' "$TARGETARCH" >&2; exit 1 ;; \
    esac \
    && archive="iroh-relay-v${IROH_VERSION}-${target}.tar.gz" \
    && curl --fail --location --silent --show-error \
      --output "$archive" \
      "https://github.com/n0-computer/iroh/releases/download/v${IROH_VERSION}/${archive}" \
    && printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict \
    && tar --extract --gzip --file "$archive" \
    && install -Dm755 iroh-relay /out/iroh-relay
RUN openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /out/ca.key -out /out/ca.crt -days 3650 \
      -subj "/CN=Hole Punchky development CA" \
      -addext "basicConstraints=critical,CA:true" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
    && openssl req -newkey rsa:2048 -nodes \
      -keyout /out/relay.key -out /out/relay.csr \
      -subj "/CN=localhost" \
    && printf "%s\\n" \
      "[v3_server]" \
      "basicConstraints=critical,CA:false" \
      "keyUsage=critical,digitalSignature,keyEncipherment" \
      "extendedKeyUsage=serverAuth" \
      "subjectAltName=DNS:localhost,IP:127.0.0.1" \
      > /out/relay.ext \
    && openssl x509 -req -in /out/relay.csr \
      -CA /out/ca.crt -CAkey /out/ca.key -CAcreateserial \
      -out /out/relay.crt -days 3650 -extfile /out/relay.ext -extensions v3_server \
    && chmod 0400 /out/relay.key \
    && chmod 0444 /out/relay.crt /out/ca.crt

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=downloader /out/iroh-relay /usr/local/bin/iroh-relay
COPY --from=downloader /out/relay.key /etc/iroh-relay/relay.key
COPY --from=downloader /out/relay.crt /etc/iroh-relay/relay.crt
COPY --from=downloader /out/ca.crt /etc/iroh-relay/relay-ca.crt
RUN chown 65532:65532 /etc/iroh-relay/relay.key /etc/iroh-relay/relay.crt /etc/iroh-relay/relay-ca.crt \
    && chmod 0400 /etc/iroh-relay/relay.key \
    && chmod 0444 /etc/iroh-relay/relay.crt /etc/iroh-relay/relay-ca.crt
COPY deploy/iroh-relay.toml /etc/iroh-relay.toml
USER 65532:65532
EXPOSE 3340
EXPOSE 7842/udp
ENTRYPOINT ["iroh-relay"]
CMD ["--dev", "--config-path", "/etc/iroh-relay.toml"]
