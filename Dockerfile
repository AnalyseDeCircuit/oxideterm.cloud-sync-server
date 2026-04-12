# ── Build stage ──
FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || \
    cargo build --release
RUN cp target/*/release/oxideterm-cloud-sync-server /build/server || \
    cp target/release/oxideterm-cloud-sync-server /build/server

# ── Runtime stage ──
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tini
RUN addgroup -S oxideterm && adduser -S oxideterm -G oxideterm

# Data volume
RUN mkdir -p /data && chown oxideterm:oxideterm /data
VOLUME /data

COPY --from=builder /build/server /usr/local/bin/oxideterm-cloud-sync-server

USER oxideterm
EXPOSE 8730

ENTRYPOINT ["tini", "--"]
CMD ["oxideterm-cloud-sync-server", "--listen", "0.0.0.0:8730", "--db-path", "/data/sync.db"]
