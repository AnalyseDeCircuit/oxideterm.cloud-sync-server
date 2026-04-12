# OxideTerm Cloud Sync Server

Self-hosted cloud sync backend for [OxideTerm](https://github.com/AnalyseDeCircuit/oxideterm). Encrypted at rest, Docker-ready, single binary, zero external dependencies.

[中文说明](docs/README.zh-CN.md)

## Features

- **Encryption at rest** — ChaCha20-Poly1305 AEAD with a master key you control. Data is never stored in plaintext.
- **Structured sync** — Compatible with OxideTerm Cloud Sync plugin's `structured-v1` protocol. Per-section objects for connections, forwards, settings, and more.
- **Concurrency control** — ETag-based optimistic locking prevents data loss from simultaneous uploads.
- **Scoped API tokens** — SHA-256 hashed before storage. Each token is restricted to a namespace pattern (`*`, `exact`, or `prefix*`).
- **Admin web panel** — Embedded SPA for managing tokens and namespaces. Protected by bcrypt + JWT.
- **Single binary** — Rust + [redb](https://github.com/cberner/redb). No external database required. ~10 MB Docker image.

## Why Self-Host?

| Aspect | Self-Hosted (This Server) | Third-Party / Generic Sync |
|---|---|---|
| Encryption at rest | ChaCha20-Poly1305, key held by you | Varies; often plaintext |
| Protocol support | Full `structured-v1` with per-section objects | Typically blob-only |
| Concurrency control | ETag-based optimistic locking | Rarely supported |
| Token scoping | Per-namespace pattern matching | Usually a single global key |
| Admin panel | Built-in SPA | External tooling required |
| Data sovereignty | You choose where data lives | Depends on provider |

## Quick Start

### Docker (Recommended)

```bash
# Generate an encryption key
export ENCRYPTION_KEY=$(openssl rand -hex 32)
export ADMIN_PASSWORD=your-secure-password

docker run -d \
  --name oxideterm-cloud-sync \
  -p 8730:8730 \
  -v oxideterm-sync-data:/data \
  -e ENCRYPTION_KEY=$ENCRYPTION_KEY \
  -e ADMIN_PASSWORD=$ADMIN_PASSWORD \
  ghcr.io/analysedecircuit/oxideterm.cloud-sync-server:latest
```

### Docker Compose

```bash
cp .env.example .env
# Edit .env — fill in ENCRYPTION_KEY and ADMIN_PASSWORD
docker compose up -d
```

### From Source

```bash
cargo build --release
./target/release/oxideterm-cloud-sync-server \
  --listen 0.0.0.0:8730 \
  --db-path ./data/sync.db \
  --encryption-key $(openssl rand -hex 32) \
  --admin-password your-password
```

## Configuration

| Environment Variable | CLI Flag | Default | Description |
|---|---|---|---|
| `LISTEN_ADDR` | `--listen` | `0.0.0.0:8730` | Listen address |
| `DB_PATH` | `--db-path` | `/data/sync.db` | Database file path |
| `ENCRYPTION_KEY` | `--encryption-key` | *(none)* | 32-byte hex key for encryption at rest |
| `ADMIN_PASSWORD` | `--admin-password` | *(none)* | Admin panel password (panel disabled if unset) |
| `MAX_BLOB_SIZE` | `--max-blob-size` | `67108864` (64 MiB) | Max blob upload size |
| `MAX_OBJECT_SIZE` | `--max-object-size` | `16777216` (16 MiB) | Max object upload size |
| `RUST_LOG` | — | `info` | Log level filter |

## Connecting from OxideTerm

1. Open OxideTerm → Plugins → Cloud Sync
2. Select **HTTP JSON** backend
3. Set endpoint to `http://your-server:8730`
4. In the admin panel (`http://your-server:8730/admin`), create an API token
5. Paste the token into the plugin's "Bearer Token" field
6. Click "Upload" to sync

## Security

### Encryption

When `ENCRYPTION_KEY` is set:
- All blobs and objects are encrypted with ChaCha20-Poly1305 before writing to disk
- Each write uses a random 12-byte nonce prepended to the ciphertext
- Metadata (JSON) is stored in plaintext for server-side query support
- **If you lose the key, your data cannot be recovered**

When `ENCRYPTION_KEY` is *not* set:
- Data is stored in plaintext (not recommended for production)

### Authentication

- API tokens are hashed with SHA-256 before storage — the raw token is shown once at creation
- Each token is scoped to a namespace pattern (`*`, `exact`, or `prefix*`)
- Admin JWT tokens expire after 24 hours
- Admin password is hashed with bcrypt

### Network

- Always use HTTPS in production (reverse proxy: nginx / Caddy / Traefik)
- CORS is permissive by default — restrict origins in production via reverse proxy
- The admin panel should only be accessed from trusted networks

## API Reference

### Sync API (requires Bearer token)

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/namespaces/:ns/metadata` | Fetch sync metadata |
| `PUT` | `/v1/namespaces/:ns/metadata` | Update sync metadata |
| `GET` | `/v1/namespaces/:ns/blob` | Download snapshot blob |
| `PUT` | `/v1/namespaces/:ns/blob` | Upload snapshot blob (ETag concurrency) |
| `GET` | `/v1/namespaces/:ns/objects/*path` | Download structured object |
| `PUT` | `/v1/namespaces/:ns/objects/*path` | Upload structured object |
| `GET` | `/health` | Health check (no auth) |

### Admin API (requires admin JWT)

| Method | Path | Description |
|---|---|---|
| `POST` | `/admin/api/login` | Admin login |
| `GET` | `/admin/api/stats` | Server statistics |
| `GET` | `/admin/api/namespaces` | List all namespaces |
| `DELETE` | `/admin/api/namespaces/:ns` | Delete a namespace |
| `GET` | `/admin/api/tokens` | List API tokens |
| `POST` | `/admin/api/tokens` | Create API token |
| `DELETE` | `/admin/api/tokens/:id` | Delete API token |

## Disclaimer

This software is a **self-hosted data synchronization intermediary** designed exclusively for syncing encrypted OxideTerm configuration data between a user's own devices.

- **No proxy or tunnel functionality.** This server does not provide VPN, SOCKS proxy, HTTP proxy, traffic forwarding, or any form of network relay.
- **No content inspection.** The server stores opaque encrypted blobs. It does not parse, display, or redistribute user data to third parties.
- **No outbound connections.** The server makes no connections to external services. All data resides on the deployer's own infrastructure.
- **User responsibility.** Users must not use this software to store or transmit content that violates applicable laws and regulations. Deployers are responsible for complying with the laws of their jurisdiction, including but not limited to data protection, cybersecurity, and encryption regulations.
- **Commercial encryption.** The cryptographic algorithms used (ChaCha20-Poly1305, SHA-256, bcrypt) are employed solely for protecting the deployer's own data. This software is not a commercial encryption product or service.
- **No warranty.** This software is provided "as-is" without warranty of any kind. The author assumes no liability for any legal consequences arising from the use of this software.

## License

[GNU Affero General Public License v3.0](LICENSE)

Copyright (C) 2026 AnalyseDeCircuit
