# OxideTerm Cloud Sync Server

Self-hosted cloud sync backend for [OxideTerm](https://github.com/AnalyseDeCircuit/oxideterm). Optional at-rest encryption for blob and object payloads, Docker-ready, single binary, zero external dependencies.

[中文说明](docs/README.zh-CN.md)

## Features

- **Optional encryption at rest** — ChaCha20-Poly1305 AEAD with a master key you control. Blob and object payloads are encrypted when `ENCRYPTION_KEY` is set.
- **Structured sync** — Compatible with OxideTerm Cloud Sync plugin's `structured-v1` protocol. Per-section objects for connections, forwards, settings, and more.
- **Concurrency control** — ETag-based optimistic locking is enforced for blob and object uploads.
- **Scoped API tokens** — SHA-256 hash lookup for auth, with optional expiry, disable/enable, rotate, reveal, device binding, and usage counters.
- **Admin web panel** — Embedded SPA for managing admin users, tokens, devices, namespace storage, sync conflicts, and lifecycle operations. Protected by bcrypt + HttpOnly session cookies, persistent login throttling, and audit logs without sensitive payloads.
- **Operational controls** — Soft-delete/restore namespaces, `/ready` readiness checks, and offline backup / restore / verify commands for the redb database.
- **Supply-chain checks** — GitHub Actions run Rust checks, dependency audit, image vulnerability scanning, SBOM generation, and keyless image signing.
- **Single binary** — Rust + [redb](https://github.com/cberner/redb). No external database required. ~10 MB Docker image.

## Why Self-Host?

| Aspect | Self-Hosted (This Server) | Third-Party / Generic Sync |
| --- | --- | --- |
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
export ADMIN_USERNAME=admin
export ADMIN_JWT_SECRET=$(openssl rand -hex 32)
export ADMIN_COOKIE_SECURE=true
# Set to true only when a trusted reverse proxy overwrites X-Forwarded-For / X-Real-IP
export TRUST_PROXY_HEADERS=false
# Recommended: keep CORS disabled unless you explicitly need browser access
export SYNC_CORS_ALLOWED_ORIGINS=

docker run -d \
  --name oxideterm-cloud-sync \
  -p 8730:8730 \
  -v oxideterm-sync-data:/data \
  -e ENCRYPTION_KEY=$ENCRYPTION_KEY \
  -e ADMIN_PASSWORD=$ADMIN_PASSWORD \
  -e ADMIN_USERNAME=$ADMIN_USERNAME \
  -e ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET \
  -e ADMIN_COOKIE_SECURE=$ADMIN_COOKIE_SECURE \
  -e TRUST_PROXY_HEADERS=$TRUST_PROXY_HEADERS \
  -e SYNC_CORS_ALLOWED_ORIGINS=$SYNC_CORS_ALLOWED_ORIGINS \
  ghcr.io/analysedecircuit/oxideterm.cloud-sync-server:0.1.0
```

### Docker Compose

```bash
cp .env.example .env
# Edit .env — fill in IMAGE_TAG, ENCRYPTION_KEY, ADMIN_PASSWORD, ADMIN_JWT_SECRET, and the optional hardening knobs you need
docker compose up -d
```

For a local source build, use `docker compose build && docker compose up -d`.

### From Source

```bash
cargo build --release
./target/release/oxideterm-cloud-sync-server \
  --listen 0.0.0.0:8730 \
  --db-path ./data/sync.db \
  --encryption-key $(openssl rand -hex 32) \
  --admin-password your-password \
  --admin-jwt-secret $(openssl rand -hex 32)
```

### Backup / Restore

Stop the server before running these commands so the database file is quiescent.

```bash
# Create an offline backup + checksum sidecar
./target/release/oxideterm-cloud-sync-server \
  --db-path ./data/sync.db \
  --backup-to ./backups/sync-$(date +%F).redb

# Verify backup integrity against ./backups/sync-YYYY-MM-DD.redb.sha256
./target/release/oxideterm-cloud-sync-server \
  --verify-backup ./backups/sync-YYYY-MM-DD.redb

# Restore the database from a verified backup
./target/release/oxideterm-cloud-sync-server \
  --db-path ./data/sync.db \
  --restore-from ./backups/sync-YYYY-MM-DD.redb
```

Recovery drill:

1. Stop the service.
2. Run `--verify-backup` against the candidate backup.
3. Restore it into a staging `DB_PATH`.
4. Start the server against that staging path and confirm `/ready` returns `ready`.
5. Only then restore into production.

## Configuration

| Environment Variable | CLI Flag | Default | Description |
| --- | --- | --- | --- |
| `LISTEN_ADDR` | `--listen` | `0.0.0.0:8730` | Listen address |
| `DB_PATH` | `--db-path` | `/data/sync.db` | Database file path |
| `ENCRYPTION_KEY` | `--encryption-key` | *(none)* | 32-byte hex key for encryption at rest |
| `ADMIN_PASSWORD` | `--admin-password` | *(none)* | Password used to bootstrap or update the default admin user (panel disabled if no admin users exist) |
| `ADMIN_USERNAME` | `--admin-username` | `admin` | Username bootstrapped from `ADMIN_PASSWORD` |
| `ADMIN_JWT_SECRET` | `--admin-jwt-secret` | random per boot | Admin JWT signing secret |
| `ADMIN_COOKIE_SECURE` | `--admin-cookie-secure` | `true` | Allow admin cookies to use `Secure` on HTTPS/trusted proxy HTTPS requests |
| `TRUST_PROXY_HEADERS` | `--trust-proxy-headers` | `false` | Trust `X-Forwarded-For` / `X-Real-IP` for admin login throttling |
| `SYNC_CORS_ALLOWED_ORIGINS` | `--sync-cors-allowed-origins` | *(empty)* | Comma-separated sync API CORS allowlist, or `*` to allow any origin |
| `MAX_BLOB_SIZE` | `--max-blob-size` | `67108864` (64 MiB) | Max blob upload size |
| `MAX_OBJECT_SIZE` | `--max-object-size` | `16777216` (16 MiB) | Max object upload size |
| `MIN_FREE_DISK_BYTES` | `--min-free-disk-bytes` | `104857600` (100 MiB) | Minimum free space required on the database volume before accepting writes |
| `LOGIN_WINDOW_SECONDS` | `--login-window-seconds` | `900` | Failed-login observation window |
| `LOGIN_LOCKOUT_SECONDS` | `--login-lockout-seconds` | `900` | Temporary admin lockout duration after repeated failures |
| `MAX_LOGIN_FAILURES` | `--max-login-failures` | `5` | Failure threshold before lockout |
| `DEFAULT_TOKEN_TTL_SECONDS` | `--default-token-ttl-seconds` | *(none)* | Default lifetime applied to newly created tokens without `expiresAt` |
| `STORE_METADATA_REVISION` | `--store-metadata-revision` | `true` | Persist the metadata `revision` field |
| `STORE_METADATA_UPLOADED_AT` | `--store-metadata-uploaded-at` | `true` | Persist the metadata `uploadedAt` field |
| `STORE_METADATA_DEVICE_ID` | `--store-metadata-device-id` | `true` | Persist the metadata `deviceId` field |
| `STORE_METADATA_CONTENT_HASH` | `--store-metadata-content-hash` | `true` | Persist the metadata `contentHash` field |
| `BACKUP_TO` | `--backup-to` | *(none)* | Export the database file and write a `.sha256` sidecar |
| `RESTORE_FROM` | `--restore-from` | *(none)* | Restore the database file from a backup |
| `VERIFY_BACKUP` | `--verify-backup` | *(none)* | Verify a backup against its `.sha256` sidecar |
| `RUST_LOG` | — | `info` | Log level filter |

## Connecting from OxideTerm

1. Open OxideTerm → Plugins → Cloud Sync
2. Select **HTTP JSON** backend
3. Set endpoint to `http://your-server:8730`
4. Open the admin panel at `http://your-server:8730` (redirects to `/admin`), create a namespace and an API token
5. Paste the token into the plugin's "Bearer Token" field
6. Click "Upload" to sync

The client-side plugin is open source: **[OxideTerm Cloud Sync Plugin](https://github.com/AnalyseDeCircuit/oxideterm.cloud-sync)**.

## Security

### Encryption

When `ENCRYPTION_KEY` is set:

- All blobs and objects are encrypted with ChaCha20-Poly1305 before writing to disk
- Each write uses a random 12-byte nonce prepended to the ciphertext
- Metadata (JSON) is stored in plaintext for server-side query support
- **If you lose the key, your data cannot be recovered**

When `ENCRYPTION_KEY` is *not* set:

- Blob and object payloads are stored in plaintext, and metadata is always stored in plaintext (not recommended for production)

### Authentication

- API tokens are still authenticated by SHA-256 hash lookup; newly created tokens also keep an encrypted copy so the admin panel can reveal them later
- Each token is scoped to a namespace pattern (`*`, `exact`, or `prefix*`), supports explicit `read` / `write` permissions, can be disabled, rotated, or assigned an `expiresAt`
- Token usage profiling records operational metadata only: read/write/failure counts, last namespace, last client IP, last client version, and last use time. It does not record plaintext tokens, passwords, or synced payload content.
- Sync conflict tracking records recent ETag conflicts with namespace, operation, optional object path, device ID, requested/remote revisions, and requested/remote ETags. It does not store payload content.
- Device records are an admin-managed inventory layer. They can be linked to tokens and updated from sync observations, but they do not add a second authentication factor yet.
- Admin users are stored in redb with bcrypt password hashes; `ADMIN_PASSWORD` bootstraps or updates the configured `ADMIN_USERNAME`
- Admin user records track operational security metadata such as last login time, last login IP, failed login count, last failed login time, and password update time
- Admin sessions use HttpOnly cookies with `SameSite=Strict`; `Secure` is enabled for trusted HTTPS requests and automatically omitted for direct plain-HTTP access so local admin login works
- All non-GET admin API calls require a matching `x-csrf-token` header and `admin_csrf` same-site cookie
- Admin JWT tokens still expire after 24 hours
- Admin password is hashed with bcrypt
- Failed admin logins are throttled persistently by client IP and the thresholds are configurable; behind a reverse proxy, enable `TRUST_PROXY_HEADERS=true` only if the proxy overwrites forwarding headers
- If `ADMIN_JWT_SECRET` is omitted, all admin sessions are invalidated on restart
- Existing tokens created before this feature cannot be reconstructed; create a replacement token if you need reveal support
- If neither `ENCRYPTION_KEY` nor `ADMIN_JWT_SECRET` is configured persistently, token reveal works only until the next server restart
- Admin audit logs intentionally exclude plaintext tokens, passwords, and synced payload content

### Network

- Always use HTTPS in production (reverse proxy: nginx / Caddy / Traefik)
- The sync API only emits CORS headers when `SYNC_CORS_ALLOWED_ORIGINS` is configured; admin endpoints are never exposed through the CORS layer
- The admin panel should only be accessed from trusted networks
- Sync and admin write operations are refused when free space would fall below `MIN_FREE_DISK_BYTES`; `/ready` reports this as `diskAboveMinimum=false`

### Supply Chain

- `.github/workflows/ci.yml` runs formatting, clippy, tests, and `cargo audit`.
- `.github/workflows/docker-publish.yml` tests before publishing, builds the Docker image, generates an SPDX SBOM, scans the pushed image with Trivy, uploads SARIF results, and signs the image digest with keyless cosign.
- Published images can be verified with `cosign verify ghcr.io/analysedecircuit/oxideterm.cloud-sync-server@sha256:<digest>`.

### Data Lifecycle

- Namespace deletion is soft by default in the admin panel. Soft-deleted namespaces stop serving sync traffic until restored.
- Permanent deletion is a separate purge action and removes the namespace metadata, blob, and retained objects.
- Namespace listings include blob bytes, object bytes, total bytes, last write time, growth since the previous write snapshot, and soft-delete footprint to support capacity planning.
- Metadata minimization is configurable so operators can choose whether to retain `revision`, `uploadedAt`, `deviceId`, and `contentHash`.

## API Reference

### Sync API (requires Bearer token)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/namespaces/:ns/metadata` | Fetch sync metadata |
| `PUT` | `/v1/namespaces/:ns/metadata` | Update sync metadata |
| `GET` | `/v1/namespaces/:ns/blob` | Download snapshot blob |
| `PUT` | `/v1/namespaces/:ns/blob` | Upload snapshot blob (ETag concurrency) |
| `GET` | `/v1/namespaces/:ns/objects/*path` | Download structured object with `ETag` |
| `PUT` | `/v1/namespaces/:ns/objects/*path` | Upload structured object (supports `If-Match` / `If-None-Match`) |
| `GET` | `/health` | Health check (no auth) |
| `GET` | `/ready` | Readiness check with DB + config status |

### Admin API (requires admin session cookie)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/admin/api/login` | Admin login |
| `POST` | `/admin/api/logout` | Clear admin session |
| `GET` | `/admin/api/me` | Current admin user |
| `POST` | `/admin/api/me/password` | Change the current admin user's password |
| `GET` | `/admin/api/stats` | Server statistics |
| `GET` | `/admin/api/users` | List admin users |
| `POST` | `/admin/api/users` | Create admin user |
| `PATCH` | `/admin/api/users/:username` | Update admin password or enabled state |
| `DELETE` | `/admin/api/users/:username` | Delete admin user |
| `GET` | `/admin/api/conflicts` | List recent sync conflicts |
| `GET` | `/admin/api/namespaces` | List all namespaces |
| `POST` | `/admin/api/namespaces` | Create a namespace |
| `DELETE` | `/admin/api/namespaces/:ns` | Soft-delete a namespace |
| `DELETE` | `/admin/api/namespaces/:ns?hard=true` | Permanently purge a namespace |
| `POST` | `/admin/api/namespaces/:ns/restore` | Restore a soft-deleted namespace |
| `GET` | `/admin/api/tokens` | List API tokens |
| `POST` | `/admin/api/tokens` | Create API token |
| `PATCH` | `/admin/api/tokens/:id` | Update `enabled` / `expiresAt` / `deviceId` |
| `POST` | `/admin/api/tokens/:id/rotate` | Rotate an API token and return the new secret |
| `GET` | `/admin/api/tokens/:id/reveal` | Reveal an existing API token |
| `DELETE` | `/admin/api/tokens/:id` | Delete API token |
| `GET` | `/admin/api/devices` | List registered devices |
| `POST` | `/admin/api/devices` | Register a device record |
| `PATCH` | `/admin/api/devices/:id` | Update device metadata, enabled state, or token link |
| `DELETE` | `/admin/api/devices/:id` | Delete a device record |

## Disclaimer

This software is a **self-hosted data synchronization intermediary** designed exclusively for syncing encrypted OxideTerm configuration data between a user's own devices.

- **No proxy or tunnel functionality.** This server does not provide VPN, SOCKS proxy, HTTP proxy, traffic forwarding, or any form of network relay.
- **No content inspection.** The server stores opaque blob/object payloads and plaintext metadata for synchronization bookkeeping. It does not parse, display, or redistribute user data to third parties.
- **No outbound connections.** The server makes no connections to external services. All data resides on the deployer's own infrastructure.
- **User responsibility.** Users must not use this software to store or transmit content that violates applicable laws and regulations. Deployers are responsible for complying with the laws of their jurisdiction, including but not limited to data protection, cybersecurity, and encryption regulations.
- **Commercial encryption.** The cryptographic algorithms used (ChaCha20-Poly1305, SHA-256, bcrypt) are employed solely for protecting the deployer's own data. This software is not a commercial encryption product or service.
- **No warranty.** This software is provided "as-is" without warranty of any kind. The author assumes no liability for any legal consequences arising from the use of this software.

## License

[GNU Affero General Public License v3.0](LICENSE)

Copyright (C) 2026 AnalyseDeCircuit
