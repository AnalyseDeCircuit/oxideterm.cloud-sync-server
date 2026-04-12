# OxideTerm Cloud Sync Server

面向 [OxideTerm](https://github.com/AnalyseDeCircuit/oxideterm) 的自托管云同步后端。支持对 blob 和 object 载荷的可选静态加密，Docker 部署，单文件二进制，零外部依赖。

[English](../README.md)

## 特性

- **可选静态数据加密** — 使用 ChaCha20-Poly1305 AEAD，加密密钥由您自行掌控。设置 `ENCRYPTION_KEY` 后，blob 和 object 载荷会在落盘前加密。
- **结构化同步协议** — 完整支持 OxideTerm Cloud Sync 插件的 `structured-v1` 协议。连接、转发、设置等配置以独立对象存储，支持增量同步。
- **并发控制** — 基于 ETag 的乐观锁机制覆盖 blob 与 object 上传，防止多设备同时上传时数据丢失。
- **作用域 API Token** — Token 以 SHA-256 散列后存储，每个 Token 可限定到指定命名空间模式（`*`、精确匹配、`前缀*`）。
- **管理后台** — 内嵌 SPA 管理面板，支持 Token 和命名空间的增删管理。bcrypt 密码 + JWT 会话保护，并带内存级登录限速。
- **单文件部署** — Rust + [redb](https://github.com/cberner/redb) 嵌入式数据库。无需 MySQL / PostgreSQL。Docker 镜像约 10 MB。

## 为什么要自建？

| 维度 | 自建部署（本服务器） | 第三方/通用同步方案 |
| --- | --- | --- |
| 静态加密 | ChaCha20-Poly1305，密钥自持 | 因方案而异，常为明文 |
| 协议支持 | 完整 `structured-v1`，按节对象 | 通常仅支持单 blob |
| 并发控制 | 基于 ETag 乐观锁 | 少有支持 |
| Token 作用域 | 按命名空间模式匹配 | 通常为单一全局密钥 |
| 管理后台 | 内嵌 SPA | 需外部工具 |
| 数据主权 | 完全由您选择存储位置 | 取决于服务提供商 |

## 快速开始

### Docker（推荐）

```bash
# 生成加密密钥
export ENCRYPTION_KEY=$(openssl rand -hex 32)
export ADMIN_PASSWORD=你的安全密码
export ADMIN_JWT_SECRET=$(openssl rand -hex 32)
# 仅当可信反向代理会覆盖 X-Forwarded-For / X-Real-IP 时才设为 true
export TRUST_PROXY_HEADERS=false

docker run -d \
  --name oxideterm-cloud-sync \
  -p 8730:8730 \
  -v oxideterm-sync-data:/data \
  -e ENCRYPTION_KEY=$ENCRYPTION_KEY \
  -e ADMIN_PASSWORD=$ADMIN_PASSWORD \
  -e ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET \
  -e TRUST_PROXY_HEADERS=$TRUST_PROXY_HEADERS \
  ghcr.io/analysedecircuit/oxideterm.cloud-sync-server:0.1.0
```

### Docker Compose

```bash
cp .env.example .env
# 编辑 .env，填入 IMAGE_TAG、ENCRYPTION_KEY、ADMIN_PASSWORD、ADMIN_JWT_SECRET，必要时设置 TRUST_PROXY_HEADERS
docker compose up -d
```

如果你是从源码仓库直接构建镜像，使用 `docker compose build && docker compose up -d`。

### 从源码构建

```bash
cargo build --release
./target/release/oxideterm-cloud-sync-server \
  --listen 0.0.0.0:8730 \
  --db-path ./data/sync.db \
  --encryption-key $(openssl rand -hex 32) \
  --admin-password 你的密码 \
  --admin-jwt-secret $(openssl rand -hex 32)
```

## 配置项

| 环境变量 | 命令行参数 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `LISTEN_ADDR` | `--listen` | `0.0.0.0:8730` | 监听地址 |
| `DB_PATH` | `--db-path` | `/data/sync.db` | 数据库文件路径 |
| `ENCRYPTION_KEY` | `--encryption-key` | *(无)* | 32 字节十六进制加密密钥 |
| `ADMIN_PASSWORD` | `--admin-password` | *(无)* | 管理面板密码（未设置则禁用面板） |
| `ADMIN_JWT_SECRET` | `--admin-jwt-secret` | 每次启动随机生成 | 管理面板 JWT 签名密钥 |
| `TRUST_PROXY_HEADERS` | `--trust-proxy-headers` | `false` | 是否信任 `X-Forwarded-For` / `X-Real-IP` 参与登录限速 |
| `MAX_BLOB_SIZE` | `--max-blob-size` | `67108864`（64 MiB） | 最大 blob 上传大小 |
| `MAX_OBJECT_SIZE` | `--max-object-size` | `16777216`（16 MiB） | 最大对象上传大小 |
| `RUST_LOG` | — | `info` | 日志级别过滤 |

## 从 OxideTerm 连接

1. 打开 OxideTerm → 插件 → Cloud Sync
2. 选择 **HTTP JSON** 后端
3. 设置端点为 `http://你的服务器:8730`
4. 在管理面板 (`http://你的服务器:8730/admin`) 中创建 API Token
5. 将 Token 粘贴到插件的 "Bearer Token" 字段
6. 点击 "Upload" 开始同步

## 安全

### 加密

设置 `ENCRYPTION_KEY` 后：

- 所有 blob 和 object 在写入磁盘前均使用 ChaCha20-Poly1305 加密
- 每次写入使用随机 12 字节 nonce，拼接在密文前
- 元数据（JSON）以明文存储，用于服务端查询
- **密钥丢失后数据无法恢复**

未设置 `ENCRYPTION_KEY` 时：

- blob 和 object 载荷将以明文存储；元数据始终为明文（不建议用于生产环境）

### 认证

- API Token 以 SHA-256 散列后存储，原始 Token 仅在创建时展示一次
- 每个 Token 可限定到命名空间模式（`*` 全部、精确匹配、`前缀*`），并强制区分 `read` / `write` 权限
- 管理员 JWT 令牌 24 小时过期
- 管理员密码使用 bcrypt 散列
- 管理员登录按客户端 IP 做内存级失败限速；若部署在可信反向代理后，请仅在代理会覆盖转发头时启用 `TRUST_PROXY_HEADERS=true`
- 未设置 `ADMIN_JWT_SECRET` 时，服务重启会使所有管理会话失效

### 网络

- 生产环境请务必使用 HTTPS（反向代理：nginx / Caddy / Traefik）
- 同步 API 默认为跨域开放，便于 OxideTerm 客户端接入；管理接口不挂在 CORS 层上
- 管理面板应仅在可信网络中访问

## API 参考

### 同步 API（需要 Bearer Token）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/v1/namespaces/:ns/metadata` | 获取同步元数据 |
| `PUT` | `/v1/namespaces/:ns/metadata` | 更新同步元数据 |
| `GET` | `/v1/namespaces/:ns/blob` | 下载快照 blob |
| `PUT` | `/v1/namespaces/:ns/blob` | 上传快照 blob（ETag 并发控制） |
| `GET` | `/v1/namespaces/:ns/objects/*path` | 下载结构化对象，并返回 `ETag` |
| `PUT` | `/v1/namespaces/:ns/objects/*path` | 上传结构化对象，支持 `If-Match` / `If-None-Match` |
| `GET` | `/health` | 健康检查（无需认证） |

### 管理 API（需要管理员 JWT）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/admin/api/login` | 管理员登录 |
| `GET` | `/admin/api/stats` | 服务器统计 |
| `GET` | `/admin/api/namespaces` | 列出所有命名空间 |
| `DELETE` | `/admin/api/namespaces/:ns` | 删除命名空间 |
| `GET` | `/admin/api/tokens` | 列出 API Token |
| `POST` | `/admin/api/tokens` | 创建 API Token |
| `DELETE` | `/admin/api/tokens/:id` | 删除 API Token |

## 法律声明

本软件（OxideTerm Cloud Sync Server）是一个**自托管的数据同步中转服务**，专用于在用户自有设备之间同步 OxideTerm 客户端的加密配置数据。

### 功能边界

- **本软件不提供任何形式的网络代理、VPN、隧道、SOCKS 代理、HTTP 代理或流量转发功能。**
- 本软件不解析、审查或向第三方展示用户存储的数据内容。服务端存储的是不透明的 blob/object 载荷和用于同步账本的明文元数据，不负责内容理解或分发。
- 本软件不发起任何出站网络连接。所有数据完全存储在部署者自行控制的基础设施上。

### 用户与部署者责任

- 用户**不得**利用本软件存储、传输违反所在地法律法规的内容。
- 部署者应遵守所在地区的法律法规，包括但不限于：
  - **《中华人民共和国网络安全法》**
  - **《中华人民共和国数据安全法》**
  - **《中华人民共和国个人信息保护法》**
  - **《中华人民共和国密码法》** 及其他相关法规
- 如在中国大陆地区以 SaaS 方式对外提供服务，部署者应依法完成 ICP 备案及相关资质申请。

### 加密合规

本软件使用的加密算法（ChaCha20-Poly1305、SHA-256、bcrypt）仅用于保护部署者自身的数据安全，属于《密码法》第二十一条规定的"公民、法人和其他组织依法使用商用密码保护网络与信息安全"范畴。本软件不属于商用密码产品，不提供面向他人的加密服务。

### 出口合规

本软件包含加密功能。用户在使用、分发或出口本软件时，应确保遵守所在司法管辖区的出口管制法规，包括但不限于美国 EAR、欧盟两用物品条例以及中国相关出口管制法律。

### 免责

本软件按"原样"提供，不附带任何明示或默示的保证。作者不对因使用本软件而产生的任何直接、间接、附带或后果性损失承担责任，亦不对用户或部署者因违反适用法律而产生的法律后果承担任何义务。

## 许可证

[GNU Affero General Public License v3.0](../LICENSE)

Copyright (C) 2026 AnalyseDeCircuit
