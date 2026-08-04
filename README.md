# Oryx Live Portal

多路 HLS 播放门户。默认展示 `stream01` 到 `stream10`，支持总览、单路播放、
声音、全屏和断流重连。

项目只部署播放门户，不包含 Oryx/SRS。

## 功能

- OIDC SSO 登录和 SQLite 观看权限
- 管理员后台：添加、禁用、恢复和归档观看用户
- 超级管理员可在后台授予或取消管理员权限
- 访问记录和操作审计，不采集客户端 IP
- 每日数据库备份，默认保留 30 天
- Basic Auth 备用模式

## 架构

```text
Browser -> Gateway :8086 -> Portal -> Oryx HLS
                    |-> oauth2-proxy
                    `-> Authz + SQLite
```

Gateway 会检查页面、API、m3u8 和视频分片。用户被禁用后，后续请求会立即
失去访问权限。

## SSO 部署

先在 OIDC 平台创建 Confidential Client，登记回调地址：

```text
https://live.example.com/oauth2/callback
```

拉取代码并创建配置：

```bash
git clone https://github.com/zhangldaniel/oryx-live-portal.git
cd oryx-live-portal
cp .env.example .env
chmod 600 .env
```

生成三个不同的内部密钥：

```bash
openssl rand -base64 32
openssl rand -base64 32
openssl rand -hex 32
```

编辑 `.env`：

```dotenv
PORT=8086
AUTH_MODE=sso
HLS_UPSTREAM=http://oryx.example.com:2022

OIDC_ISSUER_URL=https://sso.example.com/oidc/
OIDC_CLIENT_ID=oryx-live-portal
OIDC_CLIENT_SECRET=replace-with-real-client-secret
OIDC_REDIRECT_URL=https://live.example.com/oauth2/callback
OIDC_SCOPE=openid profile email

SSO_COOKIE_SECRET=replace-with-cookie-secret
AUTHZ_CSRF_SECRET=replace-with-base64-secret
AUTHZ_GATEWAY_SECRET=replace-with-hex-secret

PORTAL_ADMIN_EMAILS=admin@example.com
PORTAL_INITIAL_VIEWERS=viewer1@example.com,viewer2@example.com
AUTHZ_ALLOWED_EMAIL_DOMAIN=example.com
AUTHZ_DATA_DIR=/opt/oryx-live/data
PORTAL_TRUSTED_PROXY_CIDR=10.0.0.10/32

ROOM_COUNT=10
STREAM_PREFIX=stream
PORTAL_TITLE=直播总览
```

`PORTAL_ADMIN_EMAILS` 中的账号是不可降权的超级管理员，可在 `/admin/` 授予或
取消普通管理员。普通管理员可以维护观看用户，但不能变更管理员权限。管理员需先
取消管理员角色，之后才能禁用或归档。`PORTAL_INITIAL_VIEWERS` 只在空数据库首次
启动时导入。

`AUTHZ_DATA_DIR` 必须使用新的专用 `data` 或 `authz-data` 目录。部署脚本会
写入目录标记，避免误改宿主机目录权限。普通用户无法把目录交给 UID
`10001` 时，使用 `sudo ./deploy.sh`。

启动服务：

```bash
./deploy.sh
docker compose --profile sso ps
```

`deploy.sh` 自动兼容 `docker compose` 和 `docker-compose`。

访问地址：

```text
https://live.example.com/
https://live.example.com/admin/
```

## 更新容器

代码或 `.env` 变更后执行：

```bash
git pull --ff-only origin main
chmod 600 .env
docker compose --profile sso config -q
docker compose --profile sso pull oauth2-proxy
./deploy.sh
docker compose --profile sso ps
```

`docker compose restart` 不会重新读取 `.env`。

旧版变量 `SSO_AUTHZ_MODE`、`SSO_ALLOWED_EMAILS`、`SSO_ALLOWED_GROUPS` 和
`SSO_GROUPS_CLAIM` 不再控制观看权限，可以从 `.env` 删除。

## 常用命令

```bash
docker compose --profile sso logs -f gateway authz oauth2-proxy portal
docker compose --profile sso restart gateway
docker compose --profile sso down
```

## 备份恢复

数据库位于 `${AUTHZ_DATA_DIR}/authz.db`，每日备份位于
`${AUTHZ_DATA_DIR}/backups/`。

恢复前确认 `quick_check` 返回 `ok`：

```bash
data_dir=/opt/oryx-live/data
backup="$data_dir/backups/要恢复的备份.db"

sqlite3 "$backup" 'PRAGMA quick_check;'
docker compose --profile sso stop gateway authz
cp "$data_dir/authz.db" "$data_dir/authz.db.before-restore"
rm -f "$data_dir/authz.db-wal" "$data_dir/authz.db-shm"
install -m 0600 -o 10001 -g 10001 "$backup" "$data_dir/authz.db"
docker compose --profile sso up -d authz gateway
```

## Basic Auth

不使用 SSO 和权限后台时：

```dotenv
AUTH_MODE=basic
HLS_UPSTREAM=http://oryx.example.com:2022
BASIC_AUTH_USER=viewer
BASIC_AUTH_PASSWORD=replace-with-a-long-random-password
```

```bash
./deploy.sh
```

## Nginx 和防火墙

外层 Nginx 参考 [nginx/https-reverse-proxy.example.conf](nginx/https-reverse-proxy.example.conf)。

- 所有路径，包括 `/live/`，必须交给 Gateway。
- 不要用 `.m3u8`、`.ts` 正则直连 Oryx。
- Oryx HTTP/HLS 端口只允许门户服务器访问。
- Gateway 的 `8086` 只允许外层 HTTPS Nginx 访问。

`.env` 不要提交到 Git。上线前轮换测试中使用过的 OIDC、Cookie、推流和
镜像仓库密钥。

## License

[MIT](LICENSE)
