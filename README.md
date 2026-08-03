# Oryx Live Portal

一个用于多路 HLS 直播监看的轻量播放门户。默认展示
`stream01`～`stream10`，支持总览、单画面切换、声音、全屏和断流重连。

项目只部署播放门户，不包含 Oryx。

## 功能

- 多路低延迟 HLS 总览，默认全部静音
- 单路专注播放、声音控制和全屏
- 直播状态检测与断流自动重连
- `basic` 账号密码认证
- `sso` OIDC 单点登录
- OIDC 用户组或邮箱白名单授权
- 右上角显示登录邮箱并支持退出门户
- 自定义无权限页和退出完成页
- Docker Compose 部署，默认使用 `8086`

## 认证架构

所有门户请求先经过统一认证网关，静态门户容器不直接暴露宿主机端口：

```text
浏览器 → 8086 认证网关
              ├─ basic → Basic Auth → 静态门户
              └─ sso   → oauth2-proxy → 权限检查 → 静态门户
```

SSO 使用固定版本 `oauth2-proxy v7.15.2`，会话保存在加密 Cookie 中，
不需要 Redis。

## 快速启动：Basic Auth

要求：已安装 Docker 和 Docker Compose。

```bash
git clone https://github.com/zhangldaniel/oryx-live-portal.git
cd oryx-live-portal
cp .env.example .env
```

编辑 `.env`：

```dotenv
AUTH_MODE=basic
HLS_UPSTREAM=http://你的Oryx地址:端口
BASIC_AUTH_USER=viewer
BASIC_AUTH_PASSWORD=换成一个至少12位的随机密码
PORTAL_TITLE=直播总览
```

启动：

```bash
chmod +x deploy.sh
./deploy.sh
```

浏览器访问：

```text
http://服务器IP:8086
```

## 接入 OIDC SSO

### 1. 在 SSO 创建客户端

创建独立的 Confidential OIDC Client，并登记回调地址：

```text
https://你的门户域名/oauth2/callback
```

需要取得：

- OIDC Issuer URL
- Client ID
- Client Secret

SSO 支持用户组和邮箱白名单两种授权方式。用户组模式要求门户用户组同步到
OIDC Token，默认读取 `groups` Claim。

### 2. 配置服务器 `.env`

```dotenv
AUTH_MODE=sso

OIDC_ISSUER_URL=https://sso.example.com
OIDC_CLIENT_ID=oryx-live-portal
OIDC_CLIENT_SECRET=真实ClientSecret
OIDC_REDIRECT_URL=https://live.example.com/oauth2/callback
OIDC_SCOPE=openid profile email groups

SSO_AUTHZ_MODE=group
SSO_GROUPS_CLAIM=groups
SSO_ALLOWED_GROUPS=oryx-live-viewers,oryx-live-admins

SSO_COOKIE_SECRET=使用下面命令生成
SSO_COOKIE_EXPIRE=8h
SSO_COOKIE_REFRESH=1h
```

生成 Cookie Secret：

```bash
openssl rand -base64 32
```

`SSO_ALLOWED_GROUPS` 必须至少填写一个组。多个组使用英文逗号分隔，
用户匹配任意一个组即可访问。SSO 模式缺少用户组或其他必填参数时，
认证网关会拒绝启动，不会自动放开访问。

如果 OIDC 不提供用户组，可以使用邮箱白名单：

```dotenv
SSO_AUTHZ_MODE=email
SSO_ALLOWED_EMAILS=viewer1@example.com,viewer2@example.com
```

多个邮箱使用英文逗号分隔，不能包含空格。两种授权模式都由认证网关在服务端
执行，前端无法绕过。

### 3. 启动

```bash
./deploy.sh
```

脚本会根据 `AUTH_MODE` 自动启用对应的 Compose 服务。

未登录用户会直接跳转 SSO。登录后，页面右上角显示用户邮箱和
“退出门户”。退出操作只清除门户会话，不会退出公司其他系统。

## 同域部署

当 Oryx 后台、HLS 和门户共用一个域名时，推荐路由：

```text
/                         Oryx 后台
/live/                    HLS，保持原有策略
/portal/                  SSO 播放门户
/oauth2/                  OIDC 登录与回调
/portal-signed-out/       退出完成页
```

可直接参考：

```text
nginx/oryx-same-domain.example.conf
```

`/portal/` 的 `proxy_pass` 后面不能添加结尾斜杠，否则 OAuth 登录后可能
丢失原始门户路径。

如果门户使用独立域名并挂载在根路径，参考：

```text
nginx/https-reverse-proxy.example.conf
```

## 配置

| 变量                  | 默认值                        | 说明                                   |
| --------------------- | ----------------------------- | -------------------------------------- |
| `PORT`                | `8086`                        | 认证网关宿主机端口                     |
| `AUTH_MODE`           | `basic`                       | `basic` 或 `sso`                       |
| `HLS_UPSTREAM`        | 无                            | Oryx HTTP/HLS 地址，不带路径和结尾 `/` |
| `BASIC_AUTH_USER`     | 无                            | Basic 模式账号                         |
| `BASIC_AUTH_PASSWORD` | 无                            | Basic 模式密码，至少 12 位             |
| `OIDC_ISSUER_URL`     | 无                            | OIDC Issuer URL                        |
| `OIDC_CLIENT_ID`      | 无                            | OIDC Client ID                         |
| `OIDC_CLIENT_SECRET`  | 无                            | OIDC Client Secret                     |
| `OIDC_REDIRECT_URL`   | 无                            | HTTPS 回调地址                         |
| `OIDC_SCOPE`          | `openid profile email groups` | OIDC Scope                             |
| `SSO_AUTHZ_MODE`      | `group`                       | `group` 或 `email`                     |
| `SSO_GROUPS_CLAIM`    | `groups`                      | Token 中的用户组字段                   |
| `SSO_ALLOWED_GROUPS`  | 无                            | 允许访问的组，英文逗号分隔             |
| `SSO_ALLOWED_EMAILS`  | 无                            | 允许访问的邮箱，英文逗号分隔           |
| `SSO_COOKIE_SECRET`   | 无                            | Cookie 加密密钥                        |
| `SSO_COOKIE_EXPIRE`   | `8h`                          | 会话最长有效时间                       |
| `SSO_COOKIE_REFRESH`  | `1h`                          | 会话刷新间隔                           |
| `PORTAL_NETWORK_CIDR` | `172.30.246.0/24`             | 内部 Docker 网络                       |
| `ROOM_COUNT`          | `10`                          | 直播间数量，范围 1～100                |
| `STREAM_PREFIX`       | `stream`                      | 流名称前缀                             |
| `PORTAL_TITLE`        | `直播总览`                    | 页面主标题                             |

默认播放地址：

```text
/live/stream01.m3u8
/live/stream02.m3u8
...
/live/stream10.m3u8
```

## 常用操作

查看状态：

```bash
docker compose ps
```

查看日志：

```bash
docker compose logs -f gateway portal oauth2-proxy
```

更新：

```bash
git pull
./deploy.sh
```

停止：

```bash
docker compose --profile sso down
```

## 安全边界

- `.env` 已被 Git 忽略，不要提交真实账号、Client Secret 或内网地址。
- Access Token、ID Token 和授权名单不会写入前端代码。
- SSO 权限检查在认证网关服务端执行，不能由浏览器绕过。
- 建议通过防火墙限制 `8086`，只允许外层 HTTPS Nginx 访问。
- SSO 必须通过 HTTPS 使用。
- 同域示例只保护 `/portal/`；`/live/` HLS 地址仍可被直接访问。
- 页面不要写入 RTMP 推流密钥。

## License

[MIT](LICENSE)
