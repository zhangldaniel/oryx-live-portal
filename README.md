# Oryx Live Portal

一个深海蓝渐变风格的多路 HLS 直播监看页面。默认展示 10 路
`stream01`～`stream10`，支持总览、单画面切换、声音、全屏和断流重连。

这个项目只部署播放门户，不包含 Oryx。

## 功能

- 总览同时播放多路低延迟 HLS，默认全部静音
- 点击任意画面进入单路播放，可开启声音
- 自动识别直播中、连接中和未开播状态
- Basic Auth 账号密码保护
- Nginx 代理并缓存 HLS，浏览器不直接访问 Oryx
- Docker Compose 一条命令启动
- 适配电脑和手机

## 快速启动

要求：已安装 Docker 和 Docker Compose。

```bash
git clone https://github.com/zhangldaniel/oryx-live-portal.git
cd oryx-live-portal
cp .env.example .env
```

编辑 `.env`，至少修改这三项：

```dotenv
HLS_UPSTREAM=http://你的Oryx地址:端口
BASIC_AUTH_USER=viewer
BASIC_AUTH_PASSWORD=换成一个至少12位的随机密码
```

随机密码可以这样生成：

```bash
openssl rand -hex 20
```

启动：

```bash
docker compose up -d --build
```

浏览器访问：

```text
http://服务器IP:8086
```

输入 `.env` 中设置的账号密码即可观看。

## 配置

| 变量 | 默认值 | 说明 |
| --- | ---: | --- |
| `PORT` | `8086` | 宿主机监听端口 |
| `HLS_UPSTREAM` | 无 | Oryx HTTP/HLS 地址，不带路径和结尾 `/` |
| `BASIC_AUTH_USER` | 无 | 登录账号 |
| `BASIC_AUTH_PASSWORD` | 无 | 登录密码，至少 12 位 |
| `ROOM_COUNT` | `10` | 直播间数量，范围 1～100 |
| `STREAM_PREFIX` | `stream` | 流名称前缀 |

例如默认配置会请求：

```text
/live/stream01.m3u8
/live/stream02.m3u8
...
/live/stream10.m3u8
```

如果 Oryx 的播放地址是
`http://192.168.1.20:2022/live/stream01.m3u8`，则填写：

```dotenv
HLS_UPSTREAM=http://192.168.1.20:2022
```

## 前面加 HTTPS Nginx

容器只提供 HTTP。正式环境建议在前面使用 Nginx、Ingress 或负载均衡器
终止 HTTPS。

仓库提供了可直接修改的示例：

```text
nginx/https-reverse-proxy.example.conf
```

把示例里的域名和证书路径换成自己的，然后检查并重新加载 Nginx。
外层代理必须保留 `Authorization` 请求头，否则 Basic Auth 无法登录。

## 常用操作

查看状态：

```bash
docker compose ps
```

查看日志：

```bash
docker compose logs -f portal
```

更新：

```bash
git pull
docker compose up -d --build
```

停止：

```bash
docker compose down
```

## 安全说明

- `.env` 已被 Git 忽略，不要提交真实账号、密码或内网地址。
- 页面只需要 HLS 播放地址，不要写入 RTMP 推流密钥。
- 建议通过防火墙限制 `8086`，只允许外层 HTTPS 代理访问。
- 公开使用前请启用 HTTPS，并设置独立的长随机密码。

## License

[MIT](LICENSE)
