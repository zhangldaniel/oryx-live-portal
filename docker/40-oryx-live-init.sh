#!/bin/sh
set -eu

fail() {
  echo "启动失败：$1" >&2
  exit 1
}

[ -n "${BASIC_AUTH_USER:-}" ] || fail "未设置 BASIC_AUTH_USER"
[ -n "${BASIC_AUTH_PASSWORD:-}" ] || fail "未设置 BASIC_AUTH_PASSWORD"
[ -n "${HLS_UPSTREAM:-}" ] || fail "未设置 HLS_UPSTREAM"

case "${BASIC_AUTH_USER}" in
  *[!A-Za-z0-9_.-]*|"") fail "BASIC_AUTH_USER 只能包含字母、数字、点、下划线和短横线" ;;
esac

[ "${#BASIC_AUTH_PASSWORD}" -ge 12 ] || fail "BASIC_AUTH_PASSWORD 至少需要 12 个字符"

if ! printf '%s' "${HLS_UPSTREAM}" |
  grep -Eq '^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?$'; then
  fail "HLS_UPSTREAM 格式应为 http://主机:端口，且不要包含路径或结尾斜杠"
fi

ROOM_COUNT="${ROOM_COUNT:-10}"
case "${ROOM_COUNT}" in
  *[!0-9]*|"") fail "ROOM_COUNT 必须是 1 到 100 的整数" ;;
esac
[ "${ROOM_COUNT}" -ge 1 ] && [ "${ROOM_COUNT}" -le 100 ] ||
  fail "ROOM_COUNT 必须是 1 到 100 的整数"

STREAM_PREFIX="${STREAM_PREFIX:-stream}"
case "${STREAM_PREFIX}" in
  *[!A-Za-z0-9_-]*|"") fail "STREAM_PREFIX 只能包含字母、数字、下划线和短横线" ;;
esac

htpasswd -bcB /etc/nginx/.htpasswd "${BASIC_AUTH_USER}" "${BASIC_AUTH_PASSWORD}" >/dev/null
chown root:nginx /etc/nginx/.htpasswd
chmod 0640 /etc/nginx/.htpasswd

cat > /usr/share/nginx/html/config.js <<EOF
window.ORYX_PORTAL_CONFIG = {
  roomCount: ${ROOM_COUNT},
  streamPrefix: "${STREAM_PREFIX}",
};
EOF
