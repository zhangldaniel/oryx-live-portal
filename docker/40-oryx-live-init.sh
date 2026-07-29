#!/bin/sh
set -eu

fail() {
  echo "启动失败：$1" >&2
  exit 1
}

[ -n "${HLS_UPSTREAM:-}" ] || fail "未设置 HLS_UPSTREAM"

AUTH_MODE="${AUTH_MODE:-basic}"
case "${AUTH_MODE}" in
  basic|sso) ;;
  *) fail "AUTH_MODE 只能是 basic 或 sso" ;;
esac

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

PORTAL_TITLE="${PORTAL_TITLE:-直播总览}"
[ -n "${PORTAL_TITLE}" ] || fail "PORTAL_TITLE 不能为空"
[ "${#PORTAL_TITLE}" -le 120 ] || fail "PORTAL_TITLE 不能超过 120 个字节"
PORTAL_TITLE_BASE64="$(printf '%s' "${PORTAL_TITLE}" | base64 | tr -d '\r\n')"

cat > /usr/share/nginx/html/config.js <<EOF
window.ORYX_PORTAL_CONFIG = {
  roomCount: ${ROOM_COUNT},
  streamPrefix: "${STREAM_PREFIX}",
  portalTitleBase64: "${PORTAL_TITLE_BASE64}",
  authMode: "${AUTH_MODE}",
};
EOF
