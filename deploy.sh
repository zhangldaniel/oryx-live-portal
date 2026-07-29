#!/bin/sh
set -eu

fail() {
  echo "部署失败：$1" >&2
  exit 1
}

[ -f .env ] || fail "当前目录缺少 .env，请先复制 .env.example"

auth_mode="$(
  sed -n 's/^[[:space:]]*AUTH_MODE[[:space:]]*=[[:space:]]*//p' .env |
    tail -n 1 |
    tr -d '\r'
)"

case "${auth_mode:-basic}" in
  basic)
    docker compose up -d --build --remove-orphans
    ;;
  sso)
    docker compose --profile sso up -d --build --remove-orphans
    ;;
  *)
    fail "AUTH_MODE 只能是 basic 或 sso"
    ;;
esac

docker compose ps
