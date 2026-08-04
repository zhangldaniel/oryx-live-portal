#!/bin/sh
set -eu

fail() {
  echo "部署失败：$1" >&2
  exit 1
}

[ -f .env ] || fail "当前目录缺少 .env，请先复制 .env.example"

if docker compose version >/dev/null 2>&1; then
  compose() {
    docker compose "$@"
  }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() {
    docker-compose "$@"
  }
else
  fail "未找到 docker compose 或 docker-compose"
fi

auth_mode="$(
  sed -n 's/^[[:space:]]*AUTH_MODE[[:space:]]*=[[:space:]]*//p' .env |
    tail -n 1 |
    tr -d '\r'
)"

authz_data_dir="$(
  sed -n 's/^[[:space:]]*AUTHZ_DATA_DIR[[:space:]]*=[[:space:]]*//p' .env |
    tail -n 1 |
    tr -d '\r'
)"
authz_data_dir="${authz_data_dir:-./data}"

command -v stat >/dev/null 2>&1 ||
  fail "缺少 stat，无法检查 .env 权限"
env_mode="$(stat -c '%a' .env)"
[ "$((0${env_mode} % 64))" -eq 0 ] ||
  fail ".env 包含密钥，请先执行 chmod 600 .env"

case "${auth_mode:-basic}" in
  basic)
    compose up -d --build --remove-orphans
    ;;
  sso)
    command -v realpath >/dev/null 2>&1 ||
      fail "缺少 realpath，无法安全解析 AUTHZ_DATA_DIR"
    repo_dir="$(pwd -P)"
    resolved_authz_data_dir="$(realpath -m -- "${authz_data_dir}")"

    case "$(basename "${resolved_authz_data_dir}")" in
      data|authz-data) ;;
      *) fail "AUTHZ_DATA_DIR 必须是专用的 data 或 authz-data 目录" ;;
    esac
    case "${resolved_authz_data_dir}" in
      ""|/|/bin|/boot|/dev|/etc|/home|/opt|/root|/run|/srv|/usr|/var|"${repo_dir}")
        fail "AUTHZ_DATA_DIR 解析后不能是系统顶层目录或项目根目录"
        ;;
    esac
    authz_data_dir="${resolved_authz_data_dir}"

    data_marker="${authz_data_dir}/.oryx-live-authz-data"
    if [ -e "${authz_data_dir}" ]; then
      [ -d "${authz_data_dir}" ] || fail "AUTHZ_DATA_DIR 不是目录"
      [ -f "${data_marker}" ] && [ ! -L "${data_marker}" ] ||
        fail "已有 AUTHZ_DATA_DIR 缺少专用目录标记；请换用空的新目录"
    else
      mkdir -p "${authz_data_dir}"
      : >"${data_marker}"
    fi
    [ ! -L "${authz_data_dir}/backups" ] || fail "backups 不能是符号链接"
    [ ! -L "${authz_data_dir}/authz.db" ] || fail "authz.db 不能是符号链接"
    mkdir -p "${authz_data_dir}/backups"

    if [ "$(id -u)" -eq 0 ]; then
      chown 10001:10001 "${authz_data_dir}" "${authz_data_dir}/backups" "${data_marker}"
      [ ! -e "${authz_data_dir}/authz.db" ] ||
        chown 10001:10001 "${authz_data_dir}/authz.db"
    elif [ "$(stat -c '%u' "${authz_data_dir}")" -ne 10001 ]; then
      fail "非 root 部署时 AUTHZ_DATA_DIR 必须已属于 UID 10001"
    elif [ ! -w "${authz_data_dir}" ]; then
      fail "${authz_data_dir} 不可写"
    fi
    chmod 0750 "${authz_data_dir}" "${authz_data_dir}/backups"
    chmod 0600 "${data_marker}"

    export AUTHZ_DATA_DIR="${authz_data_dir}"
    compose --profile sso up -d --build --remove-orphans
    ;;
  *)
    fail "AUTH_MODE 只能是 basic 或 sso"
    ;;
esac

compose ps
