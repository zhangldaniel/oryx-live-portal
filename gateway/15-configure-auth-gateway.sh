#!/bin/sh
set -eu

fail() {
  echo "认证网关启动失败：$1" >&2
  exit 1
}

require_value() {
  variable_name="$1"
  eval "variable_value=\${${variable_name}:-}"
  [ -n "${variable_value}" ] || fail "AUTH_MODE=sso 时必须设置 ${variable_name}"
}

validate_email_list() {
  variable_name="$1"
  eval "variable_value=\${${variable_name}:-}"

  printf '%s' "${variable_value}" |
    grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(,[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})*$' ||
    fail "${variable_name} 必须是逗号分隔的邮箱，且不能包含空格"
}

wait_for_url() {
  service_name="$1"
  service_url="$2"
  attempts=0

  until wget -q -T 2 -O /dev/null "${service_url}"; do
    attempts=$((attempts + 1))
    [ "${attempts}" -lt 30 ] ||
      fail "${service_name} 未就绪，请检查容器日志"
    sleep 2
  done
}

AUTH_MODE="${AUTH_MODE:-basic}"

# nginx:stable-alpine does not guarantee that the template directory exists.
# The official 20-envsubst entrypoint script consumes the selected template
# from this directory after this script finishes.
mkdir -p /etc/nginx/templates

case "${AUTH_MODE}" in
  basic)
    [ -n "${BASIC_AUTH_USER:-}" ] || fail "未设置 BASIC_AUTH_USER"
    [ -n "${BASIC_AUTH_PASSWORD:-}" ] || fail "未设置 BASIC_AUTH_PASSWORD"

    case "${BASIC_AUTH_USER}" in
      *[!A-Za-z0-9_.-]*|"")
        fail "BASIC_AUTH_USER 只能包含字母、数字、点、下划线和短横线"
        ;;
    esac

    [ "${#BASIC_AUTH_PASSWORD}" -ge 12 ] ||
      fail "BASIC_AUTH_PASSWORD 至少需要 12 个字符"

    htpasswd -bcB /etc/nginx/.htpasswd \
      "${BASIC_AUTH_USER}" "${BASIC_AUTH_PASSWORD}" >/dev/null
    chown root:nginx /etc/nginx/.htpasswd
    chmod 0640 /etc/nginx/.htpasswd

    cp /etc/nginx/auth-templates/basic.conf.template \
      /etc/nginx/templates/default.conf.template
    ;;

  sso)
    require_value OIDC_ISSUER_URL
    require_value OIDC_CLIENT_ID
    require_value OIDC_CLIENT_SECRET
    require_value OIDC_REDIRECT_URL
    require_value SSO_COOKIE_SECRET
    require_value AUTHZ_CSRF_SECRET
    require_value AUTHZ_GATEWAY_SECRET
    require_value PORTAL_ADMIN_EMAILS
    require_value PORTAL_TRUSTED_PROXY_CIDR
    validate_email_list PORTAL_ADMIN_EMAILS
    if [ -n "${PORTAL_INITIAL_VIEWERS:-}" ]; then
      validate_email_list PORTAL_INITIAL_VIEWERS
    fi

    case "${OIDC_CLIENT_SECRET}" in
      replace-*|not-configured)
        fail "OIDC_CLIENT_SECRET 仍是示例值"
        ;;
    esac

    case "${SSO_COOKIE_SECRET}" in
      replace-*|not-configured)
        fail "SSO_COOKIE_SECRET 仍是示例值"
        ;;
    esac

    case "${AUTHZ_CSRF_SECRET}" in
      replace-*|not-configured)
        fail "AUTHZ_CSRF_SECRET 仍是示例值"
        ;;
    esac

    case "${AUTHZ_GATEWAY_SECRET}" in
      replace-*|not-configured)
        fail "AUTHZ_GATEWAY_SECRET 仍是示例值"
        ;;
    esac

    case "${OIDC_ISSUER_URL}" in
      https://*) ;;
      *) fail "OIDC_ISSUER_URL 必须使用 https://" ;;
    esac

    case "${OIDC_REDIRECT_URL}" in
      https://*/oauth2/callback) ;;
      *) fail "OIDC_REDIRECT_URL 必须是 https://域名/oauth2/callback" ;;
    esac

    [ "${#SSO_COOKIE_SECRET}" -ge 32 ] ||
      fail "SSO_COOKIE_SECRET 长度不足，请使用 openssl rand -base64 32 生成"
    [ "${#AUTHZ_CSRF_SECRET}" -ge 32 ] ||
      fail "AUTHZ_CSRF_SECRET 长度不足，请使用 openssl rand -base64 32 生成"
    [ "${#AUTHZ_GATEWAY_SECRET}" -ge 32 ] ||
      fail "AUTHZ_GATEWAY_SECRET 长度不足，请使用 openssl rand -hex 32 生成"

    cp /etc/nginx/auth-templates/sso.conf.template \
      /etc/nginx/templates/default.conf.template

    wait_for_url oauth2-proxy http://oauth2-proxy:4180/ping
    wait_for_url authz http://authz:8081/readyz
    ;;

  *)
    fail "AUTH_MODE 只能是 basic 或 sso"
    ;;
esac
