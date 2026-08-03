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

    SSO_AUTHZ_MODE="${SSO_AUTHZ_MODE:-group}"
    case "${SSO_AUTHZ_MODE}" in
      group)
        require_value SSO_ALLOWED_GROUPS

        case "${SSO_ALLOWED_GROUPS}" in
          *[!A-Za-z0-9_.,:@/-]*|""|,*|*,|*,,*)
            fail "SSO_ALLOWED_GROUPS 必须是逗号分隔的用户组，且不能包含空格"
            ;;
        esac

        SSO_GROUPS_CLAIM="${SSO_GROUPS_CLAIM:-groups}"
        case "${SSO_GROUPS_CLAIM}" in
          *[!A-Za-z0-9_.:-]*|"")
            fail "SSO_GROUPS_CLAIM 包含不支持的字符"
            ;;
        esac
        ;;

      email)
        require_value SSO_ALLOWED_EMAILS

        printf '%s' "${SSO_ALLOWED_EMAILS}" |
          grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(,[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})*$' ||
          fail "SSO_ALLOWED_EMAILS 必须是逗号分隔的邮箱，且不能包含空格"
        ;;

      *)
        fail "SSO_AUTHZ_MODE 只能是 group 或 email"
        ;;
    esac

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

    cp /etc/nginx/auth-templates/sso.conf.template \
      /etc/nginx/templates/default.conf.template

    if [ "${SSO_AUTHZ_MODE}" = "email" ]; then
      sed -i \
        's/allowed_groups=${SSO_ALLOWED_GROUPS}/allowed_emails=${SSO_ALLOWED_EMAILS}/' \
        /etc/nginx/templates/default.conf.template
    fi

    attempts=0
    until wget -q -T 2 -O /dev/null http://oauth2-proxy:4180/ping; do
      attempts=$((attempts + 1))
      [ "${attempts}" -lt 30 ] ||
        fail "oauth2-proxy 未就绪，请使用 ./deploy.sh 启动 SSO 模式并检查其日志"
      sleep 2
    done
    ;;

  *)
    fail "AUTH_MODE 只能是 basic 或 sso"
    ;;
esac
