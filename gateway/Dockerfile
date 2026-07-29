FROM nginx:stable-alpine

RUN apk add --no-cache apache2-utils

RUN rm -f /etc/nginx/conf.d/default.conf

COPY templates/ /etc/nginx/auth-templates/
COPY snippets/ /etc/nginx/snippets/
COPY static/ /usr/share/nginx/auth-pages/
COPY 15-configure-auth-gateway.sh /docker-entrypoint.d/15-configure-auth-gateway.sh

RUN chmod 0755 /docker-entrypoint.d/15-configure-auth-gateway.sh

EXPOSE 8080
