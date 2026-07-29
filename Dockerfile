FROM nginx:stable-alpine

COPY site/ /usr/share/nginx/html/
COPY docker/default.conf.template /etc/nginx/templates/default.conf.template
COPY docker/40-oryx-live-init.sh /docker-entrypoint.d/40-oryx-live-init.sh

RUN chmod 0755 /docker-entrypoint.d/40-oryx-live-init.sh

EXPOSE 8080
