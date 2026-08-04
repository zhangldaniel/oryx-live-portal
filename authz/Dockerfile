FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authz .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 10001 authz && \
    adduser -S -D -H -u 10001 -G authz authz && \
    mkdir -p /data/backups && \
    chown -R 10001:10001 /data

COPY --from=build /out/authz /usr/local/bin/authz

USER 10001:10001
EXPOSE 8081
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8081/readyz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/authz"]
