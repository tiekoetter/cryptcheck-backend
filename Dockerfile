FROM --platform=$BUILDPLATFORM golang:1.26-alpine3.22 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/cryptcheck-backend .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 app \
    && adduser -S -u 65532 -G app app

WORKDIR /app
COPY --from=builder /out/cryptcheck-backend /usr/local/bin/cryptcheck-backend

USER app:app

EXPOSE 7000

ENTRYPOINT ["/usr/local/bin/cryptcheck-backend"]

LABEL org.label-schema.usage="https://github.com/tiekoetter/cryptcheck-backend" \
      org.opencontainers.image.title="cryptcheck-backend" \
      org.opencontainers.image.source="git@github.com:tiekoetter/cryptcheck-backend.git" \
      org.opencontainers.image.documentation="https://github.com/tiekoetter/cryptcheck-backend"
