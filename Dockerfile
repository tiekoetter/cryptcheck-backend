FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/cryptcheck-backend .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /out/cryptcheck-backend /usr/local/bin/cryptcheck-backend

EXPOSE 7000

ENTRYPOINT ["/usr/local/bin/cryptcheck-backend"]

LABEL org.label-schema.usage="https://github.com/dalf/cryptcheck-backend" \
      org.opencontainers.image.title="cryptcheck-backend" \
      org.opencontainers.image.source="git@github.com:dalf/cryptcheck-backend.git" \
      org.opencontainers.image.documentation="https://github.com/dalf/cryptcheck-backend"
