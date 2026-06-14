CryptCheck Backend
==================

Small Go web service that probes HTTPS endpoints and returns a JSON response
compatible with the old cryptcheck-backend envelope. It has no Ruby, Bundler, or
`aeris22/cryptcheck` Docker image dependency.

API
---

```text
GET /https/<host>.json
GET /https/<host>:<port>.json
```

Successful responses use this shape:

```json
{
  "service": "https",
  "host": "example.com",
  "pending": false,
  "result": [
    {
      "hostname": "example.com",
      "ip": "93.184.216.34",
      "port": 443,
      "handshakes": {
        "certs": [],
        "dh": [],
        "protocols": [{"protocol": "TLSv1_3", "states": {}}],
        "ciphers": [{"protocol": "TLSv1_3", "name": "TLS_AES_128_GCM_SHA256", "states": {}}],
        "ciphers_preference": [{"protocol": "TLSv1_3", "na": true}],
        "curves": [],
        "curves_preference": null,
        "fallback_scsv": false
      },
      "states": {},
      "grade": "A"
    }
  ],
  "created_at": "2026-06-14T12:00:00.000Z",
  "updated_at": "2026-06-14T12:00:00.000Z",
  "args": 443
}
```

Invalid arguments return HTTP 400:

```json
{"status":400,"error":"Invalid port","error_message":"abc is not a number"}
```

DNS or service-level failures return HTTP 503. Per-address connection or TLS
errors are returned inside the `result` array so dual-stack hosts can still show
partial results.

Build And Run
-------------

```sh
make test
make build
./cryptcheck-backend -o 127.0.0.1 -p 7000
```

Docker:

```sh
make docker-build
make docker-run
```

Or directly:

```sh
docker run --rm -p 7000:7000 dalf/cryptcheck-backend:latest -o 0.0.0.0
```

Configuration
-------------

Flags:

```text
-o  address to bind, default 127.0.0.1
-p  port to listen on, default 7000
```

Environment:

```text
TCP_TIMEOUT  TLS dial timeout in seconds, default 10
```
