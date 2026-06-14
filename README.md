CryptCheck Backend
==================

Small Go web service that reimplements the [cryptcheck](https://github.com/aeris/cryptcheck)
HTTPS scanner and returns a JSON response compatible with [cryptcheck.fr](https://cryptcheck.fr).
The TLS engine, grading, and state analysis are implemented in pure Go with no Ruby or
external `cryptcheck` binary dependency.

API
---

```text
GET /https/<host>.json
GET /https/<host>:<port>.json
```

Successful responses use this shape:

```json
{
  "id": "cc54669a-a8d1-4739-b329-635b6e0e63b4",
  "service": "https",
  "host": "example.com",
  "pending": false,
  "result": [
    {
      "hostname": "example.com",
      "ip": "93.184.216.34",
      "port": 443,
      "grade": "F",
      "states": {"critical": {}, "error": {}, "warning": {}, "good": {}, "great": {}, "best": {}},
      "handshakes": {
        "certs": [],
        "dh": [],
        "hsts": null,
        "protocols": [{"protocol": "TLSv1_2", "states": {}}],
        "ciphers": [{"protocol": "TLSv1_2", "name": "ECDHE-ECDSA-AES128-GCM-SHA256", "states": {}}],
        "ciphers_preference": [{"protocol": "TLSv1_2", "cipher_suite": []}],
        "curves": [],
        "curves_preference": [],
        "fallback_scsv": false
      }
    }
  ],
  "created_at": "2026-06-14T12:00:00.000Z",
  "updated_at": "2026-06-14T12:00:00.000Z",
  "args": 443,
  "refresh_at": null
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
docker run --rm -p 7000:7000 tiekoetter/cryptcheck-backend:latest -o 0.0.0.0
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
TCP_TIMEOUT  per-connection timeout in seconds, default 10
```
