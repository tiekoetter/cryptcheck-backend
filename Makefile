GO ?= go
IMAGE ?= tiekoetter/cryptcheck-backend:latest

.PHONY: build test run docker-build docker-run docker-daemon

build:
	$(GO) build -o cryptcheck-backend .

test:
	$(GO) test ./...

run:
	$(GO) run . -o 127.0.0.1

docker-build:
	docker build . -t $(IMAGE)

docker-run:
	docker run --rm -p 7000:7000 $(IMAGE) -o 0.0.0.0

docker-daemon:
	docker run -d --name=cryptcheck-backend --rm -p 7000:7000 $(IMAGE) -o 0.0.0.0
