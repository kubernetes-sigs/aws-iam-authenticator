default: build

GORELEASER := $(shell command -v goreleaser 2> /dev/null)

.PHONY: build test format

build: ca-certificates.crt
ifndef GORELEASER
	$(error "goreleaser not found (`go get -u -v github.com/goreleaser/goreleaser` to fix)")
endif
	$(GORELEASER) --skip-publish --rm-dist --snapshot

# pull ca-certificates.crt from Alpine
ca-certificates.crt:
	docker run -v "$$PWD":/out --rm --tty -i alpine:latest /bin/sh -c "apk add --update ca-certificates && cp /etc/ssl/certs/ca-certificates.crt /out/"

test:
	go test -v ./...

format:
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -d {} + | tee /dev/stderr)" || \
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -w {} + | tee /dev/stderr)"
