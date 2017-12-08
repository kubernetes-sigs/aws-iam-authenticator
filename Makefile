default: build

CMD_IMPORT ?= github.com/heptio/authenticator/cmd/heptio-authenticator-aws
REPO ?= gcr.io/heptio-images/authenticator
VERSION ?= v0.1.0

.PHONY: build push build-container

build: build-container heptio-authenticator-aws-osx

heptio-authenticator-aws-osx:
	GOOS=darwin GOARCH=amd64 go build -o heptio-authenticator-aws-osx $(CMD_IMPORT)

build-container: ca-certificates.crt
	GOOS=linux GOARCH=amd64 go build -o heptio-authenticator-aws $(CMD_IMPORT)
	docker build . -t $(REPO):$(VERSION)

push:
	docker push $(REPO):$(VERSION)

format:
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -d {} + | tee /dev/stderr)" || \
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -w {} + | tee /dev/stderr)"
