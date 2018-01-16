default: build

CMD_IMPORT ?= github.com/heptio/authenticator/cmd/heptio-authenticator-aws
GITHUB_REPO ?= github.com/heptio/authenticator
REPO ?= gcr.io/heptio-images/authenticator
VERSION ?= v0.1.0

.PHONY: test build push build-container

build: test build-container heptio-authenticator-aws-osx

test:
	go test -v -cover -race $(GITHUB_REPO)/...

heptio-authenticator-aws-osx: test
	GOOS=darwin GOARCH=amd64 go build -o heptio-authenticator-aws-osx $(CMD_IMPORT)

build-container: ca-certificates.crt test
	GOOS=linux GOARCH=amd64 go build -o heptio-authenticator-aws $(CMD_IMPORT)
	docker build . -t $(REPO):$(VERSION)

# pull ca-certificates.crt from Alpine
ca-certificates.crt:
	docker run -v "$$PWD":/out --rm --tty -i alpine:latest /bin/sh -c "apk add --update ca-certificates && cp /etc/ssl/certs/ca-certificates.crt /out/"

push:
	docker push $(REPO):$(VERSION)

format:
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -d {} + | tee /dev/stderr)" || \
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -w {} + | tee /dev/stderr)"
