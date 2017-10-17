default: build

REPO ?= gcr.io/heptio-images/kubernetes-aws-authenticator
VERSION ?= v0.1.0

.PHONY: build push build-container

build: build-container kubernetes-aws-authenticator-osx

kubernetes-aws-authenticator-osx:
	GOOS=darwin GOARCH=amd64 go build -o kubernetes-aws-authenticator-osx main.go

build-container: ca-certificates.crt
	GOOS=linux GOARCH=amd64 go build -o kubernetes-aws-authenticator main.go
	docker build . -t $(REPO):$(VERSION)

# pull ca-certificates.crt from Alpine
ca-certificates.crt:
	docker run -v "$$PWD":/out --rm --tty -i alpine:latest /bin/sh -c "apk add --update ca-certificates && cp /etc/ssl/certs/ca-certificates.crt /out/"

push:
	docker push $(REPO):$(VERSION)

format:
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -d {} + | tee /dev/stderr)" || \
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -w {} + | tee /dev/stderr)"
