default: build

GITHUB_REPO ?= sigs.k8s.io/aws-iam-authenticator
GORELEASER := $(shell command -v goreleaser 2> /dev/null)

.PHONY: build test format codegen

build:
ifndef GORELEASER
	$(error "goreleaser not found (`go get -u -v github.com/goreleaser/goreleaser` to fix)")
endif
	$(GORELEASER) --skip-publish --rm-dist --snapshot
		
build-eks: test
	CGO_ENABLED=0 go build $(GITHUB_REPO)/cmd/heptio-authenticator-aws

build-container-eks: 
	docker run -v $(shell pwd):/go/src/github.com/heptio/authenticator \
		--workdir=/go/src/github.com/heptio/authenticator \
		--env GOPATH=/go \
		golang:1.10 make build-eks

container-eks: build-container-eks
	docker build --network host -f Dockerfile.eks -t authenticator:latest .

test:
	go test -v -cover -race $(GITHUB_REPO)/...

format:
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -d {} + | tee /dev/stderr)" || \
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -w {} + | tee /dev/stderr)"

codegen:
	./hack/update-codegen.sh