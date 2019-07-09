default: build

GITHUB_REPO ?= sigs.k8s.io/aws-iam-authenticator
GORELEASER := $(shell command -v goreleaser 2> /dev/null)

.PHONY: build test format codegen

build:
ifndef GORELEASER
	$(error "goreleaser not found (`go get -u -v github.com/goreleaser/goreleaser` to fix)")
endif
	$(GORELEASER) --skip-publish --rm-dist --snapshot

test:
	go test -v -cover -race $(GITHUB_REPO)/...

format:
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -d {} + | tee /dev/stderr)" || \
	test -z "$$(find . -path ./vendor -prune -type f -o -name '*.go' -exec gofmt -w {} + | tee /dev/stderr)"

codegen:
	./hack/update-codegen.sh
