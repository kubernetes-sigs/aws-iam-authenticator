VERSION := $(shell cat VERSION)

.PHONY: deps
deps:
	@npm i generate-changelog -g
	@go get golang.org/x/lint/golint

.PHONY: all
all: build-example test

.PHONY: lint
lint:
	@golint -set_exit_status ./...

test-fmt:
	./hack/test-fmt.sh

.PHONY: test
test:
	@go test -v -race ./...

.PHONY: build-example
build-example:
	./hack/build-example.sh

.PHONY: generate-changelog
generate-changelog:
	./hack/generate-changelog.sh

.PHONY: tag
tag:
	./hack/tag-release.sh

push-tags:
	@git push --tags

.PHONY: release
release: generate-changelog tag push-tags