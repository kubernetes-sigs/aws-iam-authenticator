# AWS IAM Authenticator Development

## Prerequisites

- Go 1.26.1+ (see `.go-version`)
- Docker and [kind](https://kind.sigs.k8s.io/)
- AWS CLI with credentials configured (for integration and e2e tests)
- `jq` (for integration tests)

## Build

```bash
make bin              # current OS/arch → _output/bin/
make build-all-bins   # all supported platforms
make image            # Docker image for current arch
```

## Test

```bash
make test             # unit tests with race detection
make lint             # golangci-lint (install: https://golangci-lint.run/welcome/install/)
make integration      # requires AWS credentials and jq
make e2e RUNNER=kind  # e2e against a local kind cluster
make e2e RUNNER=kops  # e2e against a kops cluster on AWS
```

## Local kind Development Environment

Build the image first, then start a kind cluster with the authenticator running as a container:

```bash
make image
make start-dev \
  ADMIN_ARN=arn:aws:iam::123456789012:role/MyAdminRole \
  AUTHENTICATOR_IMAGE=aws-iam-authenticator:<version>_<commit>_<date>-linux_<arch>
```

The generated kubeconfig is written to `_output/dev/`. The binary at `_output/bin/` is used for client-side token generation — rebuild with `make bin` to pick up client-side changes without restarting the server.

To test the DynamicFile backend: `make start-dev-dynamicfile` (same env vars).

Tear down with `make kill-dev`.

## Code Generation

After modifying types in `pkg/mapper/crd/`:

```bash
make codegen
```

## Go Workspace

This repo uses a Go workspace (`go.work`) to develop the main module and test submodules (`tests/e2e`, `tests/integration`) together. Run `go mod tidy` from the repo root to keep all modules in sync.
