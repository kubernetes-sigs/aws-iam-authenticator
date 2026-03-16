## Sign the CLA

Before you can contribute, you will need to sign the [Contributor License Agreement](https://github.com/kubernetes/community/blob/master/CLA.md).

## Code of Conduct

Please make sure to read and observe our [Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

## Getting Started

### Prerequisites

- [Go](https://golang.org/dl/) 1.26.1 or later (see `.go-version`)
- [Docker](https://docs.docker.com/get-docker/) (for building images and running local dev environments)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) (for local development clusters)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) (for integration and e2e tests)
- `jq` (for integration tests)

### Building

```bash
# Build binary for your current OS/arch
make bin

# Build binaries for all supported platforms
make build-all-bins

# Build Docker image
make image
```

The binary is written to `_output/bin/`.

### Running Tests

**Unit tests:**
```bash
make test
```

This runs `go test ./pkg/...` with race detection and generates a coverage report at `coverage.html`.

**Integration tests** (requires AWS credentials and `jq`):
```bash
make integration
```

Integration tests spin up a local API server using etcd and exercise the authenticator against real AWS IAM API calls. You will need AWS credentials with permission to call `sts:GetCallerIdentity`.

**End-to-end tests:**
```bash
# Against a kops cluster on AWS (requires full AWS setup)
make e2e RUNNER=kops

# Against a local kind cluster
make e2e RUNNER=kind
```

See `docs/development.md` for setting up a local kind-based development environment.

### Linting

CI runs [golangci-lint](https://golangci-lint.run/) v2.11.3. To run it locally:

```bash
make lint
```

Install golangci-lint by following the [official installation guide](https://golangci-lint.run/welcome/install/).

### Code Generation

If you modify types in `pkg/mapper/crd/`, regenerate the CRD client code:

```bash
make codegen
```

## Submitting Changes

1. Fork the repository and create a branch from `master`.
2. Make your changes, including tests for any new behavior.
3. Ensure `make test` and `make lint` pass.
4. Open a pull request against `master`.

Pull requests are reviewed by the maintainers listed in `OWNERS`. Please allow a few business days for review.
