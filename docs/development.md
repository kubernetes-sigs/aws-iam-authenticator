# Local Development

## Prerequisites

- Go 1.26.1+ (see `.go-version`)
- Docker
- AWS CLI with credentials configured
- `jq`

## Quick Start

```bash
# 1. Build the binary and image
make bin
make image

# 2. Start a kind cluster with the authenticator running
make start-dev \
  ADMIN_ARN=arn:aws:iam::123456789012:role/MyAdminRole \
  AUTHENTICATOR_IMAGE=aws-iam-authenticator:<version>_<commit>_<date>-linux_<arch>
```

The exact image tag is printed by `make image`. `ADMIN_ARN` is the IAM role or user that will have admin access to the test cluster.

Once started, the script prints the `kubectl` command to use, with a kubeconfig pointing at your local cluster.

## What `make start-dev` Does

1. Downloads `kind` to `_output/bin/kind` if not already present
2. Creates a Docker bridge network (`172.30.0.0/16`) for the authenticator container
3. Starts the authenticator as a Docker container with your image
4. Creates a kind cluster configured to use the authenticator as its webhook
5. Writes a kubeconfig to `_output/dev/client/kubeconfig.yaml`

## Iterating

**Server-side changes** (changes to the authenticator server itself): rebuild the image and restart the environment.

```bash
make image
make kill-dev
make start-dev ADMIN_ARN=... AUTHENTICATOR_IMAGE=...
```

**Client-side changes** (changes to the `token` subcommand): just rebuild the binary — the generated kubeconfig already points at `_output/bin/aws-iam-authenticator`.

```bash
make bin
kubectl --kubeconfig=_output/dev/client/kubeconfig.yaml get nodes
```

## DynamicFile Backend

To test the DynamicFile backend mode instead of the default MountedFile mode:

```bash
make start-dev-dynamicfile \
  ADMIN_ARN=arn:aws:iam::123456789012:role/MyAdminRole \
  AUTHENTICATOR_IMAGE=aws-iam-authenticator:<version>_<commit>_<date>-linux_<arch>
```

## Tear Down

```bash
make kill-dev
```

This stops the authenticator container, deletes the kind cluster, removes the Docker network, and cleans up `_output/dev/`.

## Running Tests

**Unit tests:**
```bash
make test
```

Runs `go test ./pkg/...` with race detection. Outputs `coverage.html`.

**Integration tests** (requires AWS credentials and `jq`):
```bash
make integration
```

Spins up a local API server using etcd (downloaded from the Kubernetes repo on first run) and runs tests against real AWS IAM. Requires `sts:GetCallerIdentity` permission.

**E2E tests against a kind cluster:**
```bash
make e2e RUNNER=kind
```

**E2E tests against a kops cluster on AWS:**
```bash
make e2e RUNNER=kops
```

## Linting

```bash
make lint
```

Requires [golangci-lint](https://golangci-lint.run/welcome/install/) v2.11.3+. CI uses v2.11.3 with default settings (see `.golangci.yaml`).

## Code Generation

After modifying types in `pkg/mapper/crd/apis/`, regenerate the CRD client code:

```bash
make codegen
```
