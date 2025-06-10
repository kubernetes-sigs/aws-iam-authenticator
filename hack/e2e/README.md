# AWS IAM Authenticator E2E Testing

End-to-end testing verifies the functionality of the AWS IAM authenticator for Kubernetes.

## Prerequisites

Have the following installed on your system:
- go (1.16+)
- jq
- awscli
    - Configure your AWS credentials, as well.
- docker

## Operation

From the base directory, run `./hack/e2e/run.sh`. Alternatively, run `make test-<testname>` or `GINKGO_FOCUS="[<test_group>]" ./hack/e2e/run.sh` to run a specific subset of tests. 

You can change the behavior of the tests by setting certain environment variables beforehand. Most of these can stay unchanged, but some should be noted:
- `REGION`, `ZONES`: AWS region that the tests should be run on.
- `KOPS_STATE_FILE`: An S3 bucket that you have access to. **Change this to a bucket you own!**
- `K8S_VERSION`: Kuberenetes version. This must be compatible with the specified `KOPS_VERSION`, and vice versa.
- `TEST_ID`: Normally a random number, but can be set for a more controlled environment.
- `CLEAN`: Set to false if you don't want the cluster to be torn down after the tests are done running. Useful if you want to inspect the cluster state after setup.

:warning: Note that the tests may get stuck when patching the cluster file. To fix this issue, move or delete `~/.kube/config`.

## Tests

### Configuration tests

These tests verify the basic functionality of the authenticator (specifically, that the ConfigMap applied to the cluster correctly assigns the identity based on the IAM role/user).

Run these tests by running `./hack/e2e/run.sh`.

Future work should be done to verify that EKS-style ConfigMaps and CRDs are also applied correctly.

### Apiserver tests

When the authenticator is first installed on the cluster, the API server must be restarted with a modified manifest. This auxiliary test ensures that after a manifest modification, the API server restarts correctly.

Run this test by running `GINKGO_FOCUS="\[apiserver\]" GINKGO_SKIP=".^" GINKGO_NODES=1 ./hack/e2e/run.sh`.
