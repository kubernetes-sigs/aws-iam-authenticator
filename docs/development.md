# AWS IAM Authenticator Development

A simple [KIND](https://kind.sigs.k8s.io/) based test environment can be created with locally built images.

## Create the environment
Run `make start-dev ADMIN_ARN=arn:aws:iam::... AUTHENTICATOR_IMAGE=aws-iam-authenticator:v0.5.3_02a8...` to create a kind cluster, and run an aws-iam-authenticator server container to test.
Client side changes can be tested too, the binary in `_output/bin` is used by the generated kubeconfig.

## Tear down the environment
Run `make kill-dev` to tear down the environment complete and remove the generated config.
