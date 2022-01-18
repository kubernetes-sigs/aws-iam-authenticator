#!/bin/bash

# Copyright 2021 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o pipefail
set -o nounset

#
# An easy way to quickly test local changes.
#
# The approach taken was to start the aws-iam-authenticator as
# a separate docker container first, with a fixed IP and in the
# kind node network.  Then, generate the webhook
# config with that IP and start the kind cluster.
#
# Alternative approach: we could run the authenticator pod in
# the kind cluster.  This might be a future improvement:
# pregenerate all certificates and config, start the cluster,
# load the target authenticator image, run authenticator as a
# host network pod (same as API server), and all communication
# between them is over localhost and fixed port.

REPO_ROOT="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"

source "${REPO_ROOT}/hack/lib/dev-env.sh"

# Tear down kind cluster
delete_kind_cluster

# Kill authenticator container
kill_authenticator

sleep 5

# Tear down network
delete_network
