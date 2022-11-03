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
ADMIN_ARN=$(aws sts get-caller-identity --query Arn --output text)
REPO_NAME=${REPO_NAME:-aws-iam-authenticator}

source "${REPO_ROOT}/hack/lib/dev-env.sh"
source "${REPO_ROOT}/hack/e2e-dynamicfile.sh"

make image
LOCAL_IMAGE_TAG=$(docker images | awk '{print $2}' | awk 'NR==2')
AUTHENTICATOR_IMAGE="${REPO_NAME}":"${LOCAL_IMAGE_TAG}"

echo ${ADMIN_ARN} ${AUTHENTICATOR_IMAGE}

create_network
write_authenticator_with_dynamicfile_mode_config
start_authenticator_with_dynamicfile
sleep 5
echo "Authenticator running at $AUTHENTICATOR_IP"
replace_authenticator_ip
write_kind_config
create_kind_cluster
certificate_authority_data="$(extract_certificate_authority_data)"
write_kubectl_kubeconfig
echo "start end to end testing for mountfile mode"
e2e_mountfile
echo "starting end to end testing for dynamicfile mode"
e2e_dynamicfile