#!/usr/bin/env bash

# Copyright 2016 The Kubernetes Authors.
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

function role_arn() {
    sts=$(aws sts get-caller-identity --query "Arn" --output text)
    tmp=${sts#*/}
    role_name=${tmp%/*}
    tmp=${sts%:*}
    account_id=${tmp##*:}
    echo "arn:aws:iam::${account_id}:role/${role_name}"
}

KUBERNETES_TAG="v1.22.1"
REPO_ROOT="$(cd "$( dirname "${BASH_SOURCE[0]}" )"/.. &> /dev/null && pwd)"
TEST_ARTIFACTS="${TEST_ARTIFACTS:-"${REPO_ROOT}/test-artifacts"}"
TEST_ROLE_ARN="${TEST_ROLE_ARN:-$(role_arn)}"

command -v aws || { echo "Command 'aws' not found" && exit 1; }

make clean
make bin

if [[ ! -d ${TEST_ARTIFACTS}/k8s.io/kubernetes ]]; then
    mkdir -p ${TEST_ARTIFACTS}/k8s.io/kubernetes
    git clone --branch ${KUBERNETES_TAG} --depth 1 https://github.com/kubernetes/kubernetes.git ${TEST_ARTIFACTS}/k8s.io/kubernetes --depth 1
fi
pushd ${TEST_ARTIFACTS}/k8s.io/kubernetes
make generated_files
popd

pushd ${REPO_ROOT}/tests/integration
go test -v ./server -test-artifacts-dir="${TEST_ARTIFACTS}" -authenticator-binary-path="${REPO_ROOT}/_output/bin/aws-iam-authenticator" -role-arn="${TEST_ROLE_ARN}"
popd
