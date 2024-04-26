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

set -o errexit
set -o pipefail
set -o nounset

command -v aws || { echo "Command 'aws' not found" && exit 1; }

function account_from_default_credentials() {
    sts_account=$(aws sts get-caller-identity --query "Account" --output text)
    echo $sts_account
}

function role_arn_from_default_credentials() {
    sts_arn=$(aws sts get-caller-identity --query "Arn" --output text)
    tmp=${sts_arn#*/}
    role_name=${tmp%/*}
    tmp=${sts_arn%:*}
    account_id=${tmp##*:}
    echo "arn:aws:iam::${account_id}:role/${role_name}"
}

function write-role-policy() {
    local account_id=$1
    local file_name=$2

    cat > ${file_name} <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${account_id}:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

CREATE_TEST_ROLE="${CREATE_TEST_ROLE:-true}"
GENERATED_TEST_ROLE_NAME="aws-iam-authenticator-test-role-${RANDOM}"
GENERATED_TEST_ROLE_POLICY_FILE=/tmp/role-policy.json
KUBERNETES_TAG="v1.29.0"
REPO_ROOT="$(cd "$( dirname "${BASH_SOURCE[0]}" )"/.. &> /dev/null && pwd)"
TEST_ARTIFACTS="${TEST_ARTIFACTS:-"${REPO_ROOT}/test-artifacts"}"
TEST_ROLE_ARN="${TEST_ROLE_ARN:-$(role_arn_from_default_credentials)}"

function cleanup {
    if [[ "${CREATE_TEST_ROLE}" = "true" ]]; then
        echo "Cleaning up test role ${GENERATED_TEST_ROLE_NAME}"
        aws iam delete-role --role-name "${GENERATED_TEST_ROLE_NAME}" || echo "Failed to clean up test role ${GENERATED_TEST_ROLE_NAME}"
    fi
}
trap cleanup EXIT

if [[ "${CREATE_TEST_ROLE}" = "true" ]]; then
    echo "Creating test role ${GENERATED_TEST_ROLE_NAME}"
    write-role-policy "$(account_from_default_credentials)" ${GENERATED_TEST_ROLE_POLICY_FILE}
    create_role_output=$(aws iam create-role --role-name "${GENERATED_TEST_ROLE_NAME}" --assume-role-policy-document "file://${GENERATED_TEST_ROLE_POLICY_FILE}")
    rm ${GENERATED_TEST_ROLE_POLICY_FILE}
    TEST_ROLE_ARN="$(echo ${create_role_output} | jq -r '.Role.Arn')"
fi

source hack/setup-go.sh

go version

make clean
make bin

if [[ -d ${TEST_ARTIFACTS}/k8s.io/kubernetes ]]; then
    rm -rf ${TEST_ARTIFACTS}/k8s.io/kubernetes
fi

mkdir -p ${TEST_ARTIFACTS}/k8s.io/kubernetes
git clone --branch ${KUBERNETES_TAG} --depth 1 https://github.com/kubernetes/kubernetes.git ${TEST_ARTIFACTS}/k8s.io/kubernetes --depth 1

pushd ${TEST_ARTIFACTS}/k8s.io/kubernetes
make generated_files
./hack/install-etcd.sh
export PATH="${TEST_ARTIFACTS}/k8s.io/kubernetes/third_party/etcd:${PATH}"
popd

pushd ${REPO_ROOT}/tests/integration
export AWS_REGION=${AWS_REGION:-us-west-2}
go test -v ./server -test-artifacts-dir="${TEST_ARTIFACTS}" -authenticator-binary-path="${REPO_ROOT}/_output/bin/aws-iam-authenticator" -role-arn="${TEST_ROLE_ARN}"
popd
