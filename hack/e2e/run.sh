#!/bin/bash

# Copyright 2022 The Kubernetes Authors.
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

set -euo pipefail

BASE_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
source "${BASE_DIR}"/kops.sh
source "${BASE_DIR}"/aws.sh

KOPS_USERID=$(whoami)
#detect if run on github and set var accordingly
if [ $CI = true ]
then
  REPO_NAME=${REPO_NAME:-aws-iam-authenticator-e2e}
  KOPS_STATE_BUCKET=${KOPS_STATE_BUCKET:-k8s-kops-aws-iam-authenticator-shared-e2e}
else
  REPO_NAME=${REPO_NAME:-aws-iam-authenticator}
  KOPS_STATE_BUCKET=${KOPS_STATE_BUCKET:-k8s-kops-aws-iam-authenticator-${KOPS_USERID}}
fi

TEST_ID=${TEST_ID:-$RANDOM}
CLUSTER_NAME=test-cluster-${TEST_ID}.k8s.local
CLUSTER_TYPE=kops

TEST_DIR=${BASE_DIR}/e2e-test-artifacts
BIN_DIR=${TEST_DIR}/bin
SSH_KEY_PATH=${TEST_DIR}/id_rsa
CLUSTER_FILE=${TEST_DIR}/${CLUSTER_NAME}.json
KUBECONFIG=${KUBECONFIG:-"${TEST_DIR}/${CLUSTER_NAME}.kubeconfig"}
KUBECONFIG_ADMIN=${KUBECONFIG_ADMIN:-"${TEST_DIR}/${CLUSTER_NAME}-admin.kubeconfig"}

REGION=${AWS_REGION:-us-west-2}
ZONES=${AWS_AVAILABILITY_ZONES:-us-west-2a,us-west-2b,us-west-2c}
FIRST_ZONE=$(echo "${ZONES}" | cut -d, -f1)
NODE_COUNT=${NODE_COUNT:-3}
INSTANCE_TYPE=${INSTANCE_TYPE:-c5.large}

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
USER_ARN=$(aws sts get-caller-identity --query Arn --output text)
ECR_URL=${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com
IMAGE_NAME=${IMAGE_NAME:-${ECR_URL}/${REPO_NAME}}
IMAGE_TAG=${IMAGE_TAG:-${TEST_ID}}

K8S_VERSION=${K8S_VERSION:-1.22.10}

KOPS_VERSION=${KOPS_VERSION:-1.23.0}

KOPS_STATE_FILE=${KOPS_STATE_FILE:-s3://${KOPS_STATE_BUCKET}}
KOPS_PATCH_FILE=${KOPS_PATCH_FILE:-${BASE_DIR}/kops-patch.yaml}

ROLE_PREFIX=${ROLE_PREFIX:-"aws-iam-authenticator-test-role-"}
ROLES_SPEC_FILE=${ROLES_SPEC_FILE:-${BASE_DIR}/roles.yaml}
APISERVER_UPDATE_FILE=${APISERVER_UPDATE_FILE:-${BASE_DIR}/apiserver-update.yaml}
KUBECONFIG_UPDATE_FILE=${KUBECONFIG_UPDATE_FILE:-${BASE_DIR}/kubeconfig-update.yaml}

KUBECTL_VERSION=${KUBECTL_VERSION:-1.24.0}

TEST_PATH=${TEST_PATH:-"./..."}
ARTIFACTS=${ARTIFACTS:-"${TEST_DIR}/artifacts"}
GINKGO_FOCUS=${GINKGO_FOCUS:-"\[iam-auth-e2e\]"}
GINKGO_SKIP=${GINKGO_SKIP:-"\[Disruptive\]"}
GINKGO_NODES=${GINKGO_NODES:-4}
TEST_EXTRA_FLAGS=${TEST_EXTRA_FLAGS:-}

CLEAN=${CLEAN:-"true"}

# Setup

loudecho "Testing in region ${REGION} and zones ${ZONES}"
mkdir -p "${BIN_DIR}"
export PATH=${PATH}:${BIN_DIR}

# Installation

loudecho "Installing kops ${KOPS_VERSION} to ${BIN_DIR}"
kops_install "${BIN_DIR}" "${KOPS_VERSION}"
KOPS_BIN=${BIN_DIR}/kops

loudecho "Installing kubectl ${KUBECTL_VERSION} to ${BIN_DIR}"
KUBECTL_BIN=${BIN_DIR}/kubectl
if [[ ! -e ${KUBECTL_BIN} ]]; then
  (cd ${BIN_DIR} && curl -LO "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && chmod +x kubectl)
fi
# TODO: validate binary using checksum

loudecho "Installing ginkgo to ${BIN_DIR}"
GINKGO_BIN=${BIN_DIR}/ginkgo
if [[ ! -e ${GINKGO_BIN} ]]; then
  pushd /tmp
  GOPATH=${TEST_DIR} GOBIN=${BIN_DIR} GO111MODULE=on go install github.com/onsi/ginkgo/ginkgo@v1.12.0
  popd
fi

# Building and pushing image

loudecho "Building and pushing test driver image to ${IMAGE_NAME}:${IMAGE_TAG}"
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ECR_URL}"
## TODO: there should be a way in the makefile to change these values from default
## IMAGE=${IMAGE_NAME} TAG=${IMAGE_TAG} OS=linux ARCH=amd64 OSVERSION=amazon i
make image
IMAGE_TAG=$(docker images | awk '{print $2}' | awk 'NR==2')
IMAGE_URL="${IMAGE_NAME}:${IMAGE_TAG}"
docker tag "${REPO_NAME}":"${IMAGE_TAG}" $IMAGE_URL

set +e
aws ecr describe-repositories --region "${REGION}" --repository-names "${REPO_NAME}" --query 'repositories[0].repositoryName'
if [[ $? != 0 ]]; then
  set -e
  loudecho "Creating repository ${REPO_NAME} in ECR"
  aws ecr create-repository --region "${REGION}" --repository-name "${REPO_NAME}"
fi
set -e

docker push $IMAGE_URL

make bin
BUILD_BIN=./_output/bin/aws-iam-authenticator
cp $BUILD_BIN $BIN_DIR
AUTHENTICATOR_BIN="${BIN_DIR}/aws-iam-authenticator"

# Cluster creation

set +e
aws s3api head-bucket --bucket ${KOPS_STATE_BUCKET}
if [[ $? != 0 ]]; then
  set -e
  loudecho "Creating bucket ${KOPS_STATE_BUCKET} in S3"
  aws s3api create-bucket --bucket ${KOPS_STATE_BUCKET} --region ${REGION} --create-bucket-configuration "LocationConstraint=${REGION}"
fi
set -e

set +e
if ${KOPS_BIN} get cluster --state "${KOPS_STATE_FILE}" "${CLUSTER_NAME}"; then
  set -e
  NEW_CLUSTER=false
else
  set -e
  NEW_CLUSTER=true
fi

## setting up the configmap
loudecho "Setting up roles"
ADMIN_ROLE_NAME="${ROLE_PREFIX}KubernetesAdmin"
ADMIN_ROLE="$(create_role "${ADMIN_ROLE_NAME}" "Kubernetes administrator role (for AWS IAM Authenticator for Kubernetes)." "${AWS_ACCOUNT_ID}" "${REGION}")"
echo "admin role: $ADMIN_ROLE"
USER_ROLE_NAME="${ROLE_PREFIX}KubernetesUsers"
USER_ROLE="$(create_role "${USER_ROLE_NAME}" "Kubernetes user role (for AWS IAM Authenticator for Kubernetes)." "${AWS_ACCOUNT_ID}" "${REGION}")"
echo "user role: $USER_ROLE"

## actually creating the cluster
## note: you might have to move (or delete) ~/.kube/config for the patching to work.
kops_create_cluster \
  "$SSH_KEY_PATH" \
  "$CLUSTER_NAME" \
  "$KOPS_BIN" \
  "$KUBECTL_BIN" \
  "$ZONES" \
  "$NODE_COUNT" \
  "$INSTANCE_TYPE" \
  "$K8S_VERSION" \
  "$CLUSTER_FILE" \
  "$KUBECONFIG" \
  "$KUBECONFIG_ADMIN" \
  "$TEST_DIR" \
  "$KOPS_STATE_FILE" \
  "$KOPS_PATCH_FILE"
if [[ $? -ne 0 ]]; then
    exit 1
fi

set +e
${KUBECTL_BIN} describe secrets/regcred \
  --namespace=kube-system \
  --kubeconfig "${KUBECONFIG_ADMIN}" > /dev/null 2>&1
set -e
if [[ $? != 0 ]]; then
  ${KUBECTL_BIN} create secret docker-registry regcred \
    --docker-server=${ECR_URL} \
    --docker-username=AWS \
    --docker-password=$(aws ecr get-login-password --region "${REGION}") \
    --namespace=kube-system \
    --kubeconfig "${KUBECONFIG_ADMIN}"
fi

## Applying test roles

loudecho "Applying testing roles"
${KUBECTL_BIN} apply -f "${ROLES_SPEC_FILE}" --kubeconfig "${KUBECONFIG_ADMIN}"

## Updating the DaemonSet

loudecho "Copying daemonset file"
DAEMONSET_FILE=${TEST_DIR}/${CLUSTER_NAME}-deploy.yaml
cp "${BASE_DIR}/deploy.yaml" "${DAEMONSET_FILE}"

## updating values in the config file

loudecho "Updating daemonset values"
sed -i "s/<CLUSTER_NAME>/${CLUSTER_NAME}/g" "${DAEMONSET_FILE}"
sed -i "s/<AWS_ACCOUNT_ID>/${AWS_ACCOUNT_ID}/g" "${DAEMONSET_FILE}"
## using a weird delimiter because the role ARN has / in it
sed -i "s#<ADMIN_ROLE>#${ADMIN_ROLE}#g" "${DAEMONSET_FILE}"
sed -i "s#<USER_ROLE>#${USER_ROLE}#g" "${DAEMONSET_FILE}"
sed -i "s#<USER_ARN>#${USER_ARN}#g" "${DAEMONSET_FILE}"
sed -i "s#<IMAGE_NAME>#${IMAGE_NAME}:${IMAGE_TAG}#g" "${DAEMONSET_FILE}"

## applying the daemonset to the cluster

loudecho "Applying the daemonset"
${KUBECTL_BIN} apply -f "${DAEMONSET_FILE}" --kubeconfig "${KUBECONFIG_ADMIN}"

kubectl get pods -n kube-system --kubeconfig "${KUBECONFIG_ADMIN}" | grep aws-iam-authenticator | awk '{print $1}' | xargs kubectl delete pod -n kube-system --kubeconfig "${KUBECONFIG_ADMIN}"

if [ $NEW_CLUSTER = true ]; then
  loudecho "Updating kubeconfig"
  sed "s/<CLUSTER_NAME>/${CLUSTER_NAME}/g" "${KUBECONFIG_UPDATE_FILE}" | sed "s#<ADMIN_ROLE>#${ADMIN_ROLE}#g" | sed "s#<AUTHENTICATOR_BIN>#${AUTHENTICATOR_BIN}#g" >> "${KUBECONFIG}"
  sed -i "s/users: null/users:/g" "${KUBECONFIG}"
  sed -i "s/    user: \"\"/    user: ${CLUSTER_NAME}/g" "${KUBECONFIG}"
fi

${KOPS_BIN} validate cluster --state "${KOPS_STATE_FILE}" --kubeconfig "${KUBECONFIG_ADMIN}" --wait 10m
loudecho "Cluster is ready"

# Testing

loudecho "Testing focus ${GINKGO_FOCUS}"
eval "EXPANDED_TEST_EXTRA_FLAGS=$TEST_EXTRA_FLAGS"
set -x
set +e
pushd tests/e2e
BASE_DIR=${BASE_DIR} CLUSTER_NAME=${CLUSTER_NAME} ADMIN_ROLE=${ADMIN_ROLE} AUTHENTICATOR_BIN=${AUTHENTICATOR_BIN} USER_ROLE=${USER_ROLE} ${GINKGO_BIN} -p -nodes="${GINKGO_NODES}" -v --focus="${GINKGO_FOCUS}" --skip="${GINKGO_SKIP}" "${TEST_PATH}" -- -kubeconfig="${KUBECONFIG_ADMIN}" -report-dir="${ARTIFACTS}" -gce-zone="${FIRST_ZONE}" "${EXPANDED_TEST_EXTRA_FLAGS}"
TEST_PASSED=$?
popd
set -e
set +x
loudecho "TEST_PASSED: ${TEST_PASSED}"

# Cleanup

if [[ "${CLEAN}" == true ]]; then
  loudecho "Cleaning"

  kops_delete_cluster \
    "${KOPS_BIN}" \
    "${CLUSTER_NAME}" \
    "${KOPS_STATE_FILE}"

  aws iam delete-role --role-name "${ADMIN_ROLE_NAME}" --region ${REGION}
  aws iam delete-role --role-name "${USER_ROLE_NAME}" --region ${REGION}
else
  loudecho "Not cleaning"
fi

if [[ $TEST_PASSED -ne 0 ]]; then
  loudecho "FAIL!"
  exit 1
else
  loudecho "SUCCESS!"
fi
