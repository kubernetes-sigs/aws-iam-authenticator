#!/bin/bash

set -uo pipefail

OS_ARCH=$(go env GOOS)-amd64

BASE_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
source "${BASE_DIR}"/util.sh

function kops_install() {
  INSTALL_PATH=${1}
  KOPS_VERSION=${2}
  if [[ ! -e ${INSTALL_PATH}/kops ]]; then
    KOPS_DOWNLOAD_URL=https://github.com/kubernetes/kops/releases/download/v${KOPS_VERSION}/kops-${OS_ARCH}
    curl -L -X GET "${KOPS_DOWNLOAD_URL}" -o "${INSTALL_PATH}"/kops
    chmod +x "${INSTALL_PATH}"/kops
  fi
}

function kops_create_cluster() {
  SSH_KEY_PATH=${1}
  CLUSTER_NAME=${2}
  KOPS_BIN=${3}
  KUBECTL_BIN=${4}
  ZONES=${5}
  NODE_COUNT=${6}
  INSTANCE_TYPE=${7}
  K8S_VERSION=${8}
  CLUSTER_FILE=${9}
  KUBECONFIG=${10}
  USER=${11}
  KUBECONFIG_ADMIN=${12}
  TEST_DIR=${13}
  KOPS_STATE_FILE=${14}
  KOPS_PATCH_FILE=${15}

  if [[ ! -e ${SSH_KEY_PATH} ]]; then
    loudecho "Generating SSH key $SSH_KEY_PATH"
    ssh-keygen -P csi-e2e -f "${SSH_KEY_PATH}"
  else
    loudecho "Reusing SSH key $SSH_KEY_PATH"
  fi

  set +e
  if ${KOPS_BIN} get cluster --state "${KOPS_STATE_FILE}" "${CLUSTER_NAME}"; then
    set -e
    loudecho "Replacing cluster $CLUSTER_NAME with $CLUSTER_FILE"
    ${KOPS_BIN} replace --state "${KOPS_STATE_FILE}" -f "${CLUSTER_FILE}"
  else
    set -e
    loudecho "Creating cluster $CLUSTER_NAME with $CLUSTER_FILE (dry run)"
    ${KOPS_BIN} create cluster --state "${KOPS_STATE_FILE}" \
      --zones "${ZONES}" \
      --node-count="${NODE_COUNT}" \
      --node-size="${INSTANCE_TYPE}" \
      --kubernetes-version="${K8S_VERSION}" \
      --dry-run \
      -o json \
      "${CLUSTER_NAME}" > "${CLUSTER_FILE}.tmp"

    # TODO: maybe a less hacky way of doing this?
    cat <(echo "[") "${CLUSTER_FILE}.tmp" <(echo "]") > "$CLUSTER_FILE"
    rm "${CLUSTER_FILE}.tmp"

    kops_patch_cluster_file "$CLUSTER_FILE" "$KOPS_PATCH_FILE" "$KUBECTL_BIN"

    loudecho "Creating cluster $CLUSTER_NAME with $CLUSTER_FILE"
    ${KOPS_BIN} create --state "${KOPS_STATE_FILE}" -f "${CLUSTER_FILE}"
  fi

  loudecho "Updating cluster $CLUSTER_NAME with $CLUSTER_FILE"
  ${KOPS_BIN} update cluster --state "${KOPS_STATE_FILE}" "${CLUSTER_NAME}" \
    --ssh-public-key="${SSH_KEY_PATH}".pub --yes

  ${KOPS_BIN} export kubeconfig --state "${KOPS_STATE_FILE}" --kubeconfig "${KUBECONFIG_ADMIN}" "${CLUSTER_NAME}" --admin
  ${KOPS_BIN} export kubeconfig --state "${KOPS_STATE_FILE}" --kubeconfig "${KUBECONFIG}" "${CLUSTER_NAME}" --user "${USER}"

  loudecho "Waiting on cluster ${CLUSTER_NAME}..."
  # we can't just use kops validate, because it requires the authenticator to be ready, but it's not set up yet...
  COUNT=0
  set +e
  # this 4 is hard-coded! kops by default creates 1 master and 3 workers.
  while [[ $(${KUBECTL_BIN} get nodes --kubeconfig $KUBECONFIG_ADMIN | awk '/Ready/ {ready++} END {print ready}') -ne 4 ]]; do
    sleep 5s
    COUNT=$((COUNT+1))
    if [ $COUNT -gt 200 ]; then
      loudecho "Cluster did not start, aborting"
      return 1
    fi
  done
  set -e
  loudecho "Cluster is up!"
}

function kops_delete_cluster() {
  KOPS_BIN=${1}
  CLUSTER_NAME=${2}
  KOPS_STATE_FILE=${3}
  loudecho "Deleting cluster ${CLUSTER_NAME}"
  ${KOPS_BIN} delete cluster --name "${CLUSTER_NAME}" --state "${KOPS_STATE_FILE}" --yes
}

function kops_patch_cluster_file() {
  CLUSTER_FILE=${1}
  KOPS_PATCH_FILE=${2}
  KUBECTL_BIN=${3}

  loudecho "Patching cluster $CLUSTER_NAME with $KOPS_PATCH_FILE"

  # Temporary intermediate files for patching
  CLUSTER_FILE_0=$CLUSTER_FILE.0
  CLUSTER_FILE_1=$CLUSTER_FILE.1

  # Output is an array of Cluster and InstanceGroups
  jq '.[] | select(.kind=="Cluster")' "$CLUSTER_FILE" > "$CLUSTER_FILE_0"

  # Patch only the Cluster
  ${KUBECTL_BIN} patch -f "$CLUSTER_FILE_0" --local --type merge --patch "$(cat "$KOPS_PATCH_FILE")" -o json > "$CLUSTER_FILE_1"
  mv "$CLUSTER_FILE_1" "$CLUSTER_FILE_0"

  # Write the patched Cluster back to the array
  jq '(.[] | select(.kind=="Cluster")) = $cluster[0]' "$CLUSTER_FILE" --slurpfile cluster "$CLUSTER_FILE_0" > "$CLUSTER_FILE_1"
  mv "$CLUSTER_FILE_1" "$CLUSTER_FILE_0"

  # HACK convert the json array to multiple yaml documents
  for ((i = 0; i < $(jq length "$CLUSTER_FILE_0"); i++)); do
    echo "---" >> "$CLUSTER_FILE_1"
    jq ".[$i]" "$CLUSTER_FILE_0" | ${KUBECTL_BIN} patch -f - --local -p "{}" --type merge -o yaml >> "$CLUSTER_FILE_1"
  done
  mv "$CLUSTER_FILE_1" "$CLUSTER_FILE_0"

  # Done patching, overwrite original CLUSTER_FILE
  mv "$CLUSTER_FILE_0" "$CLUSTER_FILE"
}
