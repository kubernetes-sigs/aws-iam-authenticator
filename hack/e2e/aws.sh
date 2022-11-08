#!/bin/bash

set -uo pipefail

BASE_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
source "${BASE_DIR}"/util.sh

function create_role() {
  ROLE_NAME=${1}
  ROLE_DESCRIPTION=${2}
  AWS_ACCOUNT_ID=${3}
  REGION=${4}

  set +e
  ROLE_INFO=$(aws iam get-role --region "${REGION}" --role-name="$ROLE_NAME")
  if [[ $? != 0 ]]; then
    set -e
    loudecho "Creating ${ROLE_NAME} role" >&2

    ## define a role trust policy that opens the role to users in your account (limited by IAM policy)
    POLICY=$(echo -n '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'; echo -n "$AWS_ACCOUNT_ID"; echo -n ':root"},"Action":"sts:AssumeRole"}]}')

    ## create a role named KubernetesAdmin (will print the new role's ARN)
    ROLE_ARN=$(aws iam create-role \
      --region "${REGION}" \
      --role-name "$ROLE_NAME" \
      --description "$ROLE_DESCRIPTION" \
      --assume-role-policy-document "$POLICY" \
      --output text \
      --query 'Role.Arn')
  else
    set -e
    loudecho "${ROLE_NAME} role already exists" >&2

    ROLE_ARN=$(echo "${ROLE_INFO}" | jq -r '.Role.Arn')
  fi

  echo "${ROLE_ARN}"
}
