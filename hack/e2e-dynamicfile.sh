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


#
# An easy way to quickly do end to end test for aws-iam-authenticator
# after creating the kind cluster and running authenticator in docker.
#

REPO_ROOT="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
OUTPUT="${OUTPUT:-${REPO_ROOT}/_output}"

# Location of templates, config files, mounts
policies_template="${REPO_ROOT}/hack/dev/policies.template"
access_entry_template="${REPO_ROOT}/hack/dev/access-entries.template"
policies_json="${OUTPUT}/dev/authenticator/policies.json"
access_entry_tmp="${OUTPUT}/dev/authenticator/access-entry/access-entries.tmp"
access_entry_json="${OUTPUT}/dev/authenticator/access-entry/access-entries.json"
client_dir="${OUTPUT}/dev/client"
kubectl_kubeconfig="${client_dir}/kubeconfig.yaml"

REGION=${AWS_REGION:-us-west-2}
AWS_ACCOUNT=$(aws sts get-caller-identity --query "Account" --output text)
AWS_TEST_ROLE=${AWS_TEST_ROLE-authenticator-dev-cluster-testrole}


function e2e_mountfile() {
  sleep 5
  set +e
  OUT=$(kubectl --kubeconfig=${kubectl_kubeconfig} --context="test-authenticator" get nodes|grep Ready 2>/dev/null)
  echo $OUT
  if [ ! -z "$OUT" ]
      then
          echo "e2e mountfile test pass"
      else
          echo "e2e mountfile test fail"
          exit 1
  fi

}

function e2e_dynamicfile(){
  set +e
  RoleOutput=$(aws iam get-role --role-name authenticator-dev-cluster-testrole 2>/dev/null)

  if [ -z "$RoleOutput" ]; then
    sed -e "s|{{AWS_ACCOUNT}}|${AWS_ACCOUNT}|g" \
            "${policies_template}" > "${policies_json}"
    aws iam create-role --role-name ${AWS_TEST_ROLE} --assume-role-policy-document file://${policies_json} 1>/dev/null
    sleep 10
  fi

  set -e
  OUT=$(aws sts assume-role --role-arn arn:aws:iam::${AWS_ACCOUNT}:role/${AWS_TEST_ROLE} --role-session-name aaa);\
  export AWS_ACCESS_KEY_ID=$(echo $OUT | jq -r '.Credentials''.AccessKeyId');\
  export AWS_SECRET_ACCESS_KEY=$(echo $OUT | jq -r '.Credentials''.SecretAccessKey');\
  export AWS_SESSION_TOKEN=$(echo $OUT | jq -r '.Credentials''.SessionToken');

  OUT=$(aws sts get-caller-identity|grep "${AWS_TEST_ROLE}")
  echo "assumed role: "$OUT
  if [ -z "$OUT" ]
      then
          echo "can't assume-role: "${AWS_TEST_ROLE}
          exit 1
  fi

  #run kubectl cmd without adding the role into access entry
  if [ -f ${access_entry_json} ]
      then
          mv "${access_entry_json}" "${access_entry_tmp}"
  fi

  sleep 10
  set +e
  OUT=$(kubectl --kubeconfig=${kubectl_kubeconfig} --context="test-authenticator" get nodes 2>/dev/null)

  if [ ! -z "$OUT" ]
      then
          echo "testing failed"
          exit 1
  fi
  #update access entry to add the test role

  sed -e "s|{{AWS_ACCOUNT}}|${AWS_ACCOUNT}|g" \
      -e "s|{{AWS_TEST_ROLE}}|${AWS_TEST_ROLE}|g" \
            "${access_entry_template}" > "${access_entry_tmp}"
  mv "${access_entry_tmp}"  "${access_entry_json}"
  #sleep 10 seconds to make access entry effective
  sleep 10

  OUT=$(kubectl --kubeconfig=${kubectl_kubeconfig} --context="test-authenticator" get nodes|grep Ready)
  if [ ! -z "$OUT" ]
      then
          echo $OUT
          unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
          aws iam delete-role --role-name ${AWS_TEST_ROLE}
          echo "end to end testing for dynamicfile mode succeeded"
          exit 0

      else
          echo "testing failed"
          exit 1
  fi
}





