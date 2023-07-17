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
access_entry_username_prefix_template="${REPO_ROOT}/hack/dev/access-entries-username-prefix.template"
policies_json="${OUTPUT}/dev/authenticator/policies.json"
allow_assume_role_policies_template="${REPO_ROOT}/hack/dev/allow_assume_role_policy.template"
allow_assume_role_policies_json="${OUTPUT}/dev/authenticator/allow_assume_role_policy.json"
access_entry_tmp="${OUTPUT}/dev/authenticator/access-entry/access-entries.tmp"
access_entry_user_tmp="${OUTPUT}/dev/authenticator/access-entry/access-entries-user.tmp"
access_entry_json="${OUTPUT}/dev/authenticator/access-entry/access-entries.json"
backend_mode_json="${OUTPUT}/dev/authenticator/access-entry/backend-modes.json"
client_dir="${OUTPUT}/dev/client"
kubectl_kubeconfig="${client_dir}/kubeconfig.yaml"

REGION=${AWS_REGION:-us-west-2}
AWS_ACCOUNT=$(aws sts get-caller-identity --query "Account" --output text)
AWS_TEST_ROLE=${AWS_TEST_ROLE-authenticator-dev-cluster-testrole}
USERNAME_TEST_ROLE=${USERNAME_TEST_ROLE-authenticator-username-testrole}

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

function e2e_dynamicfile_username_prefix_enforce(){
cat << EOF > ${backend_mode_json}
{
  "backendMode": "MountedFile DynamicFile"
}
EOF

  sleep 20
  set +e
  RoleOutput=$(aws iam get-role --role-name ${USERNAME_TEST_ROLE} 2>/dev/null)

  if [ -z "$RoleOutput" ]; then
      sed -e "s|{{AWS_ACCOUNT}}|${AWS_ACCOUNT}|g" \
              "${policies_template}" > "${policies_json}"
      sleep 2
      aws iam create-role --role-name ${USERNAME_TEST_ROLE} --assume-role-policy-document file://${policies_json} 1>/dev/null
      sleep 10
  fi

  #detect if run on github and allow the test account to assume role accordingly
  if [ $CI = true ]
      then
          OUT=$(aws iam list-attached-user-policies --user-name awstester)
          echo $OUT
          if [ -z "$OUT" ]
              then
                  OUT=$(aws iam list-policies --query 'Policies[?PolicyName==`allow-assume-role`]'|jq '.[0]'|jq -r '.Arn')
                  echo $OUT
                  if [ -z "$OUT" ]; then
                      sed -e "s|{{AWS_ACCOUNT}}|${AWS_ACCOUNT}|g" \
                          "${allow_assume_role_policies_template}" > "${allow_assume_role_policies_json}"
                      sleep 2
                      OUT=$(aws iam create-policy --policy-name allow-assume-role --policy-document file://${allow_assume_role_policies_json})
                      policy_arn=$(echo $OUT| jq -r '.Policy.Arn')
                  else
                      policy_arn=$OUT
                  fi
                  echo ${policy_arn}
                  OUT=$(aws iam attach-user-policy --policy-arn ${policy_arn} --user-name awstester)
                  echo $OUT
                  echo $(aws iam get-user)
          fi
  fi

  set -e
  OUT=$(aws sts assume-role --role-arn arn:aws:iam::${AWS_ACCOUNT}:role/${USERNAME_TEST_ROLE} --role-session-name system);\
  export AWS_ACCESS_KEY_ID=$(echo $OUT | jq -r '.Credentials''.AccessKeyId');\
  export AWS_SECRET_ACCESS_KEY=$(echo $OUT | jq -r '.Credentials''.SecretAccessKey');\
  export AWS_SESSION_TOKEN=$(echo $OUT | jq -r '.Credentials''.SessionToken');

  OUT=$(aws sts get-caller-identity|grep "${USERNAME_TEST_ROLE}")
  echo "assumed role: "$OUT
  if [ -z "$OUT" ]
      then
          echo "can't assume-role: "${USERNAME_TEST_ROLE}
          exit 1
  fi
  USERID=$(aws sts get-caller-identity|jq -r '.UserId'|cut -d: -f1)
  echo "userid: " $USERID

  #update access entry to add the test role
  sed -e "s|{{AWS_ACCOUNT}}|${AWS_ACCOUNT}|g" \
      -e "s|{{USERNAME_TEST_ROLE}}|${USERNAME_TEST_ROLE}|g" \
      -e "s|{{USER_ID}}|${USERID}|g" \
            "${access_entry_username_prefix_template}" > "${access_entry_user_tmp}"
  mv "${access_entry_user_tmp}"  "${access_entry_json}"
  #sleep 10 seconds to make access entry effective
  sleep 10
  set +e
  OUT=$(kubectl --kubeconfig=${kubectl_kubeconfig} --context="test-authenticator" get nodes 2>/var/tmp/err.txt)
  if grep -q "Unauthorized" "/var/tmp/err.txt"; then
      echo "end to end testing for dynamicfile mode succeeded"
  else
      echo "end to end testing for dynamicfile mode failed"
      exit 1
  fi
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

function e2e_dynamicfile(){
cat << EOF > "${backend_mode_json}"
{
  "backendMode": "MountedFile DynamicFile"
}
EOF
  sleep 20
  set +e
  RoleOutput=$(aws iam get-role --role-name authenticator-dev-cluster-testrole 2>/dev/null)

  if [ -z "$RoleOutput" ]; then
      sed -e "s|{{AWS_ACCOUNT}}|${AWS_ACCOUNT}|g" \
              "${policies_template}" > "${policies_json}"
      sleep 2
      aws iam create-role --role-name ${AWS_TEST_ROLE} --assume-role-policy-document file://${policies_json} 1>/dev/null
      sleep 10
  fi

  #detect if run on github and allow the test account to assume role accordingly
  if [ $CI = true ]
      then
          OUT=$(aws iam list-attached-user-policies --user-name awstester)
          echo $OUT
          if [ -z "$OUT" ]
              then
                  OUT=$(aws iam list-policies|grep allow-assume-role|grep Arn| awk '{print $2}')
                  if [ -z "$OUT" ]; then
                      sed -e "s|{{AWS_ACCOUNT}}|${AWS_ACCOUNT}|g" \
                          "${allow_assume_role_policies_template}" > "${allow_assume_role_policies_json}"
                      sleep 2
                      OUT=$(aws iam create-policy --policy-name allow-assume-role --policy-document file://${allow_assume_role_policies_json})
                      policy_arn=$(echo $OUT| jq -r '.Policy.Arn')
                  else
                      policy_arn=$(echo ${OUT%?} | sed 's/\"//g')
                  fi
                  echo ${policy_arn}
                  OUT=$(aws iam attach-user-policy --policy-arn ${policy_arn} --user-name awstester)
                  echo $OUT
                  echo $(aws iam get-user)
          fi
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
  USERID=$(aws sts get-caller-identity|jq -r '.UserId'|cut -d: -f1)
  echo "userid: " $USERID
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
      -e "s|{{USER_ID}}|${USERID}|g" \
            "${access_entry_template}" > "${access_entry_tmp}"
  mv "${access_entry_tmp}"  "${access_entry_json}"
  #sleep 10 seconds to make access entry effective
  sleep 10

  OUT=$(kubectl --kubeconfig=${kubectl_kubeconfig} --context="test-authenticator" get nodes|grep Ready)
  if [ ! -z "$OUT" ]
      then
          echo $OUT
          echo "end to end testing for dynamicfile mode succeeded"

      else
          echo "testing failed"
          exit 1
  fi
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

function e2e_dynamic_backend_mode(){

  # set backend mode to MOUNTEDFILE only
  sed -e "s|{{AWS_ACCOUNT}}|${AWS_ACCOUNT}|g" \
      -e "s|{{AWS_TEST_ROLE}}|${AWS_TEST_ROLE}|g" \
      -e "s|{{USER_ID}}|${USERID}|g" \
            "${access_entry_template}" > "${access_entry_tmp}"
  mv "${access_entry_tmp}"  "${access_entry_json}"
cat << EOF > "${backend_mode_json}"
{
  "backendMode": "MountedFile"
}
EOF
  sleep 20

  set -e
  OUT=$(aws sts assume-role --role-arn arn:aws:iam::${AWS_ACCOUNT}:role/${AWS_TEST_ROLE} --role-session-name aaa);\
  export AWS_ACCESS_KEY_ID=$(echo $OUT | jq -r '.Credentials''.AccessKeyId');\
  export AWS_SECRET_ACCESS_KEY=$(echo $OUT | jq -r '.Credentials''.SecretAccessKey');\
  export AWS_SESSION_TOKEN=$(echo $OUT | jq -r '.Credentials''.SessionToken');

  OUT=$(aws sts get-caller-identity)
  echo "current role: "$OUT
  if [ -z "$OUT" ]
      then
          echo "can't assume-role: ""${AWS_TEST_ROLE}"
          exit 1
  fi

  set +e
  OUT=$(kubectl --kubeconfig=${kubectl_kubeconfig} --context="test-authenticator" get nodes 2>/var/tmp/err.txt)
  echo $OUT
  if grep -q "Unauthorized" "/var/tmp/err.txt"; then
      echo -n ""
  else
      echo "end to end testing for dynamic backend mode failed"
      exit 1
  fi

  # set backend mode to MOUNTEDFILE,DYNAMICFILE
cat << EOF > "${backend_mode_json}"
{
  "backendMode": "MountedFile DynamicFile"
}
EOF
  sleep 20

  OUT=$(aws sts get-caller-identity)
  echo "current role: "$OUT
  if [ -z "$OUT" ]
      then
          echo "can't assume-role: ""${AWS_TEST_ROLE}"
          exit 1
  fi

  OUT=$(kubectl --kubeconfig=${kubectl_kubeconfig} --context="test-authenticator" get nodes|grep Ready)
  if [ ! -z "$OUT" ]
      then
          echo $OUT
          echo "end to end testing for dynamic backend mode succeeded"

      else
          echo "end to end testing for dynamic backend mode failed"
          exit 1
  fi
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

echo "start end to end testing for mountfile mode"
e2e_mountfile
echo "starting end to end testing for dynamicfile mode"
e2e_dynamicfile
echo "starting end to end testing for dynamic backend mode"
e2e_dynamic_backend_mode
echo "starting end to end testing for dynamicfile mode with username prefix"
e2e_dynamicfile_username_prefix_enforce