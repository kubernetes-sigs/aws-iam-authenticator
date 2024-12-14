#!/usr/bin/env bash

# Copyright 2017 The Kubernetes Authors.
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
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
CODE_GEN_VERSION=$(go mod edit -print |grep 'k8s.io/code-generator' | cut -f2 -d' ')
CODE_GEN_PKG=${CODE_GEN_PKG:-$GOPATH/pkg/mod/k8s.io/code-generator\@${CODE_GEN_VERSION}}
chmod +x ${CODE_GEN_PKG}/kube_codegen.sh

AUTHENTICATOR_ROOT="${SCRIPT_ROOT}/pkg/mapper/crd"
AUTHENTICATOR_PKG="sigs.k8s.io/aws-iam-authenticator"

source "${CODE_GEN_PKG}/kube_codegen.sh"

kube::codegen::gen_helpers \
	--boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
  "${AUTHENTICATOR_ROOT}/apis" \

kube::codegen::gen_client \
  --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
  --output-dir "${AUTHENTICATOR_ROOT}/generated" \
  --output-pkg "${AUTHENTICATOR_PKG}/pkg/mapper/crd/generated" \
  --with-watch \
  "${AUTHENTICATOR_ROOT}/apis" \
