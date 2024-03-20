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

# cd to the repo root and setup go
REPO_ROOT="$(cd "$( dirname "${BASH_SOURCE[0]}" )"/.. &> /dev/null && pwd)"

source hack/setup-go.sh

pushd ${REPO_ROOT}

go version
go test -v -coverprofile=coverage.out -race sigs.k8s.io/aws-iam-authenticator/pkg/...
go tool cover -html=coverage.out -o coverage.html
popd
