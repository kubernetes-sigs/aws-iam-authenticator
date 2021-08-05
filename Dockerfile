# Copyright 2019 The Kubernetes Authors.
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
ARG image=public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-nonroot:2021-08-26-1630012071

FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/kubernetes-sigs/aws-iam-authenticator
COPY . .
RUN make bin
RUN chown 65532 _output/bin/aws-iam-authenticator

FROM $image
COPY --from=builder /go/src/github.com/kubernetes-sigs/aws-iam-authenticator/_output/bin/aws-iam-authenticator /aws-iam-authenticator
ENTRYPOINT ["/aws-iam-authenticator"]
