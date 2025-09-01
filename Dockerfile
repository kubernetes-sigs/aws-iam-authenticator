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
ARG image=public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-nonroot:2024-10-01-1727740884.2023
ARG golang_image=public.ecr.aws/eks-distro-build-tooling/golang:1.24.6

FROM --platform=$BUILDPLATFORM $golang_image AS builder
WORKDIR /go/src/github.com/kubernetes-sigs/aws-iam-authenticator
COPY . .
RUN go version

ARG TARGETOS TARGETARCH
RUN GOPROXY=direct GOOS=$TARGETOS GOARCH=$TARGETARCH make bin
RUN chown 65532 _output/bin/aws-iam-authenticator

FROM --platform=$TARGETPLATFORM public.ecr.aws/eks-distro/kubernetes/go-runner:v0.18.0-eks-1-34-latest AS go-runner

FROM --platform=$TARGETPLATFORM $image
COPY --from=go-runner /go-runner /usr/local/bin/go-runner
COPY --from=builder /go/src/github.com/kubernetes-sigs/aws-iam-authenticator/_output/bin/aws-iam-authenticator /aws-iam-authenticator
ENTRYPOINT ["/aws-iam-authenticator"]
