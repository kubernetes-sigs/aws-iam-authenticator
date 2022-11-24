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
ARG image=public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-nonroot:2021-12-01-1638322424
ARG golang_image=public.ecr.aws/eks-distro-build-tooling/golang:1.19-gcc


FROM --platform=$BUILDPLATFORM $golang_image AS builder
WORKDIR /go/src/github.com/kubernetes-sigs/aws-iam-authenticator
COPY . .
#RUN go mod download
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH make build-linux-bins
RUN chown 65532 _output/bin/*

FROM public.ecr.aws/eks-distro/kubernetes/go-runner:v0.9.0-eks-1-21-4 as go-runner

FROM $image
ARG TARGETARCH
COPY --from=go-runner /usr/local/bin/go-runner /usr/local/bin/go-runner
COPY --from=builder /go/src/github.com/kubernetes-sigs/aws-iam-authenticator/_output/bin/aws-iam-authenticator_${TARGETARCH} /aws-iam-authenticator
ENTRYPOINT ["/aws-iam-authenticator"]
