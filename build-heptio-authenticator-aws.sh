#!/bin/bash

# create output folder for binary
mkdir -p build-output

# build in dockcer container and copy to build output dir
docker run -v $(pwd)/build-output:/project golang:1.8.0-alpine sh -c "apk -Uuv add curl git && go get -u -v github.com/heptio/authenticator/cmd/heptio-authenticator-aws && cp /go/bin/heptio-authenticator-aws /project"