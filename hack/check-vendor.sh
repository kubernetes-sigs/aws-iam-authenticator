#!/usr/bin/env bash

export GO111MODULE=on
rm -rf vendor
go mod vendor
VENDOR_DIFF_LINES=$(git diff --numstat)

if [[ -n "$VENDOR_DIFF_LINES" ]]; then
    echo "Vendored code did not match was expected"
    git diff
    exit 1
fi
