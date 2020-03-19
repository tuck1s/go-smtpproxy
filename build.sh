#!/usr/bin/env bash
# flag -ldflags "-s -w" could be used to reduce size of binaries slightly
go build -v ./cmd/proxy
