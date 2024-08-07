#!/usr/bin/env bash

GOOS=linux GOARCH=amd64 go build -o dpi-bypass-proxy_amd64 -ldflags "-s -w" && upx dpi-bypass-proxy_amd64
GOOS=linux GOARCH=arm go build -o dpi-bypass-proxy_arm -ldflags "-s -w" && upx dpi-bypass-proxy_arm
GOOS=linux GOARCH=arm64 go build -o dpi-bypass-proxy_arm64 -ldflags "-s -w" && upx dpi-bypass-proxy_arm64
GOOS=linux GOARCH=mips go build -o dpi-bypass-proxy_mips -ldflags "-s -w" && upx dpi-bypass-proxy_mips
