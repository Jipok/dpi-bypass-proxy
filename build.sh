#!/usr/bin/env bash

GOOS=linux GOARCH=amd64 go build -o dpi-bypass-proxy_amd64 -ldflags "-s -w" && upx dpi-bypass-proxy_amd64
GOOS=linux GOARCH=arm go build -o dpi-bypass-proxy_arm -ldflags "-s -w" && upx dpi-bypass-proxy_arm
GOOS=linux GOARCH=arm64 go build -o dpi-bypass-proxy_arm64 -ldflags "-s -w" && upx dpi-bypass-proxy_arm64
GOOS=linux GOARCH=mips GOMIPS=softfloat go build -o dpi-bypass-proxy_mips -ldflags "-s -w" && upx dpi-bypass-proxy_mips
GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o dpi-bypass-proxy_mipsle -ldflags "-s -w" && upx dpi-bypass-proxy_mipsle
#GOOS=linux GOARCH=mips64le GOMIPS=softfloat go build -o dpi-bypass-proxy_mips64le -ldflags "-s -w" && upx dpi-bypass-proxy_mips64le
GOOS=linux GOARCH=386 go build -o dpi-bypass-proxy_386 -ldflags "-s -w" && upx dpi-bypass-proxy_386
GOOS=linux GOARCH=ppc64 go build -o dpi-bypass-proxy_ppc64 -ldflags "-s -w" && upx dpi-bypass-proxy_ppc64
GOOS=linux GOARCH=ppc64le go build -o dpi-bypass-proxy_ppc64le -ldflags "-s -w" && upx dpi-bypass-proxy_ppc64le
#GOOS=linux GOARCH=riscv64 go build -o dpi-bypass-proxy_riscv64 -ldflags "-s -w" && upx dpi-bypass-proxy_riscv64
