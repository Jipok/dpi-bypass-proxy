#!/usr/bin/env bash

GOOS=linux GOARCH=amd64 go build -o dnsr-amd64 -ldflags "-s -w" && upx dnsr-amd64
GOOS=linux GOARCH=arm go build -o dnsr-arm -ldflags "-s -w" && upx dnsr-arm
GOOS=linux GOARCH=arm64 go build -o dnsr-arm64 -ldflags "-s -w" && upx dnsr-arm64
GOOS=linux GOARCH=mips GOMIPS=softfloat go build -o dnsr-mips -ldflags "-s -w" && upx dnsr-mips
GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o dnsr-mipsle -ldflags "-s -w" && upx dnsr-mipsle
GOOS=linux GOARCH=386 go build -o dnsr-386 -ldflags "-s -w" && upx dnsr-386
GOOS=linux GOARCH=ppc64 go build -o dnsr-ppc64 -ldflags "-s -w" && upx dnsr-ppc64
GOOS=linux GOARCH=ppc64le go build -o dnsr-ppc64le -ldflags "-s -w" && upx dnsr-ppc64le

#GOOS=linux GOARCH=mips64le GOMIPS=softfloat go build -o dnsr-mips64le -ldflags "-s -w" && upx dnsr-mips64le
#GOOS=linux GOARCH=riscv64 go build -o dnsr-riscv64 -ldflags "-s -w" && upx dnsr-riscv64
