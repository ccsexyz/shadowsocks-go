#!/bin/bash
unamestr=`uname`

VERSION=`date -u +%Y%m%d`
LDFLAGS="-s -w"
GCFLAGS=""

OSES=(linux darwin windows freebsd)
ARCHS=(amd64 386)
for os in ${OSES[@]}; do
	for arch in ${ARCHS[@]}; do
		suffix=""
        cgo_enabled=0
        env CGO_ENABLED=$cgo_enabled GOOS=$os GOARCH=$arch go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o shadowsocks_${os}_${arch}${suffix} github.com/ccsexyz/shadowsocks-go
		env CGO_ENABLED=$cgo_enabled GOOS=$os GOARCH=$arch go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags goprof -o shadowsocks_${os}_${arch}${suffix}_pprof github.com/ccsexyz/shadowsocks-go
	done
done

# ARM
ARMS=(5 6 7)
for v in ${ARMS[@]}; do
	env CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=$v go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o shadowsocks_linux_arm$v  github.com/ccsexyz/shadowsocks-go
	env CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=$v go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags goprof -o shadowsocks_linux_arm$v_pprof  github.com/ccsexyz/shadowsocks-go
done

#MIPS32LE
env CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o shadowsocks_linux_mipsle github.com/ccsexyz/shadowsocks-go
env CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags goprof -o shadowsocks_linux_mipsle_pprof github.com/ccsexyz/shadowsocks-go
env CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o shadowsocks_linux_mips github.com/ccsexyz/shadowsocks-go
env CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags goprof -o shadowsocks_linux_mips_pprof github.com/ccsexyz/shadowsocks-go
