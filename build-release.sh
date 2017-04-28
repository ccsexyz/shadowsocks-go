#!/bin/bash
unamestr=`uname`
UPX=false
#if hash upx 2>/dev/null; then
#	UPX=true
#fi

VERSION=`date -u +%Y%m%d`
LDFLAGS="-X main.VERSION=$VERSION -s -w"
GCFLAGS=""

OSES=(linux darwin windows freebsd)
ARCHS=(amd64 386)
for os in ${OSES[@]}; do
	for arch in ${ARCHS[@]}; do
		suffix=""
        cgo_enabled=0
        env CGO_ENABLED=$cgo_enabled GOOS=$os GOARCH=$arch go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o shadowsocks_${os}_${arch}${suffix} github.com/ccsexyz/shadowsocks-go
		if $UPX; then upx -9 shadowsocks_${os}_${arch}${suffix} ;fi
		tar -zcf shadowsocks-${os}-${arch}-$VERSION.tar.gz shadowsocks_${os}_${arch}${suffix}
	done
done

# ARM
ARMS=(5 6 7)
for v in ${ARMS[@]}; do
	env CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=$v go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o shadowsocks_linux_arm$v  github.com/ccsexyz/shadowsocks-go
done
if $UPX; then upx -9 shadowsocks_linux_arm*;fi
tar -zcf shadowsocks-linux-arm-$VERSION.tar.gz shadowsocks_linux_arm* 

#MIPS32LE
env CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o shadowsocks_linux_mipsle github.com/ccsexyz/shadowsocks-go
env CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o shadowsocks_linux_mips github.com/ccsexyz/shadowsocks-go

if $UPX; then upx -9 shadowsocks_linux_mips* server_linux_mips*;fi
tar -zcf shadowsocks-linux-mipsle-$VERSION.tar.gz shadowsocks_linux_mipsle
tar -zcf shadowsocks-linux-mips-$VERSION.tar.gz shadowsocks_linux_mips
