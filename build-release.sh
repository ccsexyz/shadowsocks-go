#!/bin/bash
unamestr=`uname`

SHA256='shasum -a 256'
if ! hash shasum 2> /dev/null
then 
	SHA256='sha256sum.exe'
fi

VERSION=`date -u +%Y%m%d`
LDFLAGS="-s -w"
GCFLAGS=""
TAGS="bloom snappy"

OSES=(linux darwin windows freebsd)
ARCHS=(amd64 386)
for os in ${OSES[@]}; do
	for arch in ${ARCHS[@]}; do
		suffix=""
        cgo_enabled=0
        env CGO_ENABLED=$cgo_enabled GOOS=$os GOARCH=$arch go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags "$TAGS" -o shadowsocks_${os}_${arch}${suffix} github.com/ccsexyz/shadowsocks-go
		tar -zcf shadowsocks-${os}-${arch}-$VERSION.tar.gz shadowsocks_${os}_${arch}${suffix}
		$SHA256 shadowsocks-${os}-${arch}-$VERSION.tar.gz
	done
done

# ARM
ARMS=(5 6 7)
for v in ${ARMS[@]}; do
	env CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=$v go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags "$TAGS" -o shadowsocks_linux_arm${v}  github.com/ccsexyz/shadowsocks-go
done
env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags "$TAGS" -o shadowsocks_linux_arm64  github.com/ccsexyz/shadowsocks-go
tar -zcf shadowsocks-linux-arm-$VERSION.tar.gz shadowsocks_linux_arm*
$SHA256 shadowsocks-linux-arm-$VERSION.tar.gz

#MIPS32LE
env CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags "$TAGS" -o shadowsocks_linux_mipsle github.com/ccsexyz/shadowsocks-go
env CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -tags "$TAGS" -o shadowsocks_linux_mips github.com/ccsexyz/shadowsocks-go
tar -zcf shadowsocks-linux-mipsle-$VERSION.tar.gz shadowsocks_linux_mipsle
$SHA256 shadowsocks-linux-mipsle-$VERSION.tar.gz
tar -zcf shadowsocks-linux-mips-$VERSION.tar.gz shadowsocks_linux_mips
$SHA256 shadowsocks-linux-mips-$VERSION.tar.gz
