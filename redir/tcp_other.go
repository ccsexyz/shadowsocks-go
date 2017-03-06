// +build !linux

package redir

import "github.com/shadowsocks/go-shadowsocks2/core"

// copy from https://github.com/riobard/go-shadowsocks2

func redirLocal(addr, server string, ciph core.StreamConnCipher) {
	//logf("TCP redirect not supported")
}

func redir6Local(addr, server string, ciph core.StreamConnCipher) {
	//logf("TCP6 redirect not supported")
}
