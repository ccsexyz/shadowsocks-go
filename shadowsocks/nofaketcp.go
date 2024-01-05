//go:build !faketcp
// +build !faketcp

package ss

import (
	"net"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

func listenUDP(c *Config) (net.PacketConn, error) {
	return utils.NewUDPListener(c.Localaddr)
}

func dialUDP(c *Config) (net.Conn, error) {
	return net.Dial("udp", c.Remoteaddr)
}
