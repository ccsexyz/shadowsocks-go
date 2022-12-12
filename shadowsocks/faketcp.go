//go:build faketcp
// +build faketcp

package ss

import (
	"net"

	"github.com/ccsexyz/kcp-go-raw"

	"github.com/ccsexyz/rawcon"
	"github.com/ccsexyz/utils"
)

func listenUDP(c *Config) (net.PacketConn, error) {
	if len(c.FakeTCPAddr) == 0 {
		return utils.NewUDPListener(c.Localaddr)
	}

	return kcpraw.ListenRAW(c.FakeTCPAddr, c.Password, c.UseMul, c.UseUDP, &rawcon.Raw{
		Mixed: true, IgnRST: true,
	})
}

func dialUDP(c *Config) (net.Conn, error) {
	if len(c.FakeTCPAddr) == 0 {
		return net.Dial("udp", c.Remoteaddr)
	}

	return kcpraw.DialRAW(c.FakeTCPAddr, c.Password, c.MulConn, c.UseUDP, &rawcon.Raw{
		Dummy: true, IgnRST: true, NoHTTP: !c.Obfs, Hosts: c.ObfsHost,
	})
}
