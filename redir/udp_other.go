// +build !linux

package redir

import (
	"errors"
	"net"
)

// EnableUDPTProxy is only avaliable at linux
func EnableUDPTProxy(conn *net.UDPConn) error {
	return errors.New("this function is only avaliable at linux")
}

// GetOrigDstFromOob is only avaliable at linux
func GetOrigDstFromOob(oob []byte) (*net.UDPAddr, error) {
	return nil, errors.New("this function is only avaliable at linux")
}
