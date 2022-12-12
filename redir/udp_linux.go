//go:build linux
// +build linux

package redir

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// EnableUDPTProxy enable tproxy for udp sockets at linux
func EnableUDPTProxy(conn *net.UDPConn) error {
	f, err := conn.File()
	if err != nil {
		return err
	}
	defer f.Close()

	fd := int(f.Fd())
	err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
	if err != nil {
		return err
	}

	return nil
}

// GetOrigDstFromOob get the original destination from oob data
func GetOrigDstFromOob(oob []byte) (*net.UDPAddr, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			origDstRaw := &syscall.RawSockaddrInet4{}
			err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, origDstRaw)
			if err != nil {
				return nil, err
			}

			if origDstRaw.Family != syscall.AF_INET {
				err = fmt.Errorf("the network family is not supported: %v", origDstRaw.Family)
				return nil, err
			}

			p := (*[2]byte)(unsafe.Pointer(&origDstRaw.Port))
			return &net.UDPAddr{
				IP:   origDstRaw.Addr[:],
				Port: int(binary.BigEndian.Uint16((*p)[:])),
			}, nil
		}
	}
	return nil, fmt.Errorf("no avaliable orig deestination")
}
