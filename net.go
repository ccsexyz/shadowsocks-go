package main

import (
	"encoding/binary"
	"net"
	"strconv"
)

type listener struct {
	net.TCPListener
	info *ssinfo
}

func (lis *listener) Accept() (conn net.Conn, err error) {
	conn, err = lis.TCPListener.Accept()
	if err != nil {
		return
	}
	conn = NewConn(conn, lis.info)
	return
}

// ListenTCP return a net.Listener
func Listen(address string, info *ssinfo) (lis net.Listener, err error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	lis = &listener{
		TCPListener: *l,
		info:        info,
	}
	return
}

func Dial(target, service string, info *ssinfo) (conn net.Conn, err error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return
	}
	hostLen := len(host)
	headerLen := hostLen + 4
	conn, err = net.Dial("tcp", service)
	if err != nil {
		return
	}
	conn = NewConn(conn, info)
	buf := conn.(*Conn).rbuf[:headerLen]
	buf[0] = typeDm
	buf[1] = byte(hostLen)
	copy(buf[2:], []byte(host))
	binary.BigEndian.PutUint16(buf[hostLen+2:], uint16(portNum))
	_, err = conn.Write(buf)
	if err != nil {
		conn.Close()
	}
	return
}

func DialWithRawHeader(header []byte, service string, info *ssinfo) (conn net.Conn, err error) {
	conn, err = net.Dial("tcp", service)
	if err != nil {
		return
	}
	conn = NewConn(conn, info)
	_, err = conn.Write(header)
	if err != nil {
		conn.Close()
	}
	return
}
