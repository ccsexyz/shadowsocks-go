package redir

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

// copy from https://github.com/riobard/go-shadowsocks2

const (
	SO_ORIGINAL_DST = 80 // from linux/include/uapi/linux/netfilter_ipv4.h
)

// Get the original destination of a TCP connection.
func GetOrigDst(conn net.Conn) (string, error) {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("only work with TCP connection")
	}
	f, err := c.File()
	if err != nil {
		return "", err
	}
	defer f.Close()

	fd := f.Fd()

	// The File() call above puts both the original socket fd and the file fd in blocking mode.
	// Set the file fd back to non-blocking mode and the original socket fd will become non-blocking as well.
	// Otherwise blocking I/O will waste OS threads.
	if err := syscall.SetNonblock(int(fd), true); err != nil {
		return "", err
	}

	return Getorigdst(fd)
}

// Call getorigdst() from linux/net/ipv4/netfilter/nf_conntrack_l3proto_ipv4.c
func Getorigdst(fd uintptr) (string, error) {
	raw := syscall.RawSockaddrInet4{}
	siz := unsafe.Sizeof(raw)
	if err := socketcall(GETSOCKOPT, fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&siz)), 0); err != nil {
		return "", err
	}

	ip := net.IP(raw.Addr[:])
	port := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&raw.Port)))[:]) // big-endian
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}
