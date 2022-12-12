//go:build darwin
// +build darwin

package redir

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

// Get the original destination of a TCP connection.
func GetOrigDst(conn net.Conn) (string, error) {
	return getOrigDstFromAddr(conn.RemoteAddr().String(), conn.LocalAddr().String())
}

// https://opensource.apple.com/source/xnu/xnu-2050.7.9/bsd/net/pfvar.h
type pfNatLoock struct {
	saddr        [16]byte
	daddr        [16]byte
	rsaddr       [16]byte
	rdaddr       [16]byte
	sxport       [4]byte
	dxport       [4]byte
	rsxport      [4]byte
	rdxport      [4]byte
	af           uint8
	proto        uint8
	protoVariant uint8
	direction    uint8
}

// DIOCNATLOOK Look up a state table entry by source and destination addresses and ports.
// https://opensource.apple.com/source/xnu/xnu-2050.7.9/bsd/net/pfvar.h
// #define DIOCNATLOOK	_IOWR('D', 23, struct pfioc_natlook)
// #define	_IOWR(g,n,t)	_IOC(IOC_INOUT,	(g), (n), sizeof(t))
// #define	_IOC(inout,group,num,len) \
// 		(inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num))
// #define	IOCPARM_MASK	0x1fff		/* parameter length, at most 13 bits */
// #define	IOC_INOUT	(IOC_IN|IOC_OUT)
// #define	IOC_IN		(__uint32_t)0x80000000
// #define	IOC_OUT		(__uint32_t)0x40000000
// DIOCNATLOOK = ((0x80000000 | 0x40000000) | ((84 & 0x1fff) << 16) | ((68) << 8) | (23)) = 3226747927
const DIOCNATLOOK = 3226747927

func getOrigDstFromAddr(srcAddr, dstAddr string) (string, error) {
	src, err := net.ResolveUDPAddr("udp", srcAddr)
	if err != nil {
		return "", err
	}
	dst, err := net.ResolveUDPAddr("udp", dstAddr)
	if err != nil {
		return "", err
	}

	nl := new(pfNatLoock)

	nl.af = syscall.AF_INET
	nl.proto = syscall.IPPROTO_TCP
	nl.direction = 3
	copy(nl.saddr[:4], src.IP.To4())
	binary.BigEndian.PutUint16(nl.sxport[:2], uint16(src.Port))
	copy(nl.daddr[:4], dst.IP.To4())
	binary.BigEndian.PutUint16(nl.dxport[:2], uint16(dst.Port))

	pf, err := syscall.Open("/dev/pf", syscall.O_RDONLY, 0666)
	if err != nil {
		return "", err
	}

	// 3226747927
	_, _, errNo := syscall.RawSyscall(syscall.SYS_IOCTL, uintptr(pf), uintptr(3226747927), uintptr(unsafe.Pointer(nl)))
	syscall.Close(pf)

	if errNo != 0 {
		return "", fmt.Errorf("failed to call ioctl: %v", errNo)
	}

	port := int(binary.BigEndian.Uint16(nl.rdxport[:2]))

	return net.JoinHostPort(net.IP(nl.rdaddr[:4]).String(), strconv.Itoa(port)), nil
}
