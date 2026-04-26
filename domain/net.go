package domain

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"time"
)

func IsTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

func CheckConn(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(time.Microsecond))
	var buf [1]byte
	_, err := conn.Read(buf[:])
	conn.SetReadDeadline(time.Time{})
	if err == nil {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

func SplitHostAndPort(hostport string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return
	}
	port, err = strconv.Atoi(portStr)
	return
}
