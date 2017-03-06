// +build !linux

package redir

import (
	"fmt"
	"net"
)

func GetOrigDst(conn net.Conn) (string, error) {
	return "", fmt.Errorf("this function is only avaliable at linux")
}
