package ss

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

var services sync.Map

func bultinServiceHandler(conn Conn, lis *listener) (c Conn) {
	var dst string
	if conn.GetDst() != nil {
		dst = conn.GetDst().String()
	}
	if len(dst) == 0 {
		c = conn
		return
	}
	v, ok := services.Load(dst)
	if !ok {
		c = conn
		return
	}
	handler := v.(listenHandler)
	c = handler(conn, lis)
	return
}

// StoreServiceHandler stores the handler to services map with key addr
func StoreServiceHandler(addr string, handler listenHandler) {
	services.Store(addr, handler)
}

const (
	echoaddr = "echo:10086"
	echohost = "echo"
	echoport = 10086

	adminaddr = "admin:6666"
	adminhost = "admin"
	adminport = 6666
)

func init() {
	StoreServiceHandler(echoaddr, echoHandler)
	StoreServiceHandler(adminaddr, adminHandler)
}

func echoHandler(conn Conn, lis *listener) (c Conn) {
	go Pipe(conn, conn, lis.c)
	c = nilConn
	return
}

func disableBackend(lis *listener, nickname string) (ok bool) {
	if lis == nil || lis.c == nil || len(nickname) == 0 {
		return
	}
	for _, v := range lis.c.Backends {
		if v.Nickname == nickname {
			v.disable = true
			ok = true
			return
		}
	}
	return
}

func enableBackend(lis *listener, nickname string) (ok bool) {
	if lis == nil || lis.c == nil || len(nickname) == 0 {
		return
	}
	for _, v := range lis.c.Backends {
		if v.Nickname == nickname {
			v.disable = false
			ok = true
			return
		}
	}
	return
}

var (
	errInvalidCommand = errors.New("invalid command")
)

func sendErrorPage(conn Conn, err error) {
	p := utils.NewHTTPHeaderParser(utils.GetBuf(4096))
	defer utils.PutBuf(p.GetBuf())
	errstr := err.Error() + "\r\n"
	p.StoreFirstline1([]byte("HTTP/1.1"))
	p.StoreFirstline2([]byte("400"))
	p.StoreFirstline3([]byte("Bad Request"))
	p.Store([]byte("Server"), []byte("shadowsocks-go"))
	p.Store([]byte("Content-Length"),
		utils.StringToSlice(strconv.Itoa(len(errstr))))
	p.Store([]byte("Connection"), []byte("close"))
	buf := utils.GetBuf(4096)
	defer utils.PutBuf(buf)
	n, err := p.Encode(buf)
	if err != nil {
		return
	}
	conn.WriteBuffers([][]byte{buf[:n], utils.StringToSlice(errstr)})
}

func sendNormalPage(conn Conn, s string) {
	p := utils.NewHTTPHeaderParser(utils.GetBuf(4096))
	defer utils.PutBuf(p.GetBuf())
	if !strings.HasSuffix(s, "\n") {
		s = s + "\n"
	}
	p.StoreFirstline1([]byte("HTTP/1.1"))
	p.StoreFirstline2([]byte("200"))
	p.StoreFirstline3([]byte("OK"))
	p.Store([]byte("Server"), []byte("shadowsocks-go"))
	p.Store([]byte("Content-Length"),
		utils.StringToSlice(strconv.Itoa(len(s))))
	p.Store([]byte("Connection"), []byte("close"))
	buf := utils.GetBuf(4096)
	defer utils.PutBuf(buf)
	n, err := p.Encode(buf)
	if err != nil {
		return
	}
	conn.WriteBuffers([][]byte{buf[:n], utils.StringToSlice(s)})
}

func sendStatusPage(conn Conn, s *statServer) {
	var str string
	str += fmt.Sprintf("Connections: %v\r\n", s.connections)
	str += fmt.Sprintf("TotalReadBytes: %v\r\n", s.totalReadBytes)
	str += fmt.Sprintf("TotalWritBytes: %v\r\n", s.totalWritBytes)
	sendNormalPage(conn, str)
}

const (
	cmdEnable  = "enable"
	cmdDisable = "disable"
	cmdStatus  = "status"
)

func adminHandler(conn Conn, lis *listener) (c Conn) {
	c = nilConn
	defer conn.Close()

	var err error
	defer func() {
		if err != nil {
			sendErrorPage(conn, err)
		}
	}()
	r := bufio.NewReader(conn)
	_, err = r.ReadString(' ')
	if err != nil {
		lis.c.LogD(err)
		return
	}
	uri, err := r.ReadString(' ')
	if err != nil {
		lis.c.LogD(err)
		return
	}
	uri = strings.TrimSuffix(uri, " ")

	strs := strings.Split(uri, "/")
	if len(strs) > 3 || len(strs) < 2 {
		err = errInvalidCommand
		return
	}
	if len(strs) == 2 {
		cmd := strs[1]
		if cmd == cmdEnable {
			lis.c.disable = false
		} else if cmd == cmdDisable {
			lis.c.disable = true
		} else if cmd == cmdStatus {
			sendStatusPage(conn, lis.c.stat)
			return
		} else {
			err = errInvalidCommand
			return
		}
		sendNormalPage(conn, "successed!")
		return
	}
	cmd := strs[1]
	nickname := strs[2]

	var ok bool
	switch cmd {
	default:
		err = errInvalidCommand
	case cmdEnable:
		ok = enableBackend(lis, nickname)
	case cmdDisable:
		ok = disableBackend(lis, nickname)
	case "autoproxy":
		if nickname == cmdDisable {
			ok = true
			lis.c.AutoProxy = false
		} else if nickname == cmdEnable {
			ok = true
			lis.c.AutoProxy = true
		} else {
			err = errInvalidCommand
		}
	case "loghttp":
		if nickname == cmdDisable {
			ok = true
			lis.c.LogHTTP = false
		} else if nickname == cmdEnable {
			ok = true
			lis.c.LogHTTP = true
		} else {
			err = errInvalidCommand
		}
	}
	if err != nil {
		return
	}
	if ok {
		sendNormalPage(conn, "successed!")
	} else {
		sendNormalPage(conn, "failed!")
	}
	return
}
