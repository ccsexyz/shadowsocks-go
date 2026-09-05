package ss

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

var services sync.Map

func bultinServiceHandler(conn Conn, lis *listener) AcceptResult {
	dst := ""
	if cm := getConnMeta(conn); cm != nil && cm.GetDst() != nil {
		dst = cm.GetDst().String()
	}
	if dst == "" {
		return AcceptResult{AcceptContinue, conn}
	}
	v, ok := services.Load(dst)
	if !ok {
		return AcceptResult{AcceptContinue, conn}
	}
	// The built-in admin service is reachable by any proxy client by simply
	// connecting to admin:6666 through the listener; restrict it to local
	// sources (in-process connections have no TCP/UDP remote address).
	if dst == adminaddr && !isLocalSource(conn) {
		lis.c.Log("reject remote admin service access from", conn.RemoteAddr())
		// The listener's Accept loop only closes connections on AcceptReject;
		// AcceptDrop hands ownership to the handler, and this rejection path
		// returns no handler — so close here or the decrypted connection
		// (FD + buffers) leaks per attempt.
		conn.Close()
		return AcceptResult{AcceptDrop, nil}
	}
	handler := v.(AcceptHandler)
	return handler(conn, lis)
}

func isLocalSource(conn Conn) bool {
	ra := conn.RemoteAddr()
	if ra == nil {
		return true
	}
	switch a := ra.(type) {
	case *net.TCPAddr:
		return a.IP.IsLoopback()
	case *net.UDPAddr:
		return a.IP.IsLoopback()
	default:
		return true
	}
}

// The HTTP admin API mutates these live Config fields under adminWriteMu;
// the virtual admin service must hold the same lock so its writes don't
// race the dial/accept paths that read them (same convention as
// Config.dialPolicy in config.go).
func setDisabledWithLock(c *Config, v bool) {
	adminWriteMu.Lock()
	c.setDisabled(v)
	adminWriteMu.Unlock()
}

func setAutoProxyWithLock(c *Config, v bool) {
	adminWriteMu.Lock()
	c.AutoProxy = v
	adminWriteMu.Unlock()
}

func setLogHTTPWithLock(c *Config, v bool) {
	adminWriteMu.Lock()
	c.LogHTTP = v
	adminWriteMu.Unlock()
}

// StoreServiceHandler stores the handler to services map with key addr
func StoreServiceHandler(addr string, handler AcceptHandler) {
	services.Store(addr, handler)
}

const (
	echoaddr = "echo:10086"

	adminaddr = "admin:6666"
)

func init() {
	StoreServiceHandler(echoaddr, echoHandler)
	StoreServiceHandler(adminaddr, adminHandler)
}

func echoHandler(conn Conn, lis *listener) AcceptResult {
	go func() {
		done := make(chan struct{})
		go func() {
			select {
			case <-lis.die:
				conn.Close()
			case <-done:
			}
		}()
		Pipe(conn, conn, lis.c)
		close(done)
	}()
	return AcceptResult{AcceptDrop, nil}
}

func disableBackend(lis *listener, nickname string) (ok bool) {
	if lis == nil || lis.c == nil || len(nickname) == 0 {
		return
	}
	for _, v := range lis.c.SnapshotBackends() {
		if v.Nickname == nickname {
			setDisabledWithLock(v, true)
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
	for _, v := range lis.c.SnapshotBackends() {
		if v.Nickname == nickname {
			setDisabledWithLock(v, false)
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
	conn.Write(buf[:n], utils.StringToSlice(errstr))
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
	conn.Write(buf[:n], utils.StringToSlice(s))
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

func adminHandler(conn Conn, lis *listener) (result AcceptResult) {
	result = AcceptResult{AcceptDrop, nil}
	defer conn.Close()

	var err error
	defer func() {
		if err != nil {
			sendErrorPage(conn, err)
		}
	}()
	r := bufio.NewReader(AsReader(conn, nil))
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
			setDisabledWithLock(lis.c, false)
		} else if cmd == cmdDisable {
			setDisabledWithLock(lis.c, true)
		} else if cmd == cmdStatus {
			sendStatusPage(conn, lis.c.getStat())
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
			setAutoProxyWithLock(lis.c, false)
		} else if nickname == cmdEnable {
			ok = true
			setAutoProxyWithLock(lis.c, true)
		} else {
			err = errInvalidCommand
		}
	case "loghttp":
		if nickname == cmdDisable {
			ok = true
			setLogHTTPWithLock(lis.c, false)
		} else if nickname == cmdEnable {
			ok = true
			setLogHTTPWithLock(lis.c, true)
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
