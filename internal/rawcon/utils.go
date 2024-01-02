package rawcon

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
)

type Raw struct {
	Mixed  bool
	NoHTTP bool
	TLS    bool
	Host   string
	DSCP   int
	IgnRST bool
	Hosts  []string
	Dummy  bool
}

type callback func()

type myMutex struct {
	sync.Mutex
}

func (m *myMutex) run(f callback) {
	m.Lock()
	defer m.Unlock()
	f()
}

// copy from stackoverflow

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randStringBytesMaskImprSrc(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

var requestFormat string
var responseFromat string

func init() {
	var requestBuffer bytes.Buffer
	strs := []string{
		"POST /%s HTTP/1.1\r\n",
		"Accept: */*\r\n",
		"Accept-Encoding: */*\r\n",
		"Accept-Language: zh-CN\r\n",
		"Connection: keep-alive\r\n",
		"%s",
		"Content-Length:%d\r\n\r\n",
	}
	for _, str := range strs {
		requestBuffer.WriteString(str)
	}
	requestFormat = requestBuffer.String()
	var responseBuffer bytes.Buffer
	strs = []string{
		"HTTP/1.1 200 OK\r\n",
		"Cache-Control: private, no-store, max-age=0, no-cache\r\n",
		"Content-Type: text/html; charset=utf-8\r\n",
		"Content-Encoding: gzip\r\n",
		"Server: openresty/1.11.2\r\n",
		"Connection: keep-alive\r\n",
		"%s",
		"Content-Length: %d\r\n\r\n",
	}
	for _, str := range strs {
		responseBuffer.WriteString(str)
	}
	responseFromat = responseBuffer.String()
}

func buildHTTPRequest(headers string) string {
	return fmt.Sprintf(requestFormat, randStringBytesMaskImprSrc(10), headers, (rand.Int63()%65536 + 10485760))
	// return fmt.Sprintf(requestFormat, randStringBytesMaskImprSrc(10), headers, 0)
}

func buildHTTPResponse(headers string) string {
	return fmt.Sprintf(responseFromat, headers, (rand.Int63()%65536 + 104857600))
	// return fmt.Sprintf(responseFromat, headers, 0)
}

func fatalErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type timeoutErr struct {
	op string
}

func (t *timeoutErr) Error() string {
	return t.op + " timeout"
}

func (t *timeoutErr) Temporary() bool {
	return true
}

func (t *timeoutErr) Timeout() bool {
	return true
}

const (
	synreceived = 0
	waithttpreq = 1
	httprepsent = 2
	established = 3
)

func getSrcIPForDstIP(dstip net.IP) (srcip net.IP, err error) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: dstip, Port: 80})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

var (
	ipv4AddrAny = net.IPv4(0, 0, 0, 0)
)
