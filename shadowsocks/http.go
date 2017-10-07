package ss

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/ccsexyz/utils"
)

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

const (
	simpleObfsFormat = "HTTP/1.1 101 Switching Protocols\r\n" +
		"Server: nginx/1.9.7\r\n" +
		"Date: %s\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: %s\r\n" +
		"\r\n"
	requestFormat = "POST /%s HTTP/1.1\r\n" +
		"Accept: */*\r\n" +
		"Accept-Encoding: */*\r\n" +
		"Accept-Language: zh-CN\r\n" +
		"Connection: keep-alive\r\n" +
		"%s" +
		"Transfer-Encoding: chunked\r\n\r\n"
	responseFromat = "HTTP/1.1 200 OK\r\n" +
		"Cache-Control: private, no-store, max-age=0, no-cache\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Server: openresty/1.11.2\r\n" +
		"Connection: keep-alive\r\n" +
		"%s" +
		"Transfer-Encoding: chunked\r\n\r\n"
)

func buildHTTPRequest(headers string) string {
	return fmt.Sprintf(requestFormat, randStringBytesMaskImprSrc(rand.Intn(48)+1), headers)
}

func buildHTTPResponse(headers string) string {
	return fmt.Sprintf(responseFromat, headers)
}

func buildSimpleObfsResponse() string {
	key := make([]byte, 16)
	utils.PutRandomBytes(key)
	b64key := base64.StdEncoding.EncodeToString(key)
	datetime := strings.Replace(time.Now().UTC().Format(time.RFC1123), "UTC", "GMT", 1)
	return fmt.Sprintf(simpleObfsFormat, datetime, b64key)
}
