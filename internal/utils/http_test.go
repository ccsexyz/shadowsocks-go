package utils

import (
	"bytes"
	"log"
	"testing"
)

var (
	firstHTTPRequest  = []byte("GET / HTTP/1.1\r\n\r\n")
	secondHTTPRequest = []byte("POST /123 HTTP/1.1\r\nContent-Length: 123\r\nOhc-Host: wtf.cn\r\n\r\n")
)

func TestBasicParser(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	p := NewHTTPHeaderParser(nil)
	ok, err := p.Read(firstHTTPRequest)
	if !ok || err != nil {
		t.Error(ok, err)
		t.Fail()
	}
	line, err := p.GetFirstLine()
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if string(line) != "GET / HTTP/1.1" {
		t.Error("bad first line", string(line))
		t.Fail()
	}
	buf := make([]byte, 120)
	n, err := p.Encode(buf)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(buf[:n], firstHTTPRequest) {
		t.Error("incorrect data")
	}
	log.Println(string(buf))
	p.Reset()
	ok, err = p.Read(secondHTTPRequest)
	if !ok || err != nil {
		t.Error(ok, err)
		t.Fail()
	}
	p.Delete([]byte("Content-Length"))
	n, err = p.Encode(buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(buf[:n]))
	_, ok = p.Load([]byte("Transfer-Encoding"))
	if ok {
		t.Fatal("ok is expected to be false")
	}
	p.Store([]byte("Transfer-Encoding"), []byte("chunked"))
	n, err = p.Encode(buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(buf[:n]))
	values, ok := p.Load([]byte("Transfer-Encoding"))
	if !ok {
		t.Fatal("ok is expected to be true")
	}
	if len(values) != 1 {
		t.Fatal("the length of the values should be one")
	}
	log.Println(string(values[0]))
	p.Reset()
}
