package rawcon

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"reflect"
	"testing"
	"time"
)

const (
	laddr = "127.0.0.1:6666"
)

func TestSingleEcho(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)

	raw := &Raw{
		Mixed:  true,
		NoHTTP: false,
		IgnRST: true,
		Dummy:  true,
		Hosts: []string{
			"www.baidu.com",
			"www.google.com",
		},
	}

	listener, err := raw.ListenRAW(laddr)
	if err != nil {
		t.Error(err)
		return
	}
	defer listener.Close()

	go func() {
		defer listener.Close()
		buf := make([]byte, 2048)
		for {
			n, addr, err := listener.ReadFrom(buf)
			if err != nil {
				log.Println(err)
				return
			}
			listener.WriteTo(buf[:n], addr)
		}
	}()

	conn, err := raw.DialRAW(laddr)
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	rbuf := make([]byte, 1024)
	for i := 0; i < 100; i++ {
		binary.Read(rand.Reader, binary.BigEndian, buf)
		n, err := conn.Write(buf)
		if n != len(buf) {
			t.Error(fmt.Errorf("short write! n = %d", n))
			return
		}
		if err != nil {
			t.Error(err)
			return
		}
		n, err = conn.Read(rbuf)
		if n != len(buf) {
			t.Error(fmt.Errorf("unexpected n = %d", n))
			return
		}
		if err != nil {
			t.Error(err)
			return
		}
		if reflect.DeepEqual(buf, rbuf) == false {
			t.Error("broken data")
			log.Println(buf)
			log.Println(rbuf)
			return
		}
	}
	return
}

func TestMultiEcho(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)

	raw := &Raw{
		Mixed:  true,
		NoHTTP: false,
		IgnRST: true,
		Dummy:  true,
		Hosts: []string{
			"www.baidu.com",
			"www.google.com",
		},
	}

	die := make(chan bool)
	defer close(die)
	errch := make(chan error)

	listener, err := raw.ListenRAW(laddr)
	if err != nil {
		t.Error(err)
		return
	}
	defer listener.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := listener.ReadFrom(buf)
			if err != nil {
				log.Println(err)
				return
			}
			listener.WriteTo(buf[:n], addr)
		}
	}()

	f := func() {
		conn, err := raw.DialRAW(laddr)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		go func() {
			select {
			case <-die:
				conn.Close()
			}
		}()

		buf := make([]byte, 1024)
		rbuf := make([]byte, 1024)
		for i := 0; i < 10; i++ {
			binary.Read(rand.Reader, binary.BigEndian, buf)
			n, err := conn.Write(buf)
			if n != len(buf) {
				errch <- fmt.Errorf("short write! n = %d", n)
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			n, err = conn.Read(rbuf)
			if n != len(buf) {
				errch <- fmt.Errorf("unexpected n = %d", n)
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			if reflect.DeepEqual(buf, rbuf) == false {
				errch <- fmt.Errorf("broken data")
				log.Println(buf)
				log.Println(rbuf)
				return
			}
		}
	}

	for i := 0; i < 100; i++ {
		go f()
	}

	timer := time.NewTimer(time.Second * 5)
	select {
	case <-timer.C:
	case err = <-errch:
		log.Println(err)
	}
	return
}
