package utils

import (
	cr "crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSliceConnMultipleWriter(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	mtu := 400
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Error(err)
		return
	}
	defer udpConn.Close()
	uaddr := udpConn.LocalAddr().(*net.UDPAddr)
	listener, err := ListenSubUDPWithConnAndCtx(udpConn, &UDPServerCtx{Mtu: mtu})
	if err != nil {
		t.Error(err)
		return
	}
	defer listener.Close()
	rnum := 0
	wnum := 0
	rlock := new(sync.Mutex)
	wlock := new(sync.Mutex)
	worker := func() {
		conn, err := net.DialUDP("udp", nil, uaddr)
		if err != nil {
			t.Error(err)
			return
		}
		if err != nil {
			log.Fatal(err)
			return
		}
		sconn := NewSliceConn(conn, mtu)
		defer sconn.Close()
		buf := make([]byte, 65536)
		for it := 0; it < 1000; it++ {
			n := rand.Intn(60000) + 6
			binary.BigEndian.PutUint16(buf, uint16(n))
			io.ReadFull(cr.Reader, buf[6:n])
			chksum := crc32.ChecksumIEEE(buf[6:n])
			binary.BigEndian.PutUint32(buf[2:6], chksum)
			nw, err := sconn.Write(buf[:n])
			if err != nil {
				t.Error(err)
				return
			}
			if nw != n {
				t.Error(io.ErrShortWrite)
				return
			}
			wlock.Lock()
			wnum++
			wlock.Unlock()
			time.Sleep(time.Millisecond * 1)
		}
	}
	var wg sync.WaitGroup
	for it := 0; it < 1; it++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker()
		}()
	}
	go func() {
		defer listener.Close()
		wg.Wait()
		time.Sleep(time.Second * 4)
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			rlock.Lock()
			wlock.Lock()
			if rnum != wnum {
				t.Error(fmt.Sprintln("rnum != wnum", rnum, "!=", wnum))
			}
			wlock.Unlock()
			rlock.Unlock()
			return
		}
		go func(conn net.Conn) {
			sconn := NewSliceConn(conn, mtu)
			defer sconn.Close()
			buf := make([]byte, 65536)
			for {
				n, err := sconn.Read(buf)
				if err != nil {
					return
				}
				pktlen := binary.BigEndian.Uint16(buf[:2])
				if int(pktlen) != n || n < 6 {
					t.Error(fmt.Sprintln("incorrect length", pktlen, "!=", n))
				}
				chksum := binary.BigEndian.Uint32(buf[2:6])
				if chksum != crc32.ChecksumIEEE(buf[6:n]) {
					t.Error("incorrect checksum")
				}
				rlock.Lock()
				rnum++
				rlock.Unlock()
			}
		}(conn)
	}
}
