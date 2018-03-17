package ss

import (
	"log"

	"github.com/ccsexyz/utils"
)

// ReadFull acts the same as io.ReadFull
func ReadFull(c Conn, b []byte) error {
	off := 0
	for off < len(b) {
		b2, err := c.ReadBuffer(b[off:])
		if err != nil {
			return err
		}
		off += copy(b[off:], b2)
	}
	return nil
}

func WriteBuffer(c Conn, b []byte) error {
	return c.WriteBuffers([][]byte{b})
}

func WriteString(c Conn, str string) error {
	return WriteBuffer(c, utils.StringToSlice(str))
}

func PipeWithBuffer(c1, c2 Conn, b1, b2 []byte) {
	c1die := make(chan struct{})
	c2die := make(chan struct{})

	defer c1.Close()
	defer c2.Close()

	f := func(dst, src Conn, b []byte, die chan struct{}) {
		defer close(die)
		for {
			b2w, err := src.ReadBuffer(b)
			if len(b2w) > 0 {
				err2 := WriteBuffer(dst, b2w)
				if err2 != nil {
					log.Println(dst.RemoteAddr(), err2)
					return
				}
			}
			if err != nil {
				log.Println(src.RemoteAddr(), err)
				return
			}
		}
	}

	go f(c1, c2, b1, c1die)
	go f(c2, c1, b2, c2die)

	select {
	case <-c1die:
	case <-c2die:
	}
}

func Pipe(c1, c2 Conn) {
	b1 := utils.GetBuf(bufferSize)
	defer utils.PutBuf(b1)
	b2 := utils.GetBuf(bufferSize)
	defer utils.PutBuf(b2)
	PipeWithBuffer(c1, c2, b1, b2)
}
