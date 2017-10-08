// +build snappy

package ss

import "github.com/golang/snappy"

type SnappyConn struct {
	Conn
	w *snappy.Writer
	r *snappy.Reader
}

func NewSnappyConn(conn Conn) *SnappyConn {
	return &SnappyConn{
		Conn: conn,
		w:    snappy.NewBufferedWriter(conn),
		r:    snappy.NewReader(conn),
	}
}

func (c *SnappyConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *SnappyConn) Write(b []byte) (n int, err error) {
	n, err = c.w.Write(b)
	if err == nil {
		err = c.w.Flush()
	}
	return n, err
}

func (c *SnappyConn) WriteBuffers(b [][]byte) (n int, err error) {
	var n2 int
	for _, v := range b {
		n2, err = c.Write(v)
		if err != nil {
			return
		}
		n += n2
	}
	return
}
