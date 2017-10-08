// +build !snappy

package ss

type SnappyConn struct {
	Conn
}

func NewSnappyConn(conn Conn) *SnappyConn {
	return &SnappyConn{Conn: conn}
}
