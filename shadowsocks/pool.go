package ss

import (
	"fmt"
	"sync"
)

type ConnPool struct {
	cond    sync.Cond
	conns   []Conn
	destroy bool
}

func NewConnPool() *ConnPool {
	return &ConnPool{cond: sync.Cond{L: &sync.Mutex{}}}
}

func (p *ConnPool) GetNonblock() (conn Conn, err error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	if p.destroy {
		err = fmt.Errorf("cannot get connection from a closed pool")
	} else {
		for err == nil {
			if len(p.conns) == 0 {
				err = fmt.Errorf("no available connection")
			} else {
				conn = p.conns[0]
				p.conns = p.conns[1:]
				if CheckConn(conn) {
					break
				}
				conn.Close()
				conn = nil
			}
		}
	}
	return
}

func (p *ConnPool) Get() (conn Conn, err error) {
	p.cond.L.Lock()
	if p.destroy {
		err = fmt.Errorf("cannot get connection from a closed pool")
		p.cond.L.Unlock()
		return
	}
	if len(p.conns) != 0 {
		conn = p.conns[0]
		p.conns = p.conns[1:]
	}
	p.cond.L.Unlock()
	if conn == nil {
		p.cond.L.Lock()
		for len(p.conns) == 0 {
			p.cond.Wait()
			if p.destroy {
				p.cond.L.Unlock()
				err = fmt.Errorf("cannot get connection from a closed pool")
				return
			}
		}
		conn = p.conns[0]
		p.conns = p.conns[1:]
		p.cond.L.Unlock()
	}
	if !CheckConn(conn) {
		conn.Close()
		conn, err = p.Get()
	}
	return
}

func (p *ConnPool) Put(conn Conn) (err error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	if p.destroy {
		err = fmt.Errorf("cannot put into a closed connection pool")
	} else if !CheckConn(conn) {
		err = fmt.Errorf("cannot put a closed connetion")
	} else {
		p.conns = append(p.conns, conn)
		p.cond.Signal()
	}
	return
}

func (p *ConnPool) Close() (err error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	p.destroy = true
	p.cond.Broadcast()
	return
}
