package main

import (
	"sync"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type bultinServiceAcceptor struct {
	services sync.Map
}

func newBultinServiceAcceptor() *bultinServiceAcceptor {
	return &bultinServiceAcceptor{}
}

func (b *bultinServiceAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	v, ok := ctx.Get(ss.CtxTarget)
	if !ok {
		return conn, nil
	}
	dst := v.(ss.DstAddr)
	v, ok = b.services.Load(dst.String())
	if !ok {
		return conn, nil
	}
	acc := v.(Acceptor)
	acc.Accept(conn, ctx)
	return nil, nil
}

func (b *bultinServiceAcceptor) StoreServiceAcceptor(addr string, acc Acceptor) {
	b.services.Store(addr, acc)
}

const (
	echoaddr = "echo:10086"
)

type echoAcceptor struct{}

func (e *echoAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	ss.Pipe(conn, conn)
	return nil, nil
}
