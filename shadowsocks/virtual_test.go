package ss

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// --- unit tests for virtual registry ---

func TestRegisterVirtual(t *testing.T) {
	ln, err := RegisterVirtual("@test1", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@test1")

	if ln.Addr().String() != "@test1" {
		t.Errorf("expected addr '@test1', got '%s'", ln.Addr().String())
	}
}

func TestVirtualDuplicateRegister(t *testing.T) {
	ln, err := RegisterVirtual("@dup", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@dup")

	_, err = RegisterVirtual("@dup", "")
	if err == nil {
		t.Error("expected error on duplicate register")
	}
	ln.Close()
}

func TestVirtualDialNonexistent(t *testing.T) {
	_, err := DialVirtual("@noexist")
	if err == nil {
		t.Error("expected error dialing nonexistent service")
	}
}

func TestVirtualAcceptAndDial(t *testing.T) {
	ln, err := RegisterVirtual("@echo", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@echo")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("Accept failed: %v", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	client, err := DialVirtual("@echo")
	if err != nil {
		t.Fatalf("DialVirtual failed: %v", err)
	}
	defer client.Close()

	client.Write([]byte("ping"))
	resp := make([]byte, 4)
	io.ReadFull(client, resp)
	if string(resp) != "ping" {
		t.Errorf("expected 'ping', got '%s'", string(resp))
	}
	wg.Wait()
}

func TestVirtualMultipleDials(t *testing.T) {
	ln, err := RegisterVirtual("@multi", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@multi")

	const numClients = 5
	var wg sync.WaitGroup

	for i := range numClients {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := DialVirtual("@multi")
			if err != nil {
				t.Errorf("client %d: DialVirtual failed: %v", id, err)
				return
			}
			defer c.Close()
			msg := []byte{byte(id)}
			c.Write(msg)
		}(i)
	}

	seen := make(map[byte]bool)
	for range numClients {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept failed: %v", err)
		}
		buf := make([]byte, 1)
		io.ReadFull(conn, buf)
		seen[buf[0]] = true
		conn.Close()
	}
	wg.Wait()

	if len(seen) != numClients {
		t.Errorf("expected %d unique connections, got %d", numClients, len(seen))
	}
}

func TestVirtualAcceptUnblocksOnClose(t *testing.T) {
	ln, err := RegisterVirtual("@unblock", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}

	done := make(chan error)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	ln.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error from Accept after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock after Close")
	}

	UnregisterVirtual("@unblock")
}

func TestVirtualDialAfterClose(t *testing.T) {
	ln, err := RegisterVirtual("@closed", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	ln.Close()
	UnregisterVirtual("@closed")

	_, err = DialVirtual("@closed")
	if err == nil {
		t.Error("expected error dialing closed service")
	}
}

func TestRegisterVirtualForce(t *testing.T) {
	ln1, err := RegisterVirtual("@force", "first")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}

	// Accept a connection on the old listener to fill its queue
	go func() {
		c, _ := DialVirtual("@force")
		if c != nil {
			c.Close()
		}
	}()
	conn, _ := ln1.Accept()
	if conn != nil {
		conn.Close()
	}

	// Force-replace: closes old listener, installs new one
	ln2 := RegisterVirtualForce("@force", "second")

	// Old listener should be closed
	_, err = ln1.Accept()
	if err == nil {
		t.Error("old listener should be closed after force replace")
	}

	// New listener should work
	go func() {
		c, _ := DialVirtual("@force")
		if c != nil {
			c.Close()
		}
	}()
	conn2, err := ln2.Accept()
	if err != nil {
		t.Fatalf("new listener Accept failed: %v", err)
	}
	conn2.Close()

	UnregisterVirtual("@force")
}

func TestListVirtualServices(t *testing.T) {
	_, err := RegisterVirtual("@list1", "src1")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@list1")
	_, err = RegisterVirtual("@list2", "src2")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@list2")

	list := ListVirtualServices()
	if len(list) < 2 {
		t.Errorf("expected at least 2 services, got %d", len(list))
	}

	found := make(map[string]string)
	for _, s := range list {
		found[s.Name] = s.Source
	}
	if found["@list1"] != "src1" {
		t.Errorf("@list1 source: expected 'src1', got '%s'", found["@list1"])
	}
	if found["@list2"] != "src2" {
		t.Errorf("@list2 source: expected 'src2', got '%s'", found["@list2"])
	}
}

func TestListVirtualServicesAcceptCount(t *testing.T) {
	ln, err := RegisterVirtual("@acceptcnt", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@acceptcnt")

	const numConns = 3
	for i := 0; i < numConns; i++ {
		c, _ := DialVirtual("@acceptcnt")
		if c == nil {
			t.Fatal("DialVirtual returned nil")
		}
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
		c.Close()
	}

	list := ListVirtualServices()
	for _, s := range list {
		if s.Name == "@acceptcnt" {
			if s.AcceptCount != int64(numConns) {
				t.Errorf("expected AcceptCount %d, got %d", numConns, s.AcceptCount)
			}
			return
		}
	}
	t.Error("virtual service @acceptcnt not found in listing")
}

func TestRegisterVirtualForceDrainsActiveConnections(t *testing.T) {
	ln1, err := RegisterVirtual("@force-drain", "old")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@force-drain")

	// Dial into old listener so it has pending connections in the channel.
	// We dial 2 connections but only accept 1, leaving 1 in the channel.
	c1, err := DialVirtual("@force-drain")
	if err != nil {
		t.Fatalf("DialVirtual failed: %v", err)
	}
	c2, err := DialVirtual("@force-drain")
	if err != nil {
		t.Fatalf("DialVirtual failed: %v", err)
	}

	// Accept only c1
	conn1, _ := ln1.Accept()
	if conn1 != nil {
		conn1.Close()
	}
	c1.Close()

	// Force-replace: old listener closes, c2 should be drained (closed).
	ln2 := RegisterVirtualForce("@force-drain", "new")

	// Verify old listener is closed
	_, err = ln1.Accept()
	if err == nil {
		t.Error("old listener should be closed after force replace")
	}

	// c2 should have been drained (closed by drainVirtualListener)
	// Try reading from c2 — should get an error
	buf := make([]byte, 1)
	_, err = c2.Read(buf)
	if err == nil {
		t.Error("drained connection should be closed")
	}
	c2.Close()

	// New listener should work
	c3, err := DialVirtual("@force-drain")
	if err != nil {
		t.Fatalf("DialVirtual on new listener failed: %v", err)
	}
	defer c3.Close()
	conn3, err := ln2.Accept()
	if err != nil {
		t.Fatalf("new listener Accept failed: %v", err)
	}
	defer conn3.Close()
}

func TestDialVirtualChannelFull(t *testing.T) {
	ln, err := RegisterVirtual("@fullchan", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	defer UnregisterVirtual("@fullchan")

	// Fill the channel to capacity (32). Don't accept any.
	const capacity = 32
	conns := make([]net.Conn, 0, capacity)
	for i := 0; i < capacity; i++ {
		c, err := DialVirtual("@fullchan")
		if err != nil {
			t.Fatalf("dial %d failed: %v", i, err)
		}
		conns = append(conns, c)
	}

	// Next dial should block since channel is full and no one is accepting.
	// Use a goroutine with timeout.
	errCh := make(chan error, 1)
	go func() {
		c, err := DialVirtual("@fullchan")
		if err != nil {
			errCh <- err
			return
		}
		c.Close()
		errCh <- nil
	}()

	// After 100ms, accept one connection to unblock the pending dial.
	time.Sleep(100 * time.Millisecond)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	conn.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("blocked dial should succeed after accept, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("dial should not block forever when channel is full")
	}

	for _, c := range conns {
		c.Close()
	}
}

func TestUnregisterVirtualRemovesService(t *testing.T) {
	_, err := RegisterVirtual("@unreg", "")
	if err != nil {
		t.Fatalf("RegisterVirtual failed: %v", err)
	}
	UnregisterVirtual("@unreg")

	_, err = DialVirtual("@unreg")
	if err == nil {
		t.Error("expected error dialing unregistered service")
	}

	// Listing should not include it
	for _, s := range ListVirtualServices() {
		if s.Name == "@unreg" {
			t.Error("unregistered service should not appear in listing")
		}
	}
}
