package nat

import (
	"encoding/binary"
	"net"
	"syscall"
)

type TCP struct {
	net.Listener

	table *table
}

type conn struct {
	net.Conn

	tuple tuple
}

func (t *TCP) Accept() (net.Conn, error) {
	c, err := t.Listener.Accept()
	if err != nil {
		return nil, err
	}

	addr := c.RemoteAddr().(*net.TCPAddr)
	tup := t.table.tupleOf(uint16(addr.Port))
	if tup == zeroTuple {
		_ = c.Close()

		return nil, net.InvalidAddrError("unknown remote addr")
	}

	sys, err := c.(*net.TCPConn).SyscallConn()
	if err == nil {
		_ = sys.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_NO_CHECK, 1)
		})
	}

	return &conn{
		Conn:  c,
		tuple: tup,
	}, nil
}

func (c *conn) LocalAddr() net.Addr {
	ip := make(net.IP, 4)

	binary.LittleEndian.PutUint32(ip, c.tuple.SourceIP)

	return &net.TCPAddr{
		IP:   ip,
		Port: int(c.tuple.SourcePort),
	}
}

func (c *conn) RemoteAddr() net.Addr {
	ip := make(net.IP, 4)

	binary.LittleEndian.PutUint32(ip, c.tuple.DestinationIP)

	return &net.TCPAddr{
		IP:   ip,
		Port: int(c.tuple.DestinationPort),
	}
}
