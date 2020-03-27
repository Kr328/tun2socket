package tun2socket

import (
	"github.com/kr328/tun2socket/binding"
	"github.com/kr328/tun2socket/io"
	"github.com/kr328/tun2socket/redirect"
	"net"
	"sync"
)

const (
	udpPacketBufferSize = 65535
)

type TCPHandler func(conn net.Conn, endpoint *binding.Endpoint)
type Allocator = redirect.UDPAllocator
type UDPHandler = redirect.UDPReceiver
type UDPWriter = redirect.UDPSender
type TunDevice = io.TunDevice

type Tun2Socket struct {
	initial sync.Once
	stop    sync.Once
	closed  bool

	gateway net.IP
	mirror  net.IP

	packetRedirect *redirect.Redirect
	tcpRedirect    *redirect.TCPRedirect

	tcpHandler TCPHandler
	udpHandler UDPHandler
	allocator  Allocator
}

func NewTun2Socket(device TunDevice, mtu int, gateway4 net.IP, mirror4 net.IP) *Tun2Socket {
	return &Tun2Socket{
		gateway:        gateway4,
		mirror:         mirror4,
		packetRedirect: redirect.NewRedirect(device, mtu, gateway4, mirror4),
		tcpRedirect:    redirect.NewTCPRedirect(gateway4, mirror4),
		tcpHandler: func(conn net.Conn, endpoint *binding.Endpoint) {
			_ = conn.Close()
		},
		udpHandler: func(payload []byte, endpoint *binding.Endpoint, sender redirect.UDPSender) {
		},
		allocator: func(length int) []byte {
			return make([]byte, length)
		},
	}
}

func (t *Tun2Socket) Start() {
	t.initial.Do(func() {
		t.startTCPRedirect()
		t.startRedirect()
	})
}

func (t *Tun2Socket) Close() {
	t.stop.Do(func() {
		t.closed = true

		t.tcpRedirect.Close()
		t.packetRedirect.Close()
	})
}

func (t *Tun2Socket) SetTCPHandler(handler TCPHandler) {
	t.tcpHandler = handler
}

func (t *Tun2Socket) SetUDPHandler(handler UDPHandler) {
	t.udpHandler = handler

	t.resetUDPHandler()
}

func (t *Tun2Socket) SetAllocator(allocator Allocator) {
	t.allocator = allocator

	t.resetUDPHandler()
}

func (t *Tun2Socket) resetUDPHandler() {
	h := t.udpHandler
	a := t.allocator

	if h == nil {
		t.packetRedirect.SetUDPReceiver(nil, nil)
		return
	}
	if a == nil {
		a = func(length int) []byte {
			return make([]byte, length)
		}
	}
	t.packetRedirect.SetUDPReceiver(a, h)
}

func (t *Tun2Socket) startTCPRedirect() {
	go func() {
		for !t.closed {
			port, err := t.tcpRedirect.Listen()
			if err != nil {
				t.Close()
				return
			}

			t.packetRedirect.ResetTCP(uint16(port))

			for {
				conn, addr, err := t.tcpRedirect.Accept()
				if err != nil {
					break
				}

				if !addr.IP.Equal(t.mirror) {
					_ = conn.Close()
					continue
				}

				ep := t.packetRedirect.FindEndpointByPort(uint16(addr.Port))
				if ep == nil {
					_ = conn.Close()
					continue
				}

				t.tcpHandler(conn, ep)
			}
		}
	}()
}

func (t *Tun2Socket) startRedirect() {
	go func() {
		if err := t.packetRedirect.Exec(); err != nil {
			t.Close()
			return
		}
	}()
}
