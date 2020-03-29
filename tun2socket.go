package tun2socket

import (
	"github.com/kr328/tun2socket/binding"
	"github.com/kr328/tun2socket/redirect"
	"github.com/kr328/tun2socket/tcpip/buf"
	"io"
	"net"
	"sync"
)

type TunDevice = io.ReadWriteCloser
type TCPHandler func(conn net.Conn, endpoint *binding.Endpoint)

type Tun2Socket struct {
	lock      sync.Mutex
	initialed bool
	closed    bool
	provider  buf.BufferProvider

	mtu     int
	device  TunDevice
	gateway net.IP
	mirror  net.IP

	packetRedirect *redirect.Redirect
	tcpRedirect    *redirect.TCPRedirect

	tcpHandler TCPHandler
	udpHandler redirect.UDPReceiver
	allocator  redirect.UDPAllocator
}

type fakeTCPConn struct {
	*net.TCPConn
	endpoint *binding.Endpoint
}

func (t *fakeTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   t.endpoint.Target.IP,
		Port: int(t.endpoint.Target.Port),
		Zone: "",
	}
}

func (t *fakeTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   t.endpoint.Source.IP,
		Port: int(t.endpoint.Source.Port),
		Zone: "",
	}
}

func NewTun2Socket(device TunDevice, mtu int, gateway4 net.IP, mirror4 net.IP) *Tun2Socket {
	p := buf.NewPacketBufferProvider(mtu)

	return &Tun2Socket{
		provider:       p,
		mtu:            mtu,
		device:         device,
		gateway:        gateway4,
		mirror:         mirror4,
		packetRedirect: redirect.NewRedirect(p, mtu, gateway4, mirror4),
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
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.initialed {
		return
	}

	t.initialed = true

	t.startTCPRedirect()
	t.startRedirect()
	t.startReader()
	t.startWriter()
}

func (t *Tun2Socket) Close() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.closed {
		return
	}

	t.closed = true

	_ = t.device.Close()
	t.tcpRedirect.Close()
}

func (t *Tun2Socket) SetTCPHandler(handler TCPHandler) {
	t.tcpHandler = handler
}

func (t *Tun2Socket) SetUDPHandler(handler redirect.UDPReceiver) {
	t.udpHandler = handler

	t.resetUDPHandler()
}

func (t *Tun2Socket) SetAllocator(allocator redirect.UDPAllocator) {
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

func (t *Tun2Socket) startReader() {
	go func() {
		defer t.packetRedirect.Close()

		for {
			buffer := t.provider.Obtain(t.mtu)

			n, err := t.device.Read(buffer)
			if err != nil {
				return
			}

			buffer = buffer[:n]

			select {
			case t.packetRedirect.Inbound() <- buffer:
				continue
			default:
				t.provider.Recycle(buffer)
			}
		}
	}()
}

func (t *Tun2Socket) startWriter() {
	go func() {
		for {
			buffer, ok := <-t.packetRedirect.Outbound()
			if !ok {
				return
			}

			t.lock.Lock()
			if t.closed {
				return
			}
			_, err := t.device.Write(buffer)
			t.lock.Unlock()
			if err != nil {
				return
			}
		}
	}()
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

				fakeConn := &fakeTCPConn{
					TCPConn:  conn,
					endpoint: ep,
				}

				t.tcpHandler(fakeConn, ep)
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
