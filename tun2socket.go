package tun2socket

import (
	"github.com/kr328/tun2socket/binding"
	L "github.com/kr328/tun2socket/log"
	"github.com/kr328/tun2socket/redirect"
	"net"
	"sync"
)

type TCPHandler func(conn net.Conn, endpoint *binding.Endpoint)
type ClosedHandler func()
type TunDevice redirect.Device

type Tun2Socket struct {
	lock      sync.Mutex
	initialed bool
	closed    bool

	mtu     int
	device  TunDevice
	gateway net.IP
	mirror  net.IP

	packetRedirect *redirect.Redirect
	tcpRedirect    *redirect.TCPRedirect

	closedHandler ClosedHandler
	tcpHandler    TCPHandler
	udpHandler    redirect.UDPReceiver
	allocator     redirect.UDPAllocator

	log L.Logger
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

//noinspection GoUnusedExportedFunction
func NewTun2Socket(device TunDevice, mtu int, gateway net.IP, mirror net.IP) *Tun2Socket {
	return &Tun2Socket{
		mtu:            mtu,
		device:         device,
		gateway:        gateway,
		mirror:         mirror,
		packetRedirect: redirect.NewRedirect(device, mtu, gateway, mirror),
		tcpRedirect:    redirect.NewTCPRedirect(gateway, mirror),
		closedHandler: func() {

		},
		tcpHandler: func(conn net.Conn, endpoint *binding.Endpoint) {
			_ = conn.Close()
		},
		udpHandler: func(payload []byte, endpoint *binding.Endpoint, sender redirect.UDPSender) {
		},
		allocator: func(length int) []byte {
			return make([]byte, length)
		},
		log: &L.DefaultLogger{},
	}
}

func (t *Tun2Socket) Start() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.initialed {
		return
	}

	t.initialed = true

	t.startTCP()
	t.startPacket()
}

func (t *Tun2Socket) Close() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.closed || !t.initialed {
		return
	}

	t.closed = true

	t.packetRedirect.Close()
	t.tcpRedirect.Close()
}

func (t *Tun2Socket) SetLogger(logger L.Logger) {
	if logger == nil {
		t.log = &L.DefaultLogger{}
	} else {
		t.log = logger
	}
}

func (t *Tun2Socket) SetClosedHandler(handler ClosedHandler) {
	t.closedHandler = handler
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

func (t *Tun2Socket) startTCP() {
	go func() {
		defer t.log.I("TCP redirect exited")
		defer t.tcpRedirect.Close()

		port, err := t.tcpRedirect.Listen()
		if err != nil {
			t.log.E("Listen TCP redirect failure", err.Error())
			t.Close()
			return
		}

		t.packetRedirect.ResetTCP(uint16(port))

		t.log.I("Listen TCP redirect %d", port)

		for !t.closed && t.tcpRedirect.IsAlive() {
			conn, addr, err := t.tcpRedirect.Accept()
			if err != nil {
				t.log.W("TCP Redirect receive error: %s", err.Error())
				continue
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
	}()
}

func (t *Tun2Socket) startPacket() {
	go func() {
		t.packetRedirect.Exec()
		t.Close()
		t.log.I("Packet redirect exited")
	}()
}
