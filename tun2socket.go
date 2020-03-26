package tun2socket

import (
	"github.com/kr328/tun2socket/binding"
	"github.com/kr328/tun2socket/io"
	"github.com/kr328/tun2socket/tcpip/packet"
	"net"
	"sync"
	"time"
)

const (
	udpPacketBufferSize = 65535
)

type Allocator func(length int) []byte
type TCPConnectionHandler func(conn net.Conn, endpoint *binding.Endpoint)
type UDPPacketHandler func(payload []byte, endpoint *binding.Endpoint)

type Tun2Socket struct {
	initial sync.Once
	stop    sync.Once
	closed  bool

	bp      *bufferProvider
	device  io.TunDevice
	mtu     int
	gateway net.IP
	mirror  net.IP

	tcpMapper *binding.Mapper
	udpMapper *binding.Mapper

	tcpListener *net.TCPListener
	udpConn     *net.UDPConn
	tcpPort     uint16
	udpPort     uint16

	tcpHandler TCPConnectionHandler
	udpHandler UDPPacketHandler
	allocator  Allocator
}

type bufferProvider struct {
	mtu          int
	fragmentPool sync.Pool
	mergedPool   sync.Pool
}

func NewTun2Socket(device io.TunDevice, mtu int, gateway net.IP, mirror net.IP) *Tun2Socket {
	return &Tun2Socket{
		bp:        newBufferProvider(mtu),
		device:    device,
		mtu:       mtu,
		gateway:   gateway,
		mirror:    mirror,
		tcpMapper: binding.NewMapper(),
		udpMapper: binding.NewMapper(),
		tcpHandler: func(conn net.Conn, endpoint *binding.Endpoint) {
			_ = conn.Close()
		},
		udpHandler: func(payload []byte, endpoint *binding.Endpoint) {
		},
		allocator: func(length int) []byte {
			return make([]byte, length)
		},
	}
}

func (t *Tun2Socket) Start() {
	t.initial.Do(func() {
		t.startTCPListener()
	})
}

func (t *Tun2Socket) Stop() {
	t.stop.Do(func() {
		t.closed = true

		if t := t.tcpListener; t != nil {
			_ = t.Close()
		}

		if u := t.udpConn; u != nil {
			_ = u.Close()
		}

		_ = t.device.SetDeadline(time.Unix(1, 0))
	})
}

func (t *Tun2Socket) startTCPListener() {
	go func() {
		for !t.closed {
			tcpAddr := &net.TCPAddr{
				IP:   t.gateway,
				Port: 0,
				Zone: "",
			}
			tcp, err := net.ListenTCP("tcp", tcpAddr)
			if err != nil {
				t.Stop()
				return
			}
			tcpAddr = tcp.Addr().(*net.TCPAddr)

			t.tcpPort = uint16(tcpAddr.Port)
			t.tcpListener = tcp

			for {
				conn, err := tcp.Accept()
				if err != nil {
					_ = tcp.Close()
					break
				}

				rAddr := conn.RemoteAddr().(*net.TCPAddr)
				bind := t.tcpMapper.GetBindingByPort(uint16(rAddr.Port))
				if bind == nil {
					_ = conn.Close()
					continue
				}

				t.tcpHandler(conn, bind.Endpoint)
			}
		}
	}()
}

func (t *Tun2Socket) startUDPConn() {
	go func() {
		for !t.closed {
			udpAddr := &net.UDPAddr{
				IP:   t.gateway,
				Port: 0,
				Zone: "",
			}
			udp, err := net.ListenUDP("udp", udpAddr)
			if err != nil {
				t.Stop()
				return
			}
			udpAddr = udp.LocalAddr().(*net.UDPAddr)

			t.udpPort = uint16(udpAddr.Port)
			t.udpConn = udp

			for {
				buf := t.allocator(udpPacketBufferSize)
				n, addr, err := udp.ReadFrom(buf)
				if err != nil {
					_ = udp.Close()
					break
				}

				rAddr := addr.(*net.UDPAddr)
				bind := t.udpMapper.GetBindingByPort(uint16(rAddr.Port))
				if bind == nil {
					continue
				}

				t.udpHandler(buf[:n], bind.Endpoint)
			}
		}
	}()
}

func (t *Tun2Socket) startRedirect() {
	go func() {
		decoder := io.NewPacketDecoder(t.device, t.mtu, t.bp)
		encoder := io.NewPacketEncoder(t.device, t.mtu, t.bp)

		for !t.closed {
			ipPkt, tPkt, err := decoder.Decode()
			if err != nil {
				t.Stop()
				return
			}

			switch pkt := tPkt.(type) {
			case *packet.TCPPacket:
				t.handleTCPPacket(ipPkt, pkt)
			}

			if encoder.Encode(ipPkt) != nil {
				t.Stop()
			}
		}
	}()
}

func (t *Tun2Socket) handleTCPPacket(ipPkt packet.IPPacket, tcpPkt *packet.TCPPacket) {
	ep := &binding.Endpoint{
		Source: binding.Address{
			IP:   ipPkt.SourceAddress(),
			Port: tcpPkt.SourcePort(),
		},
		Target: binding.Address{
			IP:   ipPkt.TargetAddress(),
			Port: tcpPkt.TargetPort(),
		},
	}

	bind := t.tcpMapper.GetBindingByEndpoint(ep)
	if bind == nil {
		bind = t.tcpMapper.PutBinding(&binding.Binding{
			Endpoint: ep,
			Port:     t.tcpMapper.GenerateNonUsedPort(),
		})
	}

	copy(ipPkt.SourceAddress(), t.mirror)
	copy(ipPkt.TargetAddress(), t.gateway)
	tcpPkt.SetSourcePort(bind.Port)
	tcpPkt.SetTargetPort(t.tcpPort)

	tcpPkt.ResetChecksum(ipPkt.SourceAddress(), ipPkt.TargetAddress())
}

func newBufferProvider(mtu int) *bufferProvider {
	return &bufferProvider{
		mtu: mtu,
		fragmentPool: sync.Pool{New: func() interface{} {
			return make([]byte, mtu)
		}},
		mergedPool: sync.Pool{New: func() interface{} {
			return make([]byte, 65535)
		}},
	}
}

func (b *bufferProvider) Obtain(length int) []byte {
	if length <= b.mtu {
		return b.fragmentPool.Get().([]byte)[:length]
	} else if length <= 65535 {
		return b.mergedPool.Get().([]byte)[:length]
	} else {
		return make([]byte, length)
	}
}

func (b *bufferProvider) Recycle(buffer []byte) {
	buffer = buffer[:cap(buffer)]
	if len(buffer) == b.mtu {
		b.fragmentPool.Put(buffer)
	} else if len(buffer) == 65535 {
		b.mergedPool.Put(buffer)
	}
}
