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
type TCPHandler func(conn net.Conn, endpoint *binding.Endpoint)
type UDPHandler func(payload []byte, endpoint *binding.Endpoint)
type TunDevice = io.TunDevice

type Tun2Socket struct {
	initial sync.Once
	stop    sync.Once
	closed  bool

	bp      *bufferProvider
	device  TunDevice
	mtu     int
	gateway net.IP
	mirror  net.IP

	tcpMapper *binding.Mapper
	udpMapper *binding.Mapper

	tcpListener *net.TCPListener
	udpConn     *net.UDPConn
	tcpPort     uint16
	udpPort     uint16

	tcpHandler TCPHandler
	udpHandler UDPHandler
	allocator  Allocator
}

type bufferProvider struct {
	mtu          int
	fragmentPool sync.Pool
	mergedPool   sync.Pool
}

func NewTun2Socket(device TunDevice, mtu int, gateway4 net.IP, mirror4 net.IP) *Tun2Socket {
	return &Tun2Socket{
		bp:        newBufferProvider(mtu),
		device:    device,
		mtu:       mtu,
		gateway:   gateway4.To4(),
		mirror:    mirror4.To4(),
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
		t.startUDPConn()
		t.startRedirect()
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

func (t *Tun2Socket) SetTCPHandler(handler TCPHandler) {
	t.tcpHandler = handler
}

func (t *Tun2Socket) SetUDPHandler(handler UDPHandler) {
	t.udpHandler = handler
}

func (t *Tun2Socket) SetAllocator(allocator Allocator) {
	t.allocator = allocator
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

			t.udpMapper.Reset()
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

			t.udpMapper.Reset()
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

			if tPkt.Verify(ipPkt.SourceAddress(), ipPkt.TargetAddress()) != nil {
				t.bp.Recycle(ipPkt.BaseDataBlock())
				continue
			}

			writeBack := false
			switch pkt := tPkt.(type) {
			case packet.TCPPacket:
				writeBack = t.handleTCPPacket(ipPkt, pkt)
			default:
				continue
			}

			if writeBack {
				if encoder.Encode(ipPkt) != nil {
					t.Stop()
				}
			} else {
				t.bp.Recycle(ipPkt.BaseDataBlock())
			}
		}
	}()
}

func (t *Tun2Socket) handleTCPPacket(ipPkt packet.IPPacket, tcpPkt packet.TCPPacket) bool {
	if ipPkt.TargetAddress().Equal(t.mirror) {
		if tcpPkt.SourcePort() == t.tcpPort {
			port := tcpPkt.TargetPort()
			bind := t.tcpMapper.GetBindingByPort(port)
			if bind == nil {
				return false
			}

			copy(ipPkt.SourceAddress(), bind.Endpoint.Target.IP)
			copy(ipPkt.TargetAddress(), bind.Endpoint.Source.IP)
			tcpPkt.SetSourcePort(bind.Endpoint.Target.Port)
			tcpPkt.SetTargetPort(bind.Endpoint.Source.Port)
		} else {
			return false
		}
	} else {
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

		copy(ipPkt.SourceAddress(), t.mirror.To4())
		copy(ipPkt.TargetAddress(), t.gateway.To4())
		tcpPkt.SetSourcePort(bind.Port)
		tcpPkt.SetTargetPort(t.tcpPort)
	}

	tcpPkt.ResetChecksum(ipPkt.SourceAddress(), ipPkt.TargetAddress())

	return true
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
