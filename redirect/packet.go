package redirect

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/kr328/tun2socket/binding"
	"github.com/kr328/tun2socket/tcpip/packet"
)

var (
	ErrUnsupported = errors.New("unsupported")
	ErrTooLarge    = errors.New("too large")
)

const (
	maxPacketCache = 256
)

type Device io.ReadWriteCloser

type Redirect struct {
	device Device
	mtu    int

	gateway4 net.IP
	mirror4  net.IP

	tcpMapper *binding.Mapper

	tcp4Port     uint16
	udpReceiver  UDPReceiver
	udpAllocator UDPAllocator

	pool sync.Pool
}

func NewRedirect(device Device, mtu int, gateway, mirror net.IP) *Redirect {
	return &Redirect{
		device:    device,
		mtu:       mtu,
		gateway4:  gateway,
		mirror4:   mirror,
		tcpMapper: binding.NewMapper(),
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, mtu)
			},
		},
	}
}

func (r *Redirect) Exec() {
	inbound := make(chan []byte, maxPacketCache)
	outbound := make(chan []byte, maxPacketCache)

	defer close(outbound)

	// reader
	go func() {
		defer close(inbound)

		for {
			buffer := r.pool.Get().([]byte)

			n, err := r.device.Read(buffer)
			if err != nil {
				return
			}

			select {
			case inbound <- buffer[:n]:
				break
			default:
				r.pool.Put(buffer[:cap(buffer)])
			}
		}
	}()

	// writer
	go func() {
		for {
			buffer, ok := <-outbound
			if !ok {
				return
			}

			_, _ = r.device.Write(buffer)

			r.pool.Put(buffer[:cap(buffer)])
		}
	}()

	for {
		data, ok := <-inbound
		if !ok {
			return
		}

		ipPkt, tPkt := packet.Decode(data)
		if ipPkt == nil || tPkt == nil {
			data = data[:0]
			continue
		}

		switch pkt := tPkt.(type) {
		case packet.TCPPacket:
			data = r.handleTCPPacket(ipPkt, pkt)
		case packet.UDPPacket:
			data = r.handleUDPPacket(ipPkt, pkt)
		case packet.ICMPPacket:
			data = r.handleICMPPacket(ipPkt, pkt)
		default:
			data = data[:0]
		}

		select {
		case outbound <- data:
			break
		default:
			r.pool.Put(data[:cap(data)])
		}
	}
}

func (r *Redirect) ResetTCP(port4 uint16) {
	r.tcp4Port = port4
	r.tcpMapper.Reset()
}

func (r *Redirect) SetUDPReceiver(allocator UDPAllocator, receiver UDPReceiver) {
	r.udpAllocator = allocator
	r.udpReceiver = receiver
}

func (r *Redirect) Close() {
	_ = r.device.Close()
}

func (r *Redirect) FindEndpointByPort(port uint16) *binding.Endpoint {
	bind := r.tcpMapper.GetBindingByPort(port)
	if bind == nil {
		return nil
	}
	return bind.Endpoint
}

func (r *Redirect) handleTCPPacket(ipPkt packet.IPPacket, tcpPkt packet.TCPPacket) (pkt []byte) {
	pkt = ipPkt.BaseDataBlock()[:0]

	redirectPort := r.tcp4Port
	if redirectPort <= 0 {
		return
	}

	if ipPkt.TargetAddress().Equal(r.mirror4) {
		if tcpPkt.SourcePort() == redirectPort {
			port := tcpPkt.TargetPort()
			bind := r.tcpMapper.GetBindingByPort(port)
			if bind == nil {
				return ipPkt.BaseDataBlock()[:0]
			}

			copy(ipPkt.SourceAddress(), bind.Endpoint.Target.IP)
			copy(ipPkt.TargetAddress(), bind.Endpoint.Source.IP)
			tcpPkt.SetSourcePort(bind.Endpoint.Target.Port)
			tcpPkt.SetTargetPort(bind.Endpoint.Source.Port)
		} else {
			return
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

		bind := r.tcpMapper.GetBindingByEndpoint(ep)
		if bind == nil {
			if tcpPkt.Flags() != packet.TCPSyn {
				return
			}

			bind = r.tcpMapper.PutBinding(&binding.Binding{
				Endpoint: ep,
				Port:     r.tcpMapper.FindFreePort(),
			})
		}

		copy(ipPkt.SourceAddress(), r.mirror4.To4())
		copy(ipPkt.TargetAddress(), r.gateway4.To4())
		tcpPkt.SetSourcePort(bind.Port)
		tcpPkt.SetTargetPort(redirectPort)
	}

	tcpPkt.ResetChecksum(ipPkt.SourceAddress(), ipPkt.TargetAddress())
	if ipPkt.ResetChecksum() != nil {
		return
	}

	return ipPkt.BaseDataBlock()
}

func (r *Redirect) handleUDPPacket(ipPkt packet.IPPacket, udpPkt packet.UDPPacket) (pkt []byte) {
	pkt = ipPkt.BaseDataBlock()[:0]

	alloc := r.udpAllocator
	receive := r.udpReceiver

	if alloc == nil || receive == nil {
		return
	}

	ep := &binding.Endpoint{
		Source: binding.Address{
			IP:   ipPkt.SourceAddress(),
			Port: udpPkt.SourcePort(),
		},
		Target: binding.Address{
			IP:   ipPkt.TargetAddress(),
			Port: udpPkt.TargetPort(),
		},
	}
	ep = ep.Clone()

	payload := alloc(len(udpPkt.Payload()))
	copy(payload, udpPkt.Payload())
	receive(payload, ep, r.SendUDP)

	return
}

func (r *Redirect) handleICMPPacket(ipPkt packet.IPPacket, icmpPkt packet.ICMPPacket) (pkt []byte) {
	pkt = ipPkt.BaseDataBlock()[:0]

	if icmpPkt.Type() != packet.ICMPTypePingRequest || icmpPkt.Code() != 0 {
		return
	}

	s := make(net.IP, len(ipPkt.SourceAddress()))
	t := make(net.IP, len(ipPkt.TargetAddress()))

	copy(s, ipPkt.SourceAddress())
	copy(t, ipPkt.TargetAddress())
	copy(ipPkt.SourceAddress(), t)
	copy(ipPkt.TargetAddress(), s)

	icmpPkt.SetCode(packet.ICMPTypePingResponse)
	icmpPkt.SetType(0)

	icmpPkt.ResetChecksum(ipPkt.SourceAddress(), ipPkt.TargetAddress())
	if ipPkt.ResetChecksum() != nil {
		return
	}

	return ipPkt.BaseDataBlock()
}

func (r *Redirect) SendUDP(payload []byte, endpoint *binding.Endpoint) error {
	if v4 := endpoint.Source.IP.To4(); v4 != nil {
		endpoint.Source.IP = v4
	}
	if v4 := endpoint.Target.IP.To4(); v4 != nil {
		endpoint.Target.IP = v4
	}

	if len(endpoint.Source.IP) == 4 {
		size := packet.IPv4PacketMinLength + packet.UdpHeaderSize + len(payload)

		if size > r.mtu {
			return ErrTooLarge
		}

		data := r.pool.Get().([]byte)[:size]
		defer r.pool.Put(data[:cap(data)])

		ipPkt := packet.IPv4Packet(data)

		packet.SetPacketVersion(ipPkt, packet.IPv4)
		ipPkt.SetHeaderLength(packet.IPv4PacketMinLength)
		ipPkt.SetTypeOfService(0)
		ipPkt.SetPacketLength(uint16(len(ipPkt)))
		ipPkt.SetIdentification(0)
		ipPkt.SetFragmentOffset(0)
		ipPkt.SetTimeToLive(64)
		ipPkt.SetProtocol(packet.UDP)
		copy(ipPkt.SourceAddress(), endpoint.Source.IP)
		copy(ipPkt.TargetAddress(), endpoint.Target.IP)

		udpPkt := packet.UDPPacket(ipPkt.Payload())
		udpPkt.SetSourcePort(endpoint.Source.Port)
		udpPkt.SetTargetPort(endpoint.Target.Port)
		udpPkt.SetLength(uint16(len(payload)) + packet.UdpHeaderSize)
		copy(udpPkt.Payload(), payload)

		udpPkt.ResetChecksum(endpoint.Source.IP, endpoint.Target.IP)
		if err := ipPkt.ResetChecksum(); err != nil {
			return nil
		}

		_, err := r.device.Write(data)
		return err
	}

	return ErrUnsupported
}
