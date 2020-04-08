package redirect

import (
	"github.com/kr328/tun2socket/binding"
	"github.com/kr328/tun2socket/coder"
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/packet"
	"net"
	"sync"
)

const (
	defaultPacketCache = 64
)

type Redirect struct {
	lock   sync.Mutex
	closed bool

	gateway4 net.IP
	mirror4  net.IP

	inbound  chan []byte
	outbound chan []byte

	provider  buf.BufferProvider
	encoder   *coder.PacketEncoder
	decoder   *coder.PacketDecoder
	tcpMapper *binding.Mapper

	tcp4Port     uint16
	udpReceiver  UDPReceiver
	udpAllocator UDPAllocator
}

func NewRedirect(provider buf.BufferProvider, mtu int, gateway, mirror net.IP) *Redirect {
	return &Redirect{
		gateway4:  gateway,
		mirror4:   mirror,
		inbound:   make(chan []byte, defaultPacketCache),
		outbound:  make(chan []byte, defaultPacketCache),
		provider:  provider,
		encoder:   coder.NewPacketEncoder(mtu, provider),
		decoder:   coder.NewPacketDecoder(mtu, provider),
		tcpMapper: binding.NewMapper(),
	}
}

func (r *Redirect) Exec() {
	for {
		data, ok := <-r.inbound
		if !ok {
			return
		}

		ipPkt, tPkt := r.decoder.Decode(data)
		if ipPkt == nil || tPkt == nil {
			continue
		}

		switch pkt := tPkt.(type) {
		case packet.TCPPacket:
			r.handleTCPPacket(ipPkt, pkt)
		case packet.UDPPacket:
			r.handleUDPPacket(ipPkt, pkt)
		case packet.ICMPPacket:
			r.handleICMPPacket(ipPkt, pkt)
		default:
			r.provider.Recycle(ipPkt.BaseDataBlock())
			continue
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
	r.lock.Lock()
	defer r.lock.Unlock()

	r.closed = true

	close(r.inbound)
	close(r.outbound)
}

func (r *Redirect) FindEndpointByPort(port uint16) *binding.Endpoint {
	bind := r.tcpMapper.GetBindingByPort(port)
	if bind == nil {
		return nil
	}
	return bind.Endpoint
}

func (r *Redirect) Inbound() chan []byte {
	return r.inbound
}

func (r *Redirect) Outbound() chan []byte {
	return r.outbound
}

func (r *Redirect) handleTCPPacket(ipPkt packet.IPPacket, tcpPkt packet.TCPPacket) {
	redirectPort := r.tcp4Port
	if redirectPort <= 0 {
		r.provider.Recycle(ipPkt.BaseDataBlock())
		return
	}

	if ipPkt.TargetAddress().Equal(r.mirror4) {
		if tcpPkt.SourcePort() == redirectPort {
			port := tcpPkt.TargetPort()
			bind := r.tcpMapper.GetBindingByPort(port)
			if bind == nil {
				r.provider.Recycle(ipPkt.BaseDataBlock())
				return
			}

			copy(ipPkt.SourceAddress(), bind.Endpoint.Target.IP)
			copy(ipPkt.TargetAddress(), bind.Endpoint.Source.IP)
			tcpPkt.SetSourcePort(bind.Endpoint.Target.Port)
			tcpPkt.SetTargetPort(bind.Endpoint.Source.Port)
		} else {
			r.provider.Recycle(ipPkt.BaseDataBlock())
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

	data := r.encoder.Encode(ipPkt)

	r.lock.Lock()
	defer r.lock.Unlock()
	if r.closed {
		return
	}

	for _, d := range data {
		select {
		case r.outbound <- d:
			continue
		default:
			r.provider.Recycle(d)
		}
	}
}

func (r *Redirect) handleUDPPacket(ipPkt packet.IPPacket, udpPkt packet.UDPPacket) {
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

	r.provider.Recycle(ipPkt.BaseDataBlock())
}

func (r *Redirect) handleICMPPacket(ipPkt packet.IPPacket, icmpPkt packet.ICMPPacket) {
	if icmpPkt.Type() != packet.ICMPTypePingRequest || icmpPkt.Code() != 0 {
		r.provider.Recycle(ipPkt.BaseDataBlock())
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

	data := r.encoder.Encode(ipPkt)

	r.lock.Lock()
	defer r.lock.Unlock()
	if r.closed {
		return
	}

	for _, d := range data {
		select {
		case r.outbound <- d:
			continue
		default:
			r.provider.Recycle(d)
		}
	}
}

func (r *Redirect) SendUDP(payload []byte, endpoint *binding.Endpoint) error {
	if v4 := endpoint.Source.IP.To4(); v4 != nil {
		endpoint.Source.IP = v4
	}
	if v4 := endpoint.Target.IP.To4(); v4 != nil {
		endpoint.Target.IP = v4
	}

	if len(endpoint.Source.IP) == 4 {
		ipPkt := packet.IPv4Packet(r.provider.Obtain(packet.IPv4PacketMinLength + packet.UdpHeaderSize + len(payload)))

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

		data := r.encoder.Encode(ipPkt)

		r.lock.Lock()
		defer r.lock.Unlock()
		if r.closed {
			return nil
		}

		for _, d := range data {
			select {
			case r.outbound <- d:
				continue
			default:
				r.provider.Recycle(d)
			}
		}
	}

	return nil
}
