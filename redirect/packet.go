package redirect

import (
	"github.com/kr328/tun2socket/binding"
	"github.com/kr328/tun2socket/io"
	"github.com/kr328/tun2socket/tcpip/packet"
	"net"
)

type Redirect struct {
	device   io.TunDevice
	gateway4 net.IP
	mirror4  net.IP

	bp        *bufferProvider
	encoder   *io.PacketEncoder
	decoder   *io.PacketDecoder
	tcpMapper *binding.Mapper

	tcp4Port     uint16
	udpReceiver  UDPReceiver
	udpAllocator UDPAllocator
}

func NewRedirect(device io.TunDevice, mtu int, gateway, mirror net.IP) *Redirect {
	bp := newBufferProvider(mtu)

	return &Redirect{
		gateway4:  gateway,
		mirror4:   mirror,
		device:    device,
		bp:        bp,
		encoder:   io.NewPacketEncoder(device, mtu, bp),
		decoder:   io.NewPacketDecoder(device, mtu, bp),
		tcpMapper: binding.NewMapper(),
	}
}

func (r *Redirect) Exec() error {
	for {
		ipPkt, tPkt, err := r.decoder.Decode()
		if err != nil {
			return err
		}

		switch pkt := tPkt.(type) {
		case packet.TCPPacket:
			err = r.handleTCPPacket(ipPkt, pkt)
		case packet.UDPPacket:
			err = r.handleUDPPacket(ipPkt, pkt)
		default:
			r.bp.Recycle(ipPkt.BaseDataBlock())
			continue
		}

		if err != nil {
			return nil
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

func (r *Redirect) handleTCPPacket(ipPkt packet.IPPacket, tcpPkt packet.TCPPacket) error {
	redirectPort := r.tcp4Port
	if redirectPort <= 0 {
		r.bp.Recycle(ipPkt.BaseDataBlock())
		return nil
	}

	if ipPkt.TargetAddress().Equal(r.mirror4) {
		if tcpPkt.SourcePort() == redirectPort {
			port := tcpPkt.TargetPort()
			bind := r.tcpMapper.GetBindingByPort(port)
			if bind == nil {
				r.bp.Recycle(ipPkt.BaseDataBlock())
				return nil
			}

			copy(ipPkt.SourceAddress(), bind.Endpoint.Target.IP)
			copy(ipPkt.TargetAddress(), bind.Endpoint.Source.IP)
			tcpPkt.SetSourcePort(bind.Endpoint.Target.Port)
			tcpPkt.SetTargetPort(bind.Endpoint.Source.Port)
		} else {
			r.bp.Recycle(ipPkt.BaseDataBlock())
			return nil
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
				Port:     r.tcpMapper.GenerateNonUsedPort(),
			})
		}

		copy(ipPkt.SourceAddress(), r.mirror4.To4())
		copy(ipPkt.TargetAddress(), r.gateway4.To4())
		tcpPkt.SetSourcePort(bind.Port)
		tcpPkt.SetTargetPort(redirectPort)
	}

	tcpPkt.ResetChecksum(ipPkt.SourceAddress(), ipPkt.TargetAddress())

	return r.encoder.Encode(ipPkt)
}

func (r *Redirect) handleUDPPacket(ipPkt packet.IPPacket, udpPkt packet.UDPPacket) error {
	alloc := r.udpAllocator
	receive := r.udpReceiver

	if alloc == nil || receive == nil {
		return nil
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
	receive(payload, ep, r.sendUDP)

	r.bp.Recycle(ipPkt.BaseDataBlock())

	return nil
}

func (r *Redirect) sendUDP(payload []byte, endpoint *binding.Endpoint) error {
	if v4 := endpoint.Source.IP.To4(); v4 != nil {
		endpoint.Source.IP = v4
	}
	if v4 := endpoint.Target.IP.To4(); v4 != nil {
		endpoint.Target.IP = v4
	}

	if len(endpoint.Source.IP) == 4 {
		ipPkt := packet.IPv4Packet(r.bp.Obtain(packet.IPv4PacketMinLength + packet.UdpHeaderSize + len(payload)))

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
			return err
		}

		if err := r.encoder.Encode(ipPkt); err != nil {
			return err
		}
	}

	return nil
}
