package io

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/fragment"
	"github.com/kr328/tun2socket/tcpip/packet"
)

type PacketDecoder struct {
	device      TunDevice
	mtu         int
	provider    buf.BufferProvider
	reassembler *fragment.Reassembler
}

func NewPacketDecoder(device TunDevice, mtu int, provider buf.BufferProvider) *PacketDecoder {
	return &PacketDecoder{
		device:      device,
		mtu:         mtu,
		provider:    provider,
		reassembler: fragment.NewReassemble(provider),
	}
}

func (decoder *PacketDecoder) Decode() (packet.IPPacket, packet.TransportPacket, error) {
	for {
		pkt, err := decoder.readNext()
		if err != nil {
			return nil, nil, err
		} else if pkt == nil {
			continue
		}

		pkt, err = decoder.reassembler.InjectPacket(pkt)
		if err != nil {
			if pkt != nil {
				decoder.provider.Recycle(pkt.BaseDataBlock())
			}
			continue
		} else if pkt == nil {
			continue
		}

		switch pkt.Protocol() {
		case packet.TCP:
			tcpPkt := packet.TCPPacket(pkt.Payload())
			if tcpPkt.Verify(pkt.SourceAddress(), pkt.TargetAddress()) != nil {
				decoder.provider.Recycle(pkt.BaseDataBlock())
				break
			}
			return pkt, tcpPkt, nil
		case packet.UDP:
			udpPkt := packet.UDPPacket(pkt.Payload())
			if err := udpPkt.Verify(pkt.SourceAddress(), pkt.TargetAddress()); err != nil {
				decoder.provider.Recycle(pkt.BaseDataBlock())
				break
			}
			return pkt, udpPkt, nil
		case packet.ICMP:
			icmpPkt := packet.ICMPPacket(pkt.Payload())
			if err := icmpPkt.Verify(pkt.SourceAddress(), pkt.TargetAddress()); err != nil {
				decoder.provider.Recycle(pkt.BaseDataBlock())
				break
			}
			return pkt, icmpPkt, nil
		default:
			decoder.provider.Recycle(pkt.BaseDataBlock())
		}
	}
}

func (decoder *PacketDecoder) readNext() (packet.IPPacket, error) {
	buffer := decoder.provider.Obtain(decoder.mtu)

	n, err := decoder.device.Read(buffer)
	if err != nil {
		return nil, err
	}

	data := buffer[:n]

	switch packet.DetectPacketVersion(data) {
	case packet.IPv4:
		return packet.IPv4Packet(data), nil
	default:
		decoder.provider.Recycle(buffer)
		return nil, nil
	}
}
