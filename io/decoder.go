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

		var tPkt packet.TransportPacket
		switch pkt.Protocol() {
		case packet.TCP:
			tPkt = packet.TCPPacket(pkt.Payload())
		case packet.UDP:
			tPkt = packet.UDPPacket(pkt.Payload())
		case packet.ICMP:
			tPkt = packet.ICMPPacket(pkt.Payload())
		default:
			decoder.provider.Recycle(pkt.BaseDataBlock())
			continue
		}

		return pkt, tPkt, nil
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
