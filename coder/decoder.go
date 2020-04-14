package coder

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/fragment"
	"github.com/kr328/tun2socket/tcpip/packet"
)

type PacketDecoder struct {
	mtu         int
	provider    buf.BufferProvider
	reassembler *fragment.Reassembler
}

func NewPacketDecoder(mtu int, provider buf.BufferProvider) *PacketDecoder {
	return &PacketDecoder{
		mtu:         mtu,
		provider:    provider,
		reassembler: fragment.NewReassemble(provider),
	}
}

func (decoder *PacketDecoder) Decode(data []byte) (packet.IPPacket, packet.TransportPacket) {
	var pkt packet.IPPacket

	switch packet.DetectPacketVersion(data) {
	case packet.IPv4:
		pkt = packet.IPv4Packet(data)
	default:
		decoder.provider.Recycle(data)
		return nil, nil
	}

	if err := pkt.Verify(); err != nil {
		decoder.provider.Recycle(pkt.BaseDataBlock())
		return nil, nil
	}

	pkt, err := decoder.reassembler.InjectPacket(pkt)
	if err != nil {
		if pkt != nil {
			decoder.provider.Recycle(pkt.BaseDataBlock())
		}
	}
	if pkt == nil {
		return nil, nil
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
		return nil, nil
	}

	//if err := tPkt.Verify(pkt.SourceAddress(), pkt.TargetAddress()); err != nil {
	//	decoder.provider.Recycle(pkt.BaseDataBlock())
	//	return nil, nil
	//}

	return pkt, tPkt
}
