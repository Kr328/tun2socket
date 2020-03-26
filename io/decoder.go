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
		buffer := decoder.provider.Obtain(decoder.mtu)

		n, err := decoder.device.Read(buffer)
		if err != nil {
			return nil, nil, err
		}

		data := buffer[:n]

		switch packet.DetectPacketVersion(data) {
		case packet.IPv4:
			rawPkt := packet.IPv4Packet(data)
			if err := rawPkt.Verify(); err != nil {
				decoder.provider.Recycle(buffer)
				break
			}

			ipPkt, err := decoder.reassembler.InjectPacket(rawPkt)
			if err != nil {
				decoder.provider.Recycle(buffer)
				break
			} else if ipPkt == nil {
				break
			}

			switch rawPkt.Protocol() {
			case packet.TCP:
				tcpPkt := packet.TCPPacket(ipPkt.Payload())
				if tcpPkt.Verify(ipPkt.SourceAddress(), ipPkt.TargetAddress()) != nil {
					decoder.provider.Recycle(buffer)
					break
				}
				return ipPkt, tcpPkt, nil
			default:
				decoder.provider.Recycle(buffer)
			}
		default:
			decoder.provider.Recycle(buffer)
		}
	}
}
