package fragment

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/packet"
	"sync/atomic"
)

var identification uint32 = 1

func IPPacketFragment(pkt packet.IPPacket, mtu int, provider buf.BufferProvider) []packet.IPPacket {
	switch pkt := pkt.(type) {
	case packet.IPv4Packet:
		if len(pkt) <= mtu {
			return []packet.IPPacket{pkt}
		}

		payloadSize := mtu - int(pkt.HeaderLength())
		payloadSize = payloadSize - payloadSize%8
		id := atomic.AddUint32(&identification, 1)
		count := calculateFragmentCount(len(pkt.Payload()), payloadSize)
		result := make([]packet.IPPacket, count)

		for i := 0; i < count; i++ {
			packetLength := min(len(pkt.Payload())-i*payloadSize, payloadSize) + int(pkt.HeaderLength())

			p := packet.IPv4Packet(provider.Obtain(packetLength))
			packet.SetPacketVersion(p, packet.IPv4)
			p.SetHeaderLength(pkt.HeaderLength())
			p.SetTypeOfService(pkt.TypeOfService())
			p.SetPacketLength(uint16(packetLength))
			p.SetIdentification(uint16(id))
			p.SetFragmentOffset(uint32(i * payloadSize))
			p.SetTimeToLive(pkt.TimeToLive())
			p.SetProtocol(pkt.Protocol())
			copy(p.Options(), pkt.Options())
			copy(p.SourceAddress(), pkt.SourceAddress())
			copy(p.TargetAddress(), pkt.TargetAddress())
			copy(p.Payload(), pkt.Payload()[i*payloadSize:])

			if i == len(result)-1 {
				p.SetFlags(0)
			} else {
				p.SetFlags(packet.IPv4MoreFragment)
			}

			if err := p.ResetChecksum(); err != nil {
				for _, pkt := range result {
					if pkt != nil {
						provider.Recycle(pkt.BaseDataBlock())
					} else {
						break
					}
				}
				return result[0:0]
			}

			result[i] = p
		}

		provider.Recycle(pkt.BaseDataBlock())

		return result
	}

	return nil
}

func calculateFragmentCount(length, maxSize int) int {
	result := length / maxSize

	if length%maxSize > 0 {
		return result + 1
	}

	return result
}

func min(a, b int) int {
	if a > b {
		return b
	}

	return a
}
