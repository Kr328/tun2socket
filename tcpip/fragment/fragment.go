package fragment

import (
	CRand "crypto/rand"
	"encoding/binary"
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/packet"
	"math/rand"
)

func IPPacketFragment(pkt packet.IPPacket, mtu int, provider buf.BufferProvider) []packet.IPPacket {
	switch pkt := pkt.(type) {
	case packet.IPv4Packet:
		maxPayloadSize := mtu - int(pkt.HeaderLength())
		maxPayloadSize = maxPayloadSize - maxPayloadSize%8
		fragmentCount := calFragmentCount(len(pkt.Payload()), maxPayloadSize)
		fragments := make([]packet.IPPacket, fragmentCount)
		identification := generateIdentification()

		for i := 0; i < fragmentCount; i++ {
			packetLength := min(len(pkt.Payload())-i*maxPayloadSize, maxPayloadSize) + int(pkt.HeaderLength())

			p := packet.IPv4Packet(provider.Obtain(packetLength))
			packet.SetPacketVersion(p, packet.IPv4)
			p.SetHeaderLength(pkt.HeaderLength())
			p.SetTypeOfService(pkt.TypeOfService())
			p.SetPacketLength(uint16(packetLength))
			p.SetIdentification(identification)
			p.SetFragmentOffset(uint32(i * maxPayloadSize))
			p.SetTimeToLive(pkt.TimeToLive())
			p.SetProtocol(pkt.Protocol())
			copy(p.Options(), pkt.Options())
			copy(p.SourceAddress(), pkt.SourceAddress())
			copy(p.TargetAddress(), pkt.TargetAddress())
			copy(p.Payload(), pkt.Payload()[i*maxPayloadSize:])

			if i == len(fragments) - 1 {
				p.SetFlags(0)
			} else {
				p.SetFlags(packet.IPv4MoreFragment)
			}

			if err := p.ResetChecksum(); err != nil {
				for _, pkt := range fragments {
					if pkt != nil {
						provider.Recycle(pkt.(packet.IPv4Packet))
					} else {
						break
					}
				}
				return nil
			}

			fragments[i] = p
		}

		return fragments
	}

	return nil
}

func generateIdentification() uint16 {
	var data [2]byte

	n, err := CRand.Read(data[:])
	if err != nil || n != 2 {
		return uint16(rand.Uint32())
	}

	return binary.BigEndian.Uint16(data[:])
}

func calFragmentCount(length, maxSize int) int {
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
