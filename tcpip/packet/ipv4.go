package packet

import (
	"encoding/binary"
	"github.com/kr328/tun2socket/tcpip/sum"
	"net"
)

const (
	IPv4OptionsOffset   = 20
	IPv4PacketMinLength = IPv4OptionsOffset

	IPv4DontFragment = 1 << 1
	IPv4MoreFragment = 1
)

type IPv4Packet []byte

func (pkt IPv4Packet) BaseDataBlock() []byte {
	return pkt
}

func (pkt IPv4Packet) Protocol() Protocol {
	return Protocol(pkt[9])
}

func (pkt IPv4Packet) Verify() error {
	if len(pkt) < IPv4PacketMinLength {
		return ErrInvalidLength
	}

	checksum := []byte{pkt[10], pkt[11]}
	headerLength := uint16(pkt[0]&0xF) * 4
	packetLength := binary.BigEndian.Uint16(pkt[2:])

	if pkt[0]>>4 != 4 {
		return ErrInvalidIPVersion
	}

	if uint16(len(pkt)) < packetLength || packetLength < headerLength {
		return ErrInvalidLength
	}

	pkt[10] = 0
	pkt[11] = 0
	defer copy(pkt[10:12], checksum)

	answer := sum.Checksum(0, pkt[:headerLength])

	if answer[0] != checksum[0] || answer[1] != checksum[1] {
		return ErrInvalidChecksum
	}

	return nil
}

func (pkt IPv4Packet) SourceAddress() net.IP {
	return net.IP(pkt[12:16])
}

func (pkt IPv4Packet) TargetAddress() net.IP {
	return net.IP(pkt[16:20])
}

func (pkt IPv4Packet) Payload() []byte {
	return pkt[pkt.HeaderLength():pkt.PacketLength()]
}

func (pkt IPv4Packet) ResetChecksum() error {
	if len(pkt) < IPv4PacketMinLength {
		return ErrInvalidLength
	}

	headerLength := uint16(pkt[0]&0xF) * 4
	packetLength := binary.BigEndian.Uint16(pkt[2:])

	if pkt[0]>>4 != 4 {
		return ErrInvalidIPVersion
	}

	if uint16(len(pkt)) < packetLength || packetLength < headerLength {
		return ErrInvalidLength
	}

	pkt[10] = 0
	pkt[11] = 0

	answer := sum.Checksum(0, pkt[:headerLength])
	copy(pkt[10:12], answer[:])

	return nil
}

func (pkt IPv4Packet) HeaderLength() uint16 {
	return uint16(pkt[0]&0xF) * 4
}

func (pkt IPv4Packet) SetHeaderLength(length uint16) {
	pkt[0] &= 0xF0
	pkt[0] |= byte(length / 4)
}

func (pkt IPv4Packet) TypeOfService() byte {
	return pkt[1]
}

func (pkt IPv4Packet) SetTypeOfService(tos byte) {
	pkt[1] = tos
}

func (pkt IPv4Packet) PacketLength() uint16 {
	return binary.BigEndian.Uint16(pkt[2:])
}

func (pkt IPv4Packet) SetPacketLength(length uint16) {
	binary.BigEndian.PutUint16(pkt[2:], length)
}

func (pkt IPv4Packet) Identification() uint16 {
	return binary.BigEndian.Uint16(pkt[4:])
}

func (pkt IPv4Packet) SetIdentification(id uint16) {
	binary.BigEndian.PutUint16(pkt[4:], id)
}

func (pkt IPv4Packet) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16([]byte{pkt[6] & 0x7, pkt[7]}) * 8
}

func (pkt IPv4Packet) SetFragmentOffset(offset uint32) {
	flags := pkt.Flags()
	binary.BigEndian.PutUint16(pkt[6:], uint16(offset/8))
	pkt.SetFlags(flags)
}

func (pkt IPv4Packet) Flags() uint8 {
	return pkt[6] >> 5
}

func (pkt IPv4Packet) SetFlags(flags byte) {
	pkt[6] &= 0xE0
	pkt[6] |= flags << 5
}

func (pkt IPv4Packet) TimeToLive() byte {
	return pkt[8]
}

func (pkt IPv4Packet) SetTimeToLive(ttl byte) {
	pkt[8] = ttl
}

func (pkt IPv4Packet) SetProtocol(protocol Protocol) {
	pkt[9] = byte(protocol)
}

func (pkt IPv4Packet) Options() []byte {
	return pkt[IPv4PacketMinLength:pkt.HeaderLength()]
}
