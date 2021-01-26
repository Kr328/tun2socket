package packet

import (
	"encoding/binary"
	"net"

	"github.com/kr328/tun2socket/tcpip/sum"
)

const (
	UdpHeaderSize = 8
)

type UDPPacket []byte

func (pkt UDPPacket) Verify(sourceAddress net.IP, targetAddress net.IP) error {
	if pkt.Length() < uint16(len(pkt)) {
		return ErrInvalidLength
	}

	if pkt[6] != 0 || pkt[7] != 0 {
		var checksum [2]byte
		checksum[0] = pkt[6]
		checksum[1] = pkt[7]

		pkt[6] = 0
		pkt[7] = 0

		defer func() {
			pkt[6] = checksum[0]
			pkt[7] = checksum[1]
		}()

		s := uint32(0)
		s += sum.Sum(sourceAddress)
		s += sum.Sum(targetAddress)
		s += uint32(UDP)
		s += uint32(len(pkt))

		check := sum.Checksum(s, pkt)
		if check[0] != checksum[0] || check[1] != checksum[1] {
			return ErrInvalidChecksum
		}
	}

	return nil
}

func (pkt UDPPacket) ResetChecksum(sourceAddress net.IP, targetAddress net.IP) {
	pkt[6] = 0
	pkt[7] = 0

	s := uint32(0)
	s += sum.Sum(sourceAddress)
	s += sum.Sum(targetAddress)
	s += uint32(UDP)
	s += uint32(len(pkt))

	checksum := sum.Checksum(s, pkt)

	pkt[6] = checksum[0]
	pkt[7] = checksum[1]
}

func (pkt UDPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(pkt[0:])
}

func (pkt UDPPacket) TargetPort() uint16 {
	return binary.BigEndian.Uint16(pkt[2:])
}

func (pkt UDPPacket) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(pkt[0:], port)
}

func (pkt UDPPacket) SetTargetPort(port uint16) {
	binary.BigEndian.PutUint16(pkt[2:], port)
}

func (pkt UDPPacket) Length() uint16 {
	return binary.BigEndian.Uint16(pkt[4:])
}

func (pkt UDPPacket) SetLength(length uint16) {
	binary.BigEndian.PutUint16(pkt[4:], length)
}

func (pkt UDPPacket) Payload() []byte {
	return pkt[UdpHeaderSize:pkt.Length()]
}
