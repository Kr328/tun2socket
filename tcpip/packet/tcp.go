package packet

import (
	"encoding/binary"
	"github.com/kr328/tun2socket/tcpip/sum"
	"net"
)

const (
	TCPFin uint16 = 1 << 0
	TCPSyn uint16 = 1 << 1
	TCPRst uint16 = 1 << 2
	TCPPuh uint16 = 1 << 3
	TCPAck uint16 = 1 << 4
	TCPUrg uint16 = 1 << 5
	TCPEce uint16 = 1 << 6
	TCPEwr uint16 = 1 << 7
	TCPNs  uint16 = 1 << 8
)

type TCPPacket []byte

func (pkt TCPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(pkt[0:])
}

func (pkt TCPPacket) TargetPort() uint16 {
	return binary.BigEndian.Uint16(pkt[2:])
}

func (pkt TCPPacket) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(pkt[0:], port)
}

func (pkt TCPPacket) SetTargetPort(port uint16) {
	binary.BigEndian.PutUint16(pkt[2:], port)
}

func (pkt TCPPacket) Flags() uint16 {
	return uint16(pkt[13] | (pkt[12] & 0x1))
}

func (pkt TCPPacket) Verify(sourceAddress net.IP, targetAddress net.IP) error {
	var checksum [2]byte
	checksum[0] = pkt[16]
	checksum[1] = pkt[17]

	// reset checksum
	pkt[16] = 0
	pkt[17] = 0

	// restore checksum
	defer func() {
		pkt[16] = checksum[0]
		pkt[17] = checksum[1]
	}()

	// check checksum
	s := uint32(0)
	s += sum.Sum(sourceAddress)
	s += sum.Sum(targetAddress)
	s += uint32(TCP)
	s += uint32(len(pkt))

	check := sum.Checksum(s, pkt)
	if checksum[0] != check[0] || checksum[1] != check[1] {
		return ErrInvalidChecksum
	}

	return nil
}

func (pkt TCPPacket) ResetChecksum(sourceAddress net.IP, targetAddress net.IP) {
	pkt[16] = 0
	pkt[17] = 0

	s := uint32(0)
	s += sum.Sum(sourceAddress)
	s += sum.Sum(targetAddress)
	s += uint32(TCP)
	s += uint32(len(pkt))

	checksum := sum.Checksum(s, pkt)
	pkt[16] = checksum[0]
	pkt[17] = checksum[1]
}
