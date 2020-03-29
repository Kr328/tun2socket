package packet

import (
	"encoding/binary"
	"github.com/kr328/tun2socket/tcpip/sum"
	"net"
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
