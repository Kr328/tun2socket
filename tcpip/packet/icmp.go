package packet

import (
	"github.com/kr328/tun2socket/tcpip/sum"
	"net"
)

const (
	ICMPTypePingRequest  byte = 0x8
	ICMPTypePingResponse byte = 0x0
)

type ICMPPacket []byte

func (pkt ICMPPacket) ResetChecksum(net.IP, net.IP) {
	pkt[2] = 0
	pkt[3] = 0

	check := sum.Checksum(0, pkt)

	pkt[2] = check[0]
	pkt[3] = check[1]
}

func (pkt ICMPPacket) Type() byte {
	return pkt[0]
}

func (pkt ICMPPacket) Code() byte {
	return pkt[1]
}

func (pkt ICMPPacket) SetType(t byte) {
	pkt[0] = t
}

func (pkt ICMPPacket) SetCode(code byte) {
	pkt[1] = code
}