package packet

import "net"

type TransportPacket interface {
	SourcePort() int
	TargetPort() int
	SetSourcePort(port uint16)
	SetTargetPort(port uint16)
	Verify(sourceAddress net.IP, targetAddress net.IP) error
	ResetChecksum(sourceAddress net.IP, targetAddress net.IP)
}
