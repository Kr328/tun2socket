package packet

import "net"

type TransportPacket interface {
	Verify(sourceAddress net.IP, targetAddress net.IP) error
	ResetChecksum(sourceAddress net.IP, targetAddress net.IP)
}
