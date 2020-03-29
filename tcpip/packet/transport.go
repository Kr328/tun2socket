package packet

import "net"

type TransportPacket interface {
	ResetChecksum(sourceAddress net.IP, targetAddress net.IP)
}
