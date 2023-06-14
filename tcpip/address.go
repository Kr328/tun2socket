package tcpip

import (
	"encoding/binary"
	"net/netip"
)

func BroadcastAddr(network netip.Prefix) netip.Addr {
	bytes := network.Masked().Addr().As4()

	bits := binary.BigEndian.Uint32(bytes[:])
	for i := network.Bits() + 1; i < 32; i++ {
		bits |= 1 << (31 - i)
	}
	binary.BigEndian.PutUint32(bytes[:], bits)

	return netip.AddrFrom4(bytes)
}
