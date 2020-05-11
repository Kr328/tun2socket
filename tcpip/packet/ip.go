package packet

import (
	"errors"
	"net"
)

const (
	IPPacketMaxLength = 65535
)

type Version byte
type Protocol byte

type IPPacket interface {
	BaseDataBlock() []byte
	SourceAddress() net.IP
	TargetAddress() net.IP
	Protocol() Protocol
	Verify() error
	Payload() []byte
}

const (
	IPv4 Version = 4
	IPv6 Version = 6
)

const (
	ICMP Protocol = 0x01
	TCP  Protocol = 0x06
	UDP  Protocol = 0x11
)

var (
	ErrInvalidLength    = errors.New("invalid packet length")
	ErrInvalidIPVersion = errors.New("invalid ip version")
	ErrInvalidChecksum  = errors.New("invalid checksum")
)

func DetectPacketVersion(b []byte) Version {
	if len(b) < 1 {
		return 0
	}

	return Version(b[0] >> 4)
}

func SetPacketVersion(b []byte, version Version) {
	b[0] &= 0xF
	b[0] |= byte(version << 4)
}
