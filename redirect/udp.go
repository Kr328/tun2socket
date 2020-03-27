package redirect

import (
	"github.com/kr328/tun2socket/binding"
)

type UDPAllocator func(length int) []byte
type UDPSender func(payload []byte, endpoint *binding.Endpoint) error
type UDPReceiver func(payload []byte, endpoint *binding.Endpoint, sender UDPSender)
