package endpoint

import "net"

type Address struct {
	IP   net.IP
	Port uint16
}

type Endpoint struct {
	Source Address
	Target Address
}

type Binding struct {
	Endpoint *Endpoint
	Port     uint16
}

type endpointKey struct {
	sourceIP   string
	sourcePort uint16
	targetIP   string
	targetPort uint16
}

func (e *Endpoint) asKey() endpointKey {
	return endpointKey{
		sourceIP:   string(e.Source.IP),
		sourcePort: e.Source.Port,
		targetIP:   string(e.Target.IP),
		targetPort: e.Target.Port,
	}
}

func (e *Endpoint) Clone() *Endpoint {
	newSourceIP := make(net.IP, len(e.Source.IP))
	newTargetIP := make(net.IP, len(e.Target.IP))

	copy(newSourceIP, e.Source.IP)
	copy(newTargetIP, e.Target.IP)

	return &Endpoint{
		Source: Address{
			IP:   newSourceIP,
			Port: e.Source.Port,
		},
		Target: Address{
			IP:   newTargetIP,
			Port: e.Target.Port,
		},
	}
}

func (b *Binding) Clone() *Binding {
	return &Binding{
		Endpoint: b.Endpoint.Clone(),
		Port:     b.Port,
	}
}
