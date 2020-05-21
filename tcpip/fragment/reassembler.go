package fragment

import (
	"container/heap"
	"errors"
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/packet"
	"time"
)

var (
	ErrReassembleBlocked = errors.New("reassemble blocked")
)

const (
	defaultIPFragmentTimeout   = time.Second * 120
	defaultIPFragmentQueueSize = 32
	maxReassemblingPacket      = 1024
)

type packetHeap []packet.IPPacket

type packetTracker struct {
	ttl        time.Time
	queue      packetHeap
	merged     packet.IPPacket
	nextOffset uint16
}

type Reassembler struct {
	trackers map[uint16]*packetTracker
	provider buf.BufferProvider
}

func NewReassembler(provider buf.BufferProvider) *Reassembler {
	return &Reassembler{
		trackers: map[uint16]*packetTracker{},
		provider: provider,
	}
}

func (r *Reassembler) InjectPacket(pkt packet.IPPacket) (packet.IPPacket, error) {
	switch pkt := pkt.(type) {
	case packet.IPv4Packet:
		return r.injectIPv4Packet(pkt)
	}
	return nil, nil
}

func (r *Reassembler) injectIPv4Packet(pkt packet.IPv4Packet) (packet.IPPacket, error) {
	if pkt.Flags()&packet.IPv4MoreFragment == 0 && pkt.FragmentOffset() == 0 {
		return pkt, nil
	}

	r.clearExpiredTackers()

	if pkt.Flags()&packet.IPv4DontFragment != 0 {
		return nil, ErrReassembleBlocked
	}

	t := r.trackers[pkt.Identification()]
	if t == nil {
		if len(r.trackers) > maxReassemblingPacket {
			return nil, ErrReassembleBlocked
		}

		t = &packetTracker{
			ttl:    time.Time{},
			queue:  make([]packet.IPPacket, 0, defaultIPFragmentQueueSize),
			merged: packet.IPv4Packet(r.provider.Obtain(packet.IPPacketMaxLength)),
		}

		r.trackers[pkt.Identification()] = t

		heap.Init(&t.queue)

		m := t.merged.(packet.IPv4Packet)

		packet.SetPacketVersion(m, packet.IPv4)
		m.SetPacketLength(packet.IPPacketMaxLength)
		m.SetHeaderLength(pkt.HeaderLength())
		m.SetTypeOfService(pkt.TypeOfService())
		m.SetIdentification(pkt.Identification())
		m.SetFragmentOffset(0)
		m.SetFlags(0)
		m.SetTimeToLive(pkt.TimeToLive())
		m.SetProtocol(pkt.Protocol())
		copy(m.SourceAddress(), pkt.SourceAddress())
		copy(m.TargetAddress(), pkt.TargetAddress())
		copy(m.Options(), pkt.Options())
	}

	heap.Push(&t.queue, pkt)

	t.ttl = time.Now().Add(defaultIPFragmentTimeout)

	for {
		if len(t.queue) <= 0 {
			return nil, nil
		}

		n := t.queue[0].(packet.IPv4Packet)
		m := t.merged.(packet.IPv4Packet)

		if n.FragmentOffset() == t.nextOffset && int(t.nextOffset)+len(n.Payload()) <= packet.IPPacketMaxLength {
			copy(m.Payload()[t.nextOffset:], n.Payload())
			t.nextOffset += uint16(len(n.Payload()))

			if n.Flags()&packet.IPv4MoreFragment == 0 {
				break
			}
		} else if n.FragmentOffset() < t.nextOffset {
			// Drop duplicate packet
		} else {
			return nil, nil
		}

		heap.Pop(&t.queue)
		r.provider.Recycle(n)
	}

	t.merged.(packet.IPv4Packet).SetPacketLength(pkt.HeaderLength() + t.nextOffset)

	delete(r.trackers, pkt.Identification())

	return t.merged, nil
}

func (r *Reassembler) clearExpiredTackers() {
	for k, t := range r.trackers {
		if t.ttl.Before(time.Now()) {
			for _, pkt := range t.queue {
				r.provider.Recycle(pkt.BaseDataBlock())
			}
			delete(r.trackers, k)
		}
	}
}

func (p packetHeap) Len() int {
	return len(p)
}

func (p packetHeap) Less(a, b int) bool {
	pA := p[a]
	pB := p[b]

	if v4, ok := pA.(packet.IPv4Packet); ok {
		return v4.FragmentOffset() < pB.(packet.IPv4Packet).FragmentOffset()
	}

	return false
}

func (p packetHeap) Swap(a, b int) {
	p[a], p[b] = p[b], p[a]
}

func (p *packetHeap) Push(x interface{}) {
	*p = append(*p, x.(packet.IPPacket))
}

func (p *packetHeap) Pop() interface{} {
	old := *p
	n := len(old)
	x := old[n-1]
	*p = old[0 : n-1]
	return x
}
