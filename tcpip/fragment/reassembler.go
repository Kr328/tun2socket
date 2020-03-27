package fragment

import (
	"container/list"
	"errors"
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/packet"
	"sync"
	"time"
)

var (
	ErrReassembleBlocked = errors.New("reassemble blocked")
)

const (
	defaultIPFragmentTimeout = time.Second * 120
)

type tracker struct {
	*list.List
	ttl time.Time
}

type Reassembler struct {
	trackerPool sync.Pool
	trackers    map[uint16]*tracker
	provider    buf.BufferProvider
}

func NewReassemble(provider buf.BufferProvider) *Reassembler {
	return &Reassembler{
		trackerPool: sync.Pool{New: func() interface{} {
			return &tracker{
				List: list.New(),
				ttl:  time.Now(),
			}
		}},
		trackers: map[uint16]*tracker{},
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

	if pkt.Flags()&packet.IPv4DontFragment != 0 {
		return nil, ErrReassembleBlocked
	}

	metadata := r.trackers[pkt.Identification()]
	if metadata == nil {
		metadata = r.trackerPool.Get().(*tracker)
		metadata.PushBack(pkt)
		metadata.ttl = time.Now().Add(defaultIPFragmentTimeout)

		r.trackers[pkt.Identification()] = metadata

		return nil, nil
	}

	metadata.ttl = time.Now().Add(defaultIPFragmentTimeout)

	inserted := false
	for iterator := metadata.Back(); iterator != nil; iterator = iterator.Prev() {
		p, ok := iterator.Value.(packet.IPv4Packet)
		if !ok {
			return nil, nil
		}

		if p.FragmentOffset() < pkt.FragmentOffset() {
			metadata.List.InsertAfter(pkt, iterator)
			inserted = true
			break
		}
	}
	if !inserted {
		metadata.PushFront(pkt)
	}

	expectedOffset := uint16(0)
	completed := false
	for iterator := metadata.Front(); iterator != nil; iterator = iterator.Next() {
		pkt, ok := iterator.Value.(packet.IPv4Packet)
		if !ok {
			return nil, nil
		}

		if pkt.FragmentOffset() == expectedOffset {
			expectedOffset += uint16(len(pkt.Payload()))
			completed = pkt.Flags()&packet.IPv4MoreFragment == 0
		} else {
			return nil, nil
		}
	}

	if !completed {
		return nil, nil
	}

	result := packet.IPv4Packet(r.provider.Obtain(int(pkt.HeaderLength() + expectedOffset)))
	packet.SetPacketVersion(result, packet.IPv4)
	result.SetHeaderLength(pkt.HeaderLength())
	result.SetTypeOfService(pkt.TypeOfService())
	result.SetPacketLength(expectedOffset)
	result.SetIdentification(pkt.Identification())
	result.SetFragmentOffset(0)
	result.SetFlags(0)
	result.SetTimeToLive(pkt.TimeToLive())
	result.SetProtocol(pkt.Protocol())
	copy(result.SourceAddress(), pkt.SourceAddress())
	copy(result.TargetAddress(), pkt.TargetAddress())
	copy(result.Options(), pkt.Options())

	// Merge fragments
	for iterator := metadata.Front(); iterator != nil; iterator = iterator.Next() {
		pkt := iterator.Value.(packet.IPv4Packet)
		payload := result.Payload()

		copy(payload[pkt.FragmentOffset():], pkt.Payload())

		r.provider.Recycle(pkt)
	}

	delete(r.trackers, pkt.Identification())

	metadata.Init()
	r.trackerPool.Put(metadata)

	return result, nil
}
