package fragment

import (
	"container/list"
	"errors"
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/packet"
	"time"
)

var (
	ErrReassembleBlocked = errors.New("reassemble blocked")
)

const (
	defaultIPFragmentTimeout = time.Second * 120
	maxReassemblingPacket    = 1024
)

type tracker struct {
	*list.List
	ttl time.Time
}

type Reassembler struct {
	trackers map[uint16]*tracker
	provider buf.BufferProvider
}

func NewReassemble(provider buf.BufferProvider) *Reassembler {
	return &Reassembler{
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

	r.clearExpiredTackers()

	if pkt.Flags()&packet.IPv4DontFragment != 0 {
		return nil, ErrReassembleBlocked
	}

	tacker := r.trackers[pkt.Identification()]
	if tacker == nil {
		if len(r.trackers) > maxReassemblingPacket {
			return nil, ErrReassembleBlocked
		}

		tacker = &tracker{
			List: list.New(),
			ttl:  time.Now().Add(defaultIPFragmentTimeout),
		}

		tacker.PushBack(pkt)

		r.trackers[pkt.Identification()] = tacker

		return nil, nil
	}

	tacker.ttl = time.Now().Add(defaultIPFragmentTimeout)

	inserted := false
	for iterator := tacker.Back(); iterator != nil; iterator = iterator.Prev() {
		p, ok := iterator.Value.(packet.IPv4Packet)
		if !ok {
			return nil, nil
		}

		if p.FragmentOffset() < pkt.FragmentOffset() {
			tacker.List.InsertAfter(pkt, iterator)
			inserted = true
			break
		}
	}
	if !inserted {
		tacker.PushFront(pkt)
	}

	expectedOffset := uint16(0)
	completed := false
	for iterator := tacker.Front(); iterator != nil; iterator = iterator.Next() {
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
	result.SetPacketLength(pkt.HeaderLength() + expectedOffset)
	result.SetIdentification(pkt.Identification())
	result.SetFragmentOffset(0)
	result.SetFlags(0)
	result.SetTimeToLive(pkt.TimeToLive())
	result.SetProtocol(pkt.Protocol())
	copy(result.SourceAddress(), pkt.SourceAddress())
	copy(result.TargetAddress(), pkt.TargetAddress())
	copy(result.Options(), pkt.Options())

	// Merge fragments
	for iterator := tacker.Front(); iterator != nil; iterator = iterator.Next() {
		pkt := iterator.Value.(packet.IPv4Packet)
		payload := result.Payload()

		copy(payload[pkt.FragmentOffset():], pkt.Payload())

		r.provider.Recycle(pkt)
	}

	delete(r.trackers, pkt.Identification())

	return result, nil
}

func (r *Reassembler) clearExpiredTackers() {
	for k, t := range r.trackers {
		if t.ttl.Before(time.Now()) {
			for iterator := t.Front(); iterator != nil; iterator = iterator.Next() {
				r.provider.Recycle(iterator.Value.(packet.IPPacket).BaseDataBlock())
			}
			delete(r.trackers, k)
		}
	}
}
