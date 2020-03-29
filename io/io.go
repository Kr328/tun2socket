package io

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/packet"
	"sync"
)

const (
	defaultIOCache      = 32
	defaultDecoderCount = 4
	defaultEncoderCount = 4
)

type IO struct {
	initial sync.Once
	done    *completable

	device   TunDevice
	mtu      int
	provider buf.BufferProvider

	inbound  chan PacketContext
	outbound chan PacketContext
}

type PacketContext struct {
	IPPkt        packet.IPPacket
	TransportPkt packet.TransportPacket
}

func NewIO(device TunDevice, mtu int, provider buf.BufferProvider) *IO {
	return &IO{
		done:     newCompletable(),
		device:   device,
		mtu:      mtu,
		provider: provider,
		inbound:  make(chan PacketContext, defaultIOCache),
		outbound: make(chan PacketContext, defaultIOCache),
	}
}

func (io *IO) Start() {
	io.initial.Do(func() {
		readerDecoder := make(chan []byte, defaultIOCache)
		fragmentDecoder := make(chan packet.IPPacket, defaultIOCache)
		ipDecoder := make(chan packet.IPPacket, defaultIOCache)

		startReader(io.device, io.mtu, io.provider, readerDecoder, io.done)
		startReassemble(fragmentDecoder, ipDecoder, io.provider, io.done)

		for i := 0; i < defaultDecoderCount; i++ {
			startIPDecoder(readerDecoder, fragmentDecoder, ipDecoder, io.provider, io.done)
			startTransportDecoder(ipDecoder, io.inbound, io.provider, io.done)
		}

		writerEncoder := make(chan []byte, defaultIOCache)

		startWriter(io.device, io.provider, writerEncoder, io.done)
		for i := 0; i < defaultEncoderCount; i++ {
			startTransportEncoder(io.outbound, writerEncoder, io.mtu, io.provider, io.done)
		}
	})
}

func (io *IO) Inbound() chan PacketContext {
	return io.inbound
}

func (io *IO) Outbound() chan PacketContext {
	return io.outbound
}

func (io *IO) Wait() chan struct{} {
	return io.done.waiter()
}

func (io *IO) Close() {
	_ = io.device.Close()
	io.done.complete()
}
