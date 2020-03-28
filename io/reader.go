package io

import "github.com/kr328/tun2socket/tcpip/buf"

func startReader(device TunDevice, mtu int, provider buf.BufferProvider, output chan []byte, complete *completable) {
	go func() {
		for {
			buffer := provider.Obtain(mtu)
			n, err := device.Read(buffer)
			if err != nil {
				complete.complete()
				return
			}

			select {
			case output <- buffer[:n]:
			default:
			}
		}
	}()
}
