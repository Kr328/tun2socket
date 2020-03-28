package io

import "github.com/kr328/tun2socket/tcpip/buf"

func startWriter(device TunDevice, provider buf.BufferProvider, input chan []byte, done *completable) {
	go func() {
		for {
			select {
			case buffer := <-input:
				if _, err := device.Write(buffer); err != nil {
					done.complete()
					return
				}

				provider.Recycle(buffer)
			case <-done.waiter():
				return
			}
		}
	}()
}
