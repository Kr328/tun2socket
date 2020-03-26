package endpoint

import "sync"

type PortPool struct {
	lock    sync.Mutex
	current uint16
}

func NewPortPool() *PortPool {
	return &PortPool{
		current: 0,
	}
}

func (pool *PortPool) Next() uint16 {
	pool.lock.Lock()
	defer pool.lock.Unlock()

	pool.current = uint16(uint32(pool.current+1) % 65536)
	return pool.current
}
