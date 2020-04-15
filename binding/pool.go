package binding

const (
	minimumPort = 20000
	maximumPort = 65535
)

type PortPool struct {
	offset uint32
}

func NewPortPool() *PortPool {
	return &PortPool{
		offset: minimumPort,
	}
}

func (pool *PortPool) Next() uint16 {
	pool.offset = (pool.offset + 1) % (maximumPort - minimumPort)
	return minimumPort + uint16(pool.offset)
}
