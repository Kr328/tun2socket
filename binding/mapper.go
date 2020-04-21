package binding

import (
	"container/list"
	"sync"
)

const (
	defaultRecordMaxSize = 2048
)

type Mapper struct {
	lock      sync.Mutex
	pool      *PortPool
	bindings  *list.List
	endpoints map[endpointKey]*list.Element
	ports     map[uint16]*list.Element
}

func NewMapper() *Mapper {
	return &Mapper{
		pool:      NewPortPool(),
		bindings:  list.New(),
		endpoints: make(map[endpointKey]*list.Element, defaultRecordMaxSize*2),
		ports:     make(map[uint16]*list.Element, defaultRecordMaxSize*2),
	}
}

func (mapper *Mapper) PutBinding(binding *Binding) *Binding {
	mapper.lock.Lock()
	defer mapper.lock.Unlock()

	if mapper.bindings.Len() >= defaultRecordMaxSize {
		element := mapper.bindings.Back()
		binding := element.Value.(*Binding)
		delete(mapper.endpoints, binding.Endpoint.asKey())
		delete(mapper.ports, binding.Port)
		mapper.bindings.Remove(element)
	}

	binding = binding.Clone()
	elm := mapper.bindings.PushFront(binding)
	mapper.endpoints[binding.Endpoint.asKey()] = elm
	mapper.ports[binding.Port] = elm

	return binding
}

func (mapper *Mapper) GetBindingByEndpoint(endpoint *Endpoint) *Binding {
	mapper.lock.Lock()
	defer mapper.lock.Unlock()

	elm, ok := mapper.endpoints[endpoint.asKey()]
	if !ok {
		return nil
	}

	mapper.bindings.MoveToFront(elm)
	return elm.Value.(*Binding)
}

func (mapper *Mapper) GetBindingByPort(port uint16) *Binding {
	mapper.lock.Lock()
	defer mapper.lock.Unlock()

	elm, ok := mapper.ports[port]
	if !ok {
		return nil
	}

	mapper.bindings.MoveToFront(elm)
	return elm.Value.(*Binding)
}

func (mapper *Mapper) FindFreePort() uint16 {
	mapper.lock.Lock()
	defer mapper.lock.Unlock()

	for {
		p := mapper.pool.Next()
		if _, ok := mapper.ports[p]; !ok {
			return p
		}
	}
}

func (mapper *Mapper) Reset() {
	mapper.lock.Lock()
	defer mapper.lock.Unlock()

	mapper.bindings.Init()
	mapper.ports = map[uint16]*list.Element{}
	mapper.endpoints = map[endpointKey]*list.Element{}
}
