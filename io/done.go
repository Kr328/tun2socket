package io

import "sync"

type completable struct {
	channel chan struct{}
	once    sync.Once
}

func newCompletable() *completable {
	return &completable{
		channel: make(chan struct{}),
	}
}

func (d *completable) complete() {
	d.once.Do(func() {
		close(d.channel)
	})
}

func (d *completable) waiter() chan struct{} {
	return d.channel
}

func (d *completable) wait() {
	<-d.channel
}
