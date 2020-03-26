package io

import (
	"io"
	"time"
)

type TunDevice interface {
	io.Reader
	io.Writer
	SetDeadline(t time.Time) error
}
