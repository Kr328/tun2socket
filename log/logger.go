package log

import "log"

type Logger interface {
	D(format string, args ...interface{})
	I(format string, args ...interface{})
	W(format string, args ...interface{})
	E(format string, args ...interface{})
}

type DefaultLogger struct{}

func (d *DefaultLogger) D(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}

func (d *DefaultLogger) I(format string, args ...interface{}) {
	log.Printf("[INFO]  "+format, args...)
}

func (d *DefaultLogger) W(format string, args ...interface{}) {
	log.Printf("[WARN]  "+format, args...)
}

func (d *DefaultLogger) E(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}
