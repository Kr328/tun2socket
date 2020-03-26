package buf

type BufferProvider interface {
	Obtain(length int) []byte
	Recycle(buffer []byte)
}
