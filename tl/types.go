package tl

// Object is any generated TL constructor or RPC request.
type Object interface {
	ConstructorID() uint32
	encodedSize() (int, error)
	encode(encoder) (encoder, error)
}

// Request is a generated raw RPC request with compile-time result type T.
//
// The unexported marker limits implementations to generated types in this
// package. It is never called at runtime.
type Request[T any] interface {
	Object
	requestResult(T)
	decodeResult(decoder) (T, decoder, error)
}
