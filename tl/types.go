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

// RequestObject adapts an arbitrary Object into Request[Object] so generic
// wrapper methods such as invokeWithLayer and initConnection can embed a
// request whose static result type is erased, as on raw invoke paths. The
// adapter encodes the wrapped object unchanged; it never decodes a result,
// which remains the responsibility of the original typed request.
type RequestObject struct{ Object }

func (RequestObject) requestResult(Object) {}

func (RequestObject) decodeResult(d decoder) (Object, decoder, error) {
	return nil, d, ErrNilObject
}
