package protocol

import (
	"io"

	"github.com/quic-go/quic-go"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	Name = "quic-h3-tunnel"

	Version uint8 = 1
)

// deprecated: we're going to reply on ApplicationCode going forward
// and close connections under these application error conditions
//
//go:generate stringer -type=ResponseCode
type ResponseCode uint8

const (
	CodeOK ResponseCode = iota
	CodeBadRequest
	CodeNotFound
	CodeUnauthorized
	CodeServerError
)

const (
	// ApplicationOK is returned when the stream or connection is being closed
	// intentionally with no error as the client is going away
	ApplicationOK = quic.ApplicationErrorCode(0x0)
	// ApplicationError is returned when something went wrong
	// The client can attempt to reconnect in this situation
	ApplicationError = quic.ApplicationErrorCode(0x1)
	// ApplicationClientError is return when the something went
	// wrong handling a clients request
	ApplicationClientError = quic.ApplicationErrorCode(0x2)
)

type RegisterListenerRequest struct {
	Version     uint8
	TunnelGroup string
	Metadata    map[string]string
}

type RegisterListenerResponse struct {
	Version uint8
	// deprecated: we're going to rely on ApplicationCode instead
	// and always close with connection with the relevant error code
	Code     ResponseCode
	Metadata map[string]string
	Body     []byte
}

type AuthenticationHandler interface {
	Authenticate(*RegisterListenerRequest) error
}

type AuthenticationHandlerFunc func(*RegisterListenerRequest) error

func (r AuthenticationHandlerFunc) Authenticate(req *RegisterListenerRequest) error {
	return r(req)
}

type Decoder[T any] struct {
	dec *msgpack.Decoder
}

func (d Decoder[T]) Close() {
	msgpack.PutDecoder(d.dec)
}

func NewDecoder[T any](rd io.ReadCloser) Decoder[T] {
	dec := msgpack.GetDecoder()
	dec.Reset(rd)
	return Decoder[T]{dec}
}

func (d Decoder[T]) Decode() (t T, _ error) {
	return t, d.dec.Decode(&t)
}

type Encoder[T any] struct {
	enc *msgpack.Encoder
}

func (e Encoder[T]) Close() {
	msgpack.PutEncoder(e.enc)
}

func NewEncoder[T any](wr io.WriteCloser) Encoder[T] {
	enc := msgpack.GetEncoder()
	enc.Reset(wr)
	return Encoder[T]{enc}
}

func (e Encoder[T]) Encode(t *T) error {
	return e.enc.Encode(t)
}
